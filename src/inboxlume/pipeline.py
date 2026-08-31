from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from .classifier import Classifier
from .config import AccountPolicy, policy_safety_fingerprint
from .learning import PreferenceStore
from .models import (
    Classification,
    EmailCategory,
    EmailRecord,
    PolicyAction,
    PolicyDecision,
)
from .policy import SafetyPolicyEngine
from .providers.contracts import READ_ONLY_CAPABILITIES, ReadOnlyMailbox
from .providers.gmail_finalizer import (
    QUARANTINE_DELAY_DAYS,
    MatureQuarantineCandidate,
)
from .proof_of_obsolescence import has_hard_policy_reason
from .quiz import QuizCandidate, QuizSelector


_CLEANUP_REVIEW_CATEGORIES = frozenset(
    {
        EmailCategory.ADVERTISING,
        EmailCategory.SOCIAL,
        EmailCategory.SPAM,
        EmailCategory.ONE_TIME_CODE,
    }
)


@dataclass(frozen=True, slots=True)
class DryRunResult:
    """Risultato privo di corpo, oggetto e mittente, adatto all'output locale."""

    message: EmailRecord
    classification: Classification
    decision: PolicyDecision
    age_days: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "account_id": self.message.account_id,
            "message_id": self.message.message_id,
            "received_at": self.message.received_at.isoformat(),
            "age_days": self.age_days,
            "category": self.classification.category.value,
            "confidence": round(self.classification.confidence, 4),
            "retention": self.classification.retention.value,
            "retention_confidence": round(
                self.classification.retention_confidence,
                4,
            ),
            "classifier": self.classification.classifier,
            "classification_reasons": list(self.classification.reason_codes),
            "suggested_action": self.decision.action.value,
            "policy_reasons": list(self.decision.reason_codes),
            "dry_run": self.decision.dry_run,
            "changes_mailbox": self.decision.changes_mailbox,
        }


@dataclass(frozen=True, slots=True)
class InboxMutationCandidate:
    """Opaque provider ID plus the read state that authorised selection."""

    message_id: str
    expected_unread: bool

    def __post_init__(self) -> None:
        if not self.message_id.strip():
            raise ValueError("message_id candidato operativo non valido")
        if type(self.expected_unread) is not bool:
            raise ValueError("expected_unread candidato operativo non valido")


def _require_read_only_mailbox(mailbox: ReadOnlyMailbox) -> None:
    if mailbox.capabilities != READ_ONLY_CAPABILITIES:
        raise ValueError("il provider non espone esattamente le sole capacità di lettura")


def _validate_message(message: EmailRecord, policy: AccountPolicy) -> None:
    if message.account_id != policy.account_id or message.provider is not policy.provider:
        raise ValueError("il provider ha restituito un messaggio di un altro account")


def run_dry_scan(
    policy: AccountPolicy,
    mailbox: ReadOnlyMailbox,
    classifier: Classifier,
    now: datetime,
    limit: int,
    preference_store: PreferenceStore | None = None,
) -> list[DryRunResult]:
    """Legge candidati Inbox e produce soltanto proposte non operative."""

    if now.tzinfo is None:
        raise ValueError("now deve includere il fuso orario")
    if not 1 <= limit <= policy.max_candidates_per_run:
        raise ValueError(
            f"limit deve essere tra 1 e {policy.max_candidates_per_run} per questo account"
        )
    _require_read_only_mailbox(mailbox)

    unread_cutoff = now - timedelta(days=policy.unread_age_days)
    read_otp_cutoff = now - timedelta(days=policy.read_one_time_code_age_days)
    read_access_cutoff = now - timedelta(
        days=policy.read_routine_access_alert_age_days
    )
    engine = SafetyPolicyEngine()
    results: list[DryRunResult] = []

    def evaluate(message: EmailRecord) -> None:
        _validate_message(message, policy)
        classification = classifier.classify(message)
        preference = (
            preference_store.interest_for(message, classification, now)
            if policy.learning.enabled and preference_store is not None
            else None
        )
        decision = engine.decide(message, classification, policy, now, preference)
        if not decision.dry_run or decision.changes_mailbox:
            raise RuntimeError("la policy ha prodotto una decisione operativa non consentita")
        results.append(
            DryRunResult(
                message=message,
                classification=classification,
                decision=decision,
                age_days=message.age_days(now),
            )
        )

    # Una piccola quota trova codici già letti; se non ne trova, il lotto resta
    # interamente disponibile per i vecchi non letti.
    otp_quota = max(1, limit // 5)
    seen: set[str] = set()
    for message in mailbox.iter_inbox_read_one_time_code_candidates_before(
        read_otp_cutoff,
        otp_quota,
    ):
        if message.unread:
            continue
        evaluate(message)
        seen.add(message.message_id)

    remaining = limit - len(results)
    access_iterator = getattr(
        mailbox,
        "iter_inbox_read_routine_access_alert_candidates_before",
        None,
    )
    if remaining and callable(access_iterator):
        access_quota = min(remaining, max(1, limit // 10))
        for message in access_iterator(read_access_cutoff, access_quota):
            if message.unread or message.message_id in seen:
                continue
            evaluate(message)
            seen.add(message.message_id)

    remaining = limit - len(results)
    if remaining:
        for message in mailbox.iter_inbox_unread_before(unread_cutoff, remaining):
            if not message.unread:
                raise ValueError("il provider ha restituito un messaggio letto nella scansione")
            if message.message_id in seen:
                continue
            evaluate(message)
            if len(results) >= limit:
                break
    return results


def run_shadow_scan(
    policy: AccountPolicy,
    mailbox: ReadOnlyMailbox,
    classifier: Classifier,
    now: datetime,
    limit: int,
    search_limit: int,
    preference_store: PreferenceStore,
    scan_profile: str,
    *,
    oldest_first: bool = False,
    progress: Callable[[int, int], None] | None = None,
    defer_completion: bool = False,
) -> list[DryRunResult]:
    """Scansione progressiva: salva solo HMAC e risultati, mai testo o ID."""

    if now.tzinfo is None:
        raise ValueError("now deve includere il fuso orario")
    if not 1 <= limit <= policy.max_candidates_per_run:
        raise ValueError(
            f"limit deve essere tra 1 e {policy.max_candidates_per_run} per questo account"
        )
    if search_limit != 0 and search_limit < limit:
        raise ValueError("search_limit deve essere 0 (tutti gli ID) oppure almeno limit")
    if not scan_profile.strip() or len(scan_profile) > 100:
        raise ValueError("scan_profile non valido")
    _require_read_only_mailbox(mailbox)

    engine = SafetyPolicyEngine()
    results: list[DryRunResult] = []
    unread_cutoff = now - timedelta(days=policy.unread_age_days)
    read_otp_cutoff = now - timedelta(days=policy.read_one_time_code_age_days)
    read_access_cutoff = now - timedelta(
        days=policy.read_routine_access_alert_age_days
    )
    current_policy_fingerprint = policy_safety_fingerprint(policy)

    was_scanned = preference_store.shadow_scan_membership_checker(
        policy.account_id,
        policy.provider,
        scan_profile,
        current_policy_fingerprint,
    )
    seen_in_batch: set[str] = set()

    def evaluate(message: EmailRecord) -> None:
        _validate_message(message, policy)
        if message.message_id in seen_in_batch:
            return
        seen_in_batch.add(message.message_id)
        classification = classifier.classify(message)
        preference = (
            preference_store.interest_for(message, classification, now)
            if policy.learning.enabled
            else None
        )
        decision = engine.decide(message, classification, policy, now, preference)
        if not decision.dry_run or decision.changes_mailbox:
            raise RuntimeError("la policy ha prodotto una decisione operativa non consentita")
        results.append(
            DryRunResult(
                message=message,
                classification=classification,
                decision=decision,
                age_days=message.age_days(now),
            )
        )
        if progress is not None:
            progress(len(results), limit)

    otp_quota = max(1, limit // 5)
    otp_arguments = {
        "skip_message_id": was_scanned,
        "search_limit": search_limit,
    }
    if oldest_first:
        otp_arguments["oldest_first"] = True
    for message in mailbox.iter_inbox_read_one_time_code_candidates_before(
        read_otp_cutoff, otp_quota, **otp_arguments
    ):
        if not message.unread:
            evaluate(message)

    remaining = limit - len(results)
    access_iterator = getattr(
        mailbox,
        "iter_inbox_read_routine_access_alert_candidates_before",
        None,
    )
    if remaining and callable(access_iterator):
        access_arguments = {
            "skip_message_id": was_scanned,
            "search_limit": search_limit,
        }
        if oldest_first:
            access_arguments["oldest_first"] = True
        access_quota = min(remaining, max(1, limit // 10))
        for message in access_iterator(
            read_access_cutoff,
            access_quota,
            **access_arguments,
        ):
            if not message.unread:
                evaluate(message)

    remaining = limit - len(results)
    if remaining:
        unread_arguments = {
            "skip_message_id": was_scanned,
            "search_limit": search_limit,
        }
        if oldest_first:
            unread_arguments["oldest_first"] = True
        for message in mailbox.iter_inbox_unread_before(
            unread_cutoff, remaining, **unread_arguments
        ):
            if not message.unread:
                raise ValueError("il provider ha restituito un messaggio letto nella scansione")
            evaluate(message)

    # Registra il lotto soltanto dopo che la fase di classificazione è terminata.
    # Se il processo viene annullato prima, gli ID parziali non diventano
    # silenziosamente "già elaborati" e potranno essere riproposti al prossimo run.
    preference_store.record_shadow_scan_batch(
        (
            (result.message, result.classification, result.decision)
            for result in results
        ),
        scan_profile,
        now,
        current_policy_fingerprint,
        processing_complete=not defer_completion,
    )
    return results


def prepare_quiz(
    policy: AccountPolicy,
    mailbox: ReadOnlyMailbox,
    classifier: Classifier,
    store: PreferenceStore,
    quiz_limit: int,
    sample_limit: int,
    selector: QuizSelector | None = None,
    now: datetime | None = None,
) -> list[QuizCandidate]:
    """Prepara il quiz in memoria; nessun testo viene scritto nel database."""

    if not 1 <= quiz_limit <= 500:
        raise ValueError("quiz_limit deve essere tra 1 e 500")
    if not quiz_limit <= sample_limit <= 500:
        raise ValueError("sample_limit deve essere tra quiz_limit e 500")
    _require_read_only_mailbox(mailbox)
    current_time = now or datetime.now(timezone.utc)
    if current_time.tzinfo is None:
        raise ValueError("now deve includere il fuso orario")
    old_unread_before = current_time - timedelta(days=policy.unread_age_days)

    candidates: list[QuizCandidate] = []
    for message in mailbox.iter_inbox_quiz_sample(
        sample_limit,
        old_unread_before,
        skip_message_id=lambda message_id: (
            store.quiz_answer_for_message_id(
                policy.account_id,
                policy.provider,
                message_id,
            )
            is not None
        ),
        search_limit=0,
    ):
        _validate_message(message, policy)
        if store.has_quiz_answer(message):
            continue
        candidates.append(QuizCandidate(message, classifier.classify(message)))
    return (selector or QuizSelector()).select(
        candidates,
        limit=quiz_limit,
        store=store,
    )


def prepare_shadow_review(
    policy: AccountPolicy,
    mailbox: ReadOnlyMailbox,
    store: PreferenceStore,
    now: datetime,
    limit: int,
    search_limit: int,
    scan_profile: str,
) -> list[QuizCandidate]:
    """Recupera proposte di quarantena non ancora giudicate dall'utente."""

    if now.tzinfo is None:
        raise ValueError("now deve includere il fuso orario")
    if not 1 <= limit <= 500 or not limit <= search_limit <= 1000:
        raise ValueError("limiti revisione shadow non validi")
    _require_read_only_mailbox(mailbox)
    unread_before = now - timedelta(days=policy.unread_age_days)
    read_otp_before = now - timedelta(days=policy.read_one_time_code_age_days)
    read_access_before = now - timedelta(
        days=policy.read_routine_access_alert_age_days
    )

    def record_for_id(message_id: str) -> tuple[str, str] | None:
        if (
            store.quiz_answer_for_message_id(
                policy.account_id,
                policy.provider,
                message_id,
            )
            is not None
        ):
            return None
        record = store.shadow_record_for_message_id(
            policy.account_id,
            policy.provider,
            message_id,
            scan_profile,
        )
        if record is None:
            return None
        if store.shadow_is_hard_protected(
            policy.account_id,
            policy.provider,
            message_id,
            scan_profile,
        ) or store.threat_protects_message_id(
            policy.account_id,
            policy.provider,
            message_id,
            scan_profile,
        ):
            return None
        category, action = record
        if action == "quarantine":
            return record
        if (
            action == "review"
            and EmailCategory(category) in _CLEANUP_REVIEW_CATEGORIES
        ):
            return record
        # Protected/ambiguous review families are intentionally excluded from
        # cleanup evidence.  They remain ordinary manual-review decisions.
        return None

    candidates: list[QuizCandidate] = []
    for message, category, _ in mailbox.iter_inbox_shadow_review_sample(
        unread_before,
        read_otp_before,
        read_access_before,
        limit,
        search_limit,
        record_for_id,
    ):
        _validate_message(message, policy)
        candidates.append(
            QuizCandidate(
                message,
                Classification(
                    EmailCategory(category),
                    1.0,
                    ("shadow_quarantine_review",),
                    f"shadow:{scan_profile}",
                ),
            )
        )
    return candidates


def _message_identity(message: EmailRecord) -> str:
    """Return the RFC Message-ID header, which survives a folder move."""

    return next(
        (
            str(value)
            for key, value in message.headers.items()
            if str(key).casefold() == "message-id"
        ),
        "",
    )


def prepare_quarantine_shadow_review(
    policy: AccountPolicy,
    mailbox: ReadOnlyMailbox,
    store: PreferenceStore,
    now: datetime,
    limit: int,
    search_limit: int,
    scan_profile: str,
) -> list[QuizCandidate]:
    """Recover Yahoo proposals that were moved to the reversible folder.

    This deliberately relies on a provider-specific optional method.  A
    normal Inbox mailbox cannot expose messages outside Inbox, so providers
    without a quarantine folder simply return no candidates.
    """

    if now.tzinfo is None:
        raise ValueError("now deve includere il fuso orario")
    if not 1 <= limit <= 500 or not limit <= search_limit <= 1000:
        raise ValueError("limiti revisione quarantena non validi")
    _require_read_only_mailbox(mailbox)
    iterator = getattr(mailbox, "iter_quarantine_review_messages", None)
    if not callable(iterator):
        return []
    folder = getattr(getattr(mailbox, "transport", None), "folder", "")
    if not isinstance(folder, str) or not folder:
        return []

    candidates: list[QuizCandidate] = []
    for message in iterator(search_limit):
        _validate_message(message, policy)
        if (
            store.quiz_answer_for_message_id(
                policy.account_id,
                policy.provider,
                message.message_id,
            )
            is not None
        ):
            continue
        record = store.shadow_record_for_message_id(
            policy.account_id,
            policy.provider,
            message.message_id,
            scan_profile,
        )
        if record is None:
            try:
                uid_validity, uid = message.message_id.split(":", 1)
            except ValueError:
                uid_validity, uid = "", ""
            mapped = store.quarantine_review_record_for_location(
                policy.account_id,
                policy.provider,
                scan_profile,
                folder,
                uid_validity,
                uid,
            )
            if mapped is None:
                # The destination pointer is only available when the provider
                # returns it. The RFC Message-ID survives the move regardless,
                # so a proposal stays reviewable without it.
                mapped = store.shadow_record_for_provider_identity(
                    policy.account_id,
                    policy.provider,
                    _message_identity(message),
                    scan_profile,
                )
            if mapped is None:
                # A message manually placed in a similarly named folder is
                # not InboxLume evidence and must never qualify the Governor.
                continue
            classification = Classification(
                EmailCategory(mapped[0]),
                1.0,
                ("linked_quarantine_review",),
                f"shadow:{scan_profile}",
            )
            store.record_shadow_scan(
                message,
                classification,
                PolicyDecision(
                    PolicyAction.QUARANTINE,
                    ("quarantine_folder_user_review",),
                ),
                scan_profile,
                now,
                policy_safety_fingerprint(policy),
            )
            record = (classification.category.value, "quarantine")
        category, action = record
        if action != "quarantine":
            continue
        candidates.append(
            QuizCandidate(
                message,
                Classification(
                    EmailCategory(category),
                    1.0,
                    ("shadow_quarantine_review",),
                    f"shadow:{scan_profile}",
                ),
            )
        )
        if len(candidates) >= limit:
            break
    return candidates


def prepare_verified_quarantine_candidates(
    policy: AccountPolicy,
    mailbox: ReadOnlyMailbox,
    store: PreferenceStore,
    now: datetime,
    limit: int,
    search_limit: int,
    scan_profile: str,
) -> list[InboxMutationCandidate]:
    """Seleziona proposte confermate con lo stato letto che le autorizza."""

    if now.tzinfo is None:
        raise ValueError("now deve includere il fuso orario")
    if not 1 <= limit <= 10 or not limit <= search_limit <= 1000:
        raise ValueError("limiti quarantena pilot non validi")
    if not scan_profile.strip() or len(scan_profile) > 100:
        raise ValueError("scan_profile non valido")
    _require_read_only_mailbox(mailbox)
    unread_before = now - timedelta(days=policy.unread_age_days)
    read_otp_before = now - timedelta(days=policy.read_one_time_code_age_days)
    read_access_before = now - timedelta(
        days=policy.read_routine_access_alert_age_days
    )
    current_policy_fingerprint = policy_safety_fingerprint(policy)
    matched: dict[str, InboxMutationCandidate] = {}

    def is_verified(message_id: str, currently_unread: bool) -> bool:
        if store.shadow_recovery_expected_unread(
            policy.account_id,
            policy.provider,
            message_id,
            scan_profile,
            current_policy_fingerprint,
        ) is not currently_unread:
            return False
        if not store.has_threat_assessment_id(
            policy.account_id,
            policy.provider,
            message_id,
            scan_profile,
        ):
            return False
        if store.has_quarantine_pilot_execution_id(
            policy.account_id,
            policy.provider,
            message_id,
            scan_profile,
        ):
            return False
        record = store.shadow_record_for_message_id(
            policy.account_id,
            policy.provider,
            message_id,
            scan_profile,
        )
        if record is None or record[1] != "quarantine":
            return False
        if store.quiz_answer_for_message_id(
            policy.account_id,
            policy.provider,
            message_id,
        ) != "dont_keep":
            return False
        matched[message_id] = InboxMutationCandidate(
            message_id,
            currently_unread,
        )
        return True

    message_ids = list(
        mailbox.iter_inbox_matching_candidate_ids(
            unread_before,
            read_otp_before,
            read_access_before,
            limit,
            search_limit,
            is_verified,
        )
    )
    return [matched[message_id] for message_id in message_ids]


def prepare_verified_quarantine_ids(
    policy: AccountPolicy,
    mailbox: ReadOnlyMailbox,
    store: PreferenceStore,
    now: datetime,
    limit: int,
    search_limit: int,
    scan_profile: str,
) -> list[str]:
    """Compatibility view for read-only callers that need only opaque IDs."""

    return [
        candidate.message_id
        for candidate in prepare_verified_quarantine_candidates(
            policy,
            mailbox,
            store,
            now,
            limit,
            search_limit,
            scan_profile,
        )
    ]


def prepare_automatic_quarantine_candidates(
    policy: AccountPolicy,
    mailbox: ReadOnlyMailbox,
    store: PreferenceStore,
    now: datetime,
    limit: int,
    search_limit: int,
    scan_profile: str,
    allowed_categories: frozenset[str] | None = None,
    include_verified_obsolescence: bool = False,
    allow_disabled_threat_assessment: bool = False,
) -> list[InboxMutationCandidate]:
    """Recupera proposte pendenti preservando lo stato letto che le autorizza."""

    if now.tzinfo is None:
        raise ValueError("now deve includere il fuso orario")
    if not 1 <= limit <= 500 or not limit <= search_limit <= 1000:
        raise ValueError("limiti quarantena automatica non validi")
    if not scan_profile.strip() or len(scan_profile) > 100:
        raise ValueError("scan_profile non valido")
    _require_read_only_mailbox(mailbox)
    unread_before = now - timedelta(days=policy.unread_age_days)
    read_otp_before = now - timedelta(days=policy.read_one_time_code_age_days)
    read_access_before = now - timedelta(
        days=policy.read_routine_access_alert_age_days
    )
    current_policy_fingerprint = policy_safety_fingerprint(policy)
    matched: dict[str, InboxMutationCandidate] = {}

    def is_pending(message_id: str, currently_unread: bool) -> bool:
        expected_unread = store.shadow_recovery_expected_unread(
            policy.account_id,
            policy.provider,
            message_id,
            scan_profile,
            current_policy_fingerprint,
        )
        if expected_unread is not currently_unread:
            return False
        if not store.has_threat_assessment_id(
            policy.account_id,
            policy.provider,
            message_id,
            scan_profile,
            allow_disabled=allow_disabled_threat_assessment,
        ):
            return False
        if store.threat_protects_message_id(
            policy.account_id,
            policy.provider,
            message_id,
            scan_profile,
        ):
            return False
        if store.has_quarantine_pilot_execution_id(
            policy.account_id,
            policy.provider,
            message_id,
            scan_profile,
        ):
            return False
        record = store.shadow_record_for_message_id(
            policy.account_id,
            policy.provider,
            message_id,
            scan_profile,
        )
        if record is None:
            return False
        hard_protected = store.shadow_is_hard_protected(
            policy.account_id,
            policy.provider,
            message_id,
            scan_profile,
        )
        ordinary_quarantine = record[1] == "quarantine" and not hard_protected
        # An explicit user correction may promote a cleanup-boundary REVIEW
        # to the reversible destination.  Protected/ambiguous families never
        # take this path, and Keep/Unsure remain hard stops below.
        reviewed_cleanup = (
            record[1] == "review"
            and EmailCategory(record[0]) in _CLEANUP_REVIEW_CATEGORIES
            and not hard_protected
            and store.quiz_answer_for_message_id(
                policy.account_id,
                policy.provider,
                message_id,
            )
            == "dont_keep"
        )
        proof = store.obsolescence_proof_for_message_id(
            policy.account_id,
            policy.provider,
            message_id,
            scan_profile,
        )
        proof_quarantine = (
            include_verified_obsolescence
            and proof is not None
            and proof[0] == "verified"
            and proof[2] == "quarantine"
            and not has_hard_policy_reason(
                store.shadow_reason_codes_for_message_id(
                    policy.account_id,
                    policy.provider,
                    message_id,
                    scan_profile,
                )
            )
        )
        if not ordinary_quarantine and not proof_quarantine and not reviewed_cleanup:
            return False
        if allowed_categories is not None and record[0] not in allowed_categories:
            return False
        if store.quiz_answer_for_message_id(
            policy.account_id,
            policy.provider,
            message_id,
        ) in {"keep", "unsure"}:
            return False
        matched[message_id] = InboxMutationCandidate(
            message_id,
            currently_unread,
        )
        return True

    message_ids = list(
        mailbox.iter_inbox_matching_candidate_ids(
            unread_before,
            read_otp_before,
            read_access_before,
            limit,
            search_limit,
            is_pending,
        )
    )
    return [matched[message_id] for message_id in message_ids]


def prepare_automatic_quarantine_ids(
    policy: AccountPolicy,
    mailbox: ReadOnlyMailbox,
    store: PreferenceStore,
    now: datetime,
    limit: int,
    search_limit: int,
    scan_profile: str,
    allowed_categories: frozenset[str] | None = None,
    include_verified_obsolescence: bool = False,
    allow_disabled_threat_assessment: bool = False,
) -> list[str]:
    """Compatibility view for read-only callers that need only opaque IDs."""

    return [
        candidate.message_id
        for candidate in prepare_automatic_quarantine_candidates(
            policy,
            mailbox,
            store,
            now,
            limit,
            search_limit,
            scan_profile,
            allowed_categories=allowed_categories,
            include_verified_obsolescence=include_verified_obsolescence,
            allow_disabled_threat_assessment=allow_disabled_threat_assessment,
        )
    ]


def prepare_mature_quarantine_candidates(
    policy: AccountPolicy,
    mailbox: ReadOnlyMailbox,
    store: PreferenceStore,
    now: datetime,
    limit: int,
    search_limit: int,
    scan_profile: str,
) -> list[MatureQuarantineCandidate]:
    """Seleziona quarantene confermate rimaste intatte per almeno tre giorni."""

    if now.tzinfo is None:
        raise ValueError("now deve includere il fuso orario")
    if not 1 <= limit <= 5 or not limit <= search_limit <= 1000:
        raise ValueError("limiti finalizzazione non validi")
    if not scan_profile.strip() or len(scan_profile) > 100:
        raise ValueError("scan_profile non valido")
    _require_read_only_mailbox(mailbox)
    unread_before = now - timedelta(days=policy.unread_age_days)
    read_otp_before = now - timedelta(days=policy.read_one_time_code_age_days)
    read_access_before = now - timedelta(
        days=policy.read_routine_access_alert_age_days
    )
    current_policy_fingerprint = policy_safety_fingerprint(policy)
    matched: dict[str, MatureQuarantineCandidate] = {}
    allowed_categories = {
        EmailCategory.ADVERTISING,
        EmailCategory.ONE_TIME_CODE,
        EmailCategory.SOCIAL,
        EmailCategory.SPAM,
        EmailCategory.SECURITY,
    }

    def is_mature(message_id: str, currently_unread: bool) -> bool:
        if store.shadow_recovery_expected_unread(
            policy.account_id,
            policy.provider,
            message_id,
            scan_profile,
            current_policy_fingerprint,
        ) is not currently_unread:
            return False
        if not store.has_threat_assessment_id(
            policy.account_id,
            policy.provider,
            message_id,
            scan_profile,
        ):
            return False
        if store.threat_protects_message_id(
            policy.account_id,
            policy.provider,
            message_id,
            scan_profile,
        ):
            return False
        if store.has_quarantine_finalization_id(
            policy.account_id,
            policy.provider,
            message_id,
            scan_profile,
        ):
            return False
        execution = store.quarantine_pilot_record_for_message_id(
            policy.account_id,
            policy.provider,
            message_id,
            scan_profile,
        )
        if execution is None or execution[1] not in {"applied", "already_applied"}:
            return False
        executed_at = execution[0]
        if now < executed_at + timedelta(days=QUARANTINE_DELAY_DAYS):
            return False
        record = store.shadow_record_for_message_id(
            policy.account_id,
            policy.provider,
            message_id,
            scan_profile,
        )
        if record is None or record[1] != "quarantine":
            return False
        try:
            category = EmailCategory(record[0])
        except ValueError:
            return False
        if category not in allowed_categories:
            return False
        # Il quiz è opzionale. Tieni/Non so annulla però sempre la successiva
        # finalizzazione della proposta automatica del modello.
        if store.quiz_answer_for_message_id(
            policy.account_id,
            policy.provider,
            message_id,
        ) in {"keep", "unsure"}:
            return False
        matched[message_id] = MatureQuarantineCandidate(
            message_id,
            category,
            executed_at,
            currently_unread,
        )
        return True

    message_ids = list(
        mailbox.iter_inbox_matching_candidate_ids(
            unread_before,
            read_otp_before,
            read_access_before,
            limit,
            search_limit,
            is_mature,
        )
    )
    return [matched[message_id] for message_id in message_ids]
