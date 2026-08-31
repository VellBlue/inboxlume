from __future__ import annotations

from datetime import datetime
from email.utils import getaddresses, parseaddr

from .config import AccountPolicy
from .models import (
    Classification,
    EmailCategory,
    EmailRecord,
    PolicyAction,
    PolicyDecision,
    PreferenceSnapshot,
    RetentionSignal,
)
from .semantic_guardrails import (
    AccessAlertKind,
    access_alert_kind,
    has_permanent_transaction_record,
)


def _sender_parts(sender: str) -> tuple[str, str]:
    address = parseaddr(sender)[1].strip().casefold()
    domain = address.rsplit("@", 1)[1] if "@" in address else ""
    return address, domain


_RECIPIENT_HEADERS = frozenset(
    {"to", "cc", "bcc", "delivered-to", "x-original-to", "envelope-to"}
)


def _valid_addresses(values: list[str]) -> frozenset[str]:
    addresses: set[str] = set()
    for _, raw_address in getaddresses(values):
        address = raw_address.strip().casefold()
        if (
            3 <= len(address) <= 320
            and address.count("@") == 1
            and not any(character.isspace() or ord(character) < 32 for character in address)
        ):
            addresses.add(address)
    return frozenset(addresses)


def _is_sent_to_self(message: EmailRecord) -> bool:
    senders = _valid_addresses([message.sender])
    if not senders:
        return False
    recipients = _valid_addresses(
        [
            str(value)
            for key, value in message.headers.items()
            if str(key).casefold() in _RECIPIENT_HEADERS
        ]
    )
    return bool(senders.intersection(recipients))


class SafetyPolicyEngine:
    """Converte la classificazione in una proposta prudenziale e reversibile."""

    def decide(
        self,
        message: EmailRecord,
        classification: Classification,
        policy: AccountPolicy,
        now: datetime,
        preference: PreferenceSnapshot | None = None,
    ) -> PolicyDecision:
        if message.account_id != policy.account_id:
            raise ValueError("la policy non corrisponde all'account del messaggio")

        flags = message.normalized_flags
        if flags.intersection({"starred", "important", "flagged"}):
            return PolicyDecision(PolicyAction.KEEP, ("protected_mailbox_flag",))
        if message.known_contact or message.user_replied:
            return PolicyDecision(PolicyAction.KEEP, ("known_relationship",))
        if _is_sent_to_self(message):
            return PolicyDecision(PolicyAction.KEEP, ("self_sent_message",))
        if has_permanent_transaction_record(message):
            return PolicyDecision(PolicyAction.KEEP, ("transaction_record",))

        access_alert = access_alert_kind(message)
        if access_alert is AccessAlertKind.HIGH_RISK:
            return PolicyDecision(PolicyAction.KEEP, ("high_risk_access_alert",))
        if message.unread and (
            access_alert is AccessAlertKind.ROUTINE
            or classification.category is EmailCategory.SECURITY
        ):
            return PolicyDecision(PolicyAction.KEEP, ("unread_access_alert",))

        # Una classificazione bancaria indica contenuto operativo, non pubblicità:
        # le promozioni bancarie devono essere classificate come advertising prima
        # di raggiungere questo guardrail.
        if classification.category is EmailCategory.BANKING:
            return PolicyDecision(PolicyAction.KEEP, ("banking_record_or_notice",))

        address, domain = _sender_parts(message.sender)
        if address in policy.protected_senders or domain in policy.protected_domains:
            return PolicyDecision(PolicyAction.KEEP, ("protected_sender",))

        protected_text = f"{message.subject}\n{message.body_text}".casefold()
        if any(keyword in protected_text for keyword in policy.protected_keywords):
            return PolicyDecision(PolicyAction.REVIEW, ("protected_keyword",))
        if policy.protect_attachments and message.has_attachment:
            return PolicyDecision(PolicyAction.REVIEW, ("attachment_requires_review",))

        # A local-model outage is an abstention, not cleanup evidence.  The
        # heuristic fallback may still power protective KEEP rules above, but
        # it can never combine with learned preferences to authorise a move.
        if "local_model_fallback" in classification.reason_codes:
            return PolicyDecision(PolicyAction.REVIEW, ("local_model_unavailable",))

        if (
            not message.unread
            and access_alert is AccessAlertKind.ROUTINE
            and message.age_days(now) >= policy.read_routine_access_alert_age_days
        ):
            if classification.confidence >= policy.quarantine_confidence:
                return PolicyDecision(
                    PolicyAction.QUARANTINE,
                    ("expired_read_routine_access_alert",),
                )
            return PolicyDecision(
                PolicyAction.REVIEW,
                ("possible_expired_read_routine_access_alert",),
            )

        # Un codice monouso già letto perde utilità rapidamente. L'eccezione è
        # comunque solo una proposta reversibile di quarantena, mai una
        # cancellazione definitiva, e richiede una classificazione molto sicura.
        if not message.unread:
            if (
                classification.category is EmailCategory.ONE_TIME_CODE
                and message.age_days(now) >= policy.read_one_time_code_age_days
            ):
                if classification.confidence >= policy.quarantine_confidence:
                    return PolicyDecision(
                        PolicyAction.QUARANTINE,
                        ("expired_read_one_time_code",),
                    )
                return PolicyDecision(
                    PolicyAction.REVIEW,
                    ("possible_expired_read_one_time_code",),
                )
            return PolicyDecision(PolicyAction.KEEP, ("message_is_read",))

        if message.age_days(now) < policy.unread_age_days:
            return PolicyDecision(PolicyAction.KEEP, ("younger_than_threshold",))

        if classification.category in policy.protected_categories:
            return PolicyDecision(
                PolicyAction.REVIEW,
                ("protected_category", classification.category.value),
            )

        learned_discard = False
        if policy.learning.enabled and preference is not None:
            margin = policy.learning.similarity_conflict_margin
            keep_match = (
                preference.keep_similarity
                >= policy.learning.keep_similarity_threshold
            )
            discard_match = (
                preference.dont_keep_similarity
                >= policy.learning.discard_similarity_threshold
            )
            if keep_match and discard_match:
                return PolicyDecision(
                    PolicyAction.REVIEW,
                    ("conflicting_similar_examples",),
                )
            if keep_match and (
                preference.keep_similarity
                >= preference.dont_keep_similarity + margin
            ):
                return PolicyDecision(
                    PolicyAction.KEEP,
                    ("similar_content_previously_kept",),
                )
            recent_behavior_keep = (
                preference.recent_content_evidence
                >= policy.learning.minimum_observations
                and preference.recent_content_score
                >= policy.learning.protect_score
            )
            if recent_behavior_keep and discard_match:
                return PolicyDecision(
                    PolicyAction.REVIEW,
                    ("recent_behavior_conflicts_with_explicit_feedback",),
                )
            if recent_behavior_keep:
                return PolicyDecision(
                    PolicyAction.KEEP,
                    ("similar_content_opened_recently",),
                )
            learned_discard = discard_match and (
                preference.dont_keep_similarity
                >= preference.keep_similarity + margin
            )

        # Il giudizio sul contenuto è distinto dalla categoria. Un'email social o
        # pubblicitaria può quindi essere protetta se questa specifica email è utile.
        if classification.retention is RetentionSignal.PROTECT:
            if classification.retention_confidence >= policy.review_confidence:
                return PolicyDecision(PolicyAction.KEEP, ("content_requires_retention",))
            return PolicyDecision(PolicyAction.REVIEW, ("uncertain_content_retention",))

        if classification.confidence < policy.review_confidence:
            return PolicyDecision(PolicyAction.REVIEW, ("low_confidence",))
        if classification.category in {
            EmailCategory.ADVERTISING,
            EmailCategory.SOCIAL,
            EmailCategory.SPAM,
        }:
            model_discard = (
                classification.retention is RetentionSignal.DISCARD_CANDIDATE
                and classification.retention_confidence >= policy.quarantine_confidence
            )
            if (
                classification.confidence >= policy.quarantine_confidence
                and (model_discard or learned_discard)
            ):
                return PolicyDecision(
                    PolicyAction.QUARANTINE,
                    (
                        "similar_content_previously_discarded"
                        if learned_discard
                        else "content_specific_discard_candidate",
                        classification.category.value,
                    ),
                )
            return PolicyDecision(
                PolicyAction.REVIEW,
                ("content_or_similarity_not_decisive", classification.category.value),
            )
        return PolicyDecision(PolicyAction.REVIEW, ("ambiguous_old_unread",))
