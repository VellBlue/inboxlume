from __future__ import annotations

import argparse
import getpass
import json
import sys
import webbrowser
from collections import Counter
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from .classifier import Classifier, HeuristicClassifier, HybridClassifier, OllamaClassifier
from .config import AccountPolicy, load_policies, policy_safety_fingerprint
from .credential_store import SystemCredentialStore
from .direct_trash_guard import (
    require_direct_trash_authority,
    require_direct_trash_model,
)
from .learning import FeedbackSignal, PreferenceStore, load_or_create_hmac_key
from .local_models import profile_for_backend, scan_profile_for_model
from .lumegraph_runtime import run_lumegraph_shadow
from .models import EmailCategory, EmailRecord, PolicyAction, ProviderKind
from .model_evaluation import (
    MODEL_NAMES,
    MlxWorkerClassifier,
    evaluate_local_models,
    recover_answered_messages,
)


LOCAL_BACKEND_CHOICES = ("heuristic", "ollama", "gemma12", "gemma26")
from .pipeline import (
    InboxMutationCandidate,
    DryRunResult,
    prepare_automatic_quarantine_candidates,
    prepare_mature_quarantine_candidates,
    prepare_quiz,
    prepare_verified_quarantine_candidates,
    run_dry_scan,
    run_shadow_scan,
)
from .proof_of_obsolescence import lifecycle_hard_protected
from .policy import SafetyPolicyEngine
from .providers.contracts import GMAIL_MODIFY_SCOPE, GMAIL_READONLY_SCOPE, ReadOnlyMailbox
from .providers.gmail import GmailHistoryExpired, GmailReadOnlyMailbox
from .providers.gmail_finalizer import (
    QUARANTINE_DELAY_DAYS,
    GmailDirectTrashExecutor,
    GmailQuarantineFinalizer,
)
from .providers.gmail_quarantine import (
    QUARANTINE_LABEL_NAME,
    THREAT_LABEL_NAME,
    GmailLabelQuarantineExecutor,
    GmailThreatMarkerExecutor,
)
from .providers.google_oauth import (
    GoogleAccessTokenProvider,
    GoogleDesktopOAuthFlow,
    GoogleOAuthError,
    OAuthClientCredentials,
    SecretStore,
    load_authorization,
    save_authorization,
)
from .providers.yahoo import (
    YahooImapCredentials,
    YahooImapError,
    YahooReadOnlyMailbox,
    load_yahoo_credentials,
    save_yahoo_credentials,
)
from .providers.yahoo_quarantine import (
    YAHOO_QUARANTINE_FOLDER,
    YAHOO_TRASH_FOLDER,
    YahooDirectTrashExecutor,
    YahooQuarantineExecutor,
    YahooThreatMarkerExecutor,
)
from .quiz import CalibrationQuiz, QuizAnswer
from .runtime import calibration_answer_counts
from .sanitizer import normalize_plain_text, sanitize_body
from .safety_governor import evaluate_safety_governor, operational_quarantine_gate
from .temporal_drift import (
    DEFAULT_HISTORICAL_DAYS,
    DEFAULT_RECENT_DAYS,
    evaluate_temporal_preference_drift,
)
from .threat_signals import (
    THREAT_CONSENSUS_ENGINE_VERSION,
    SemanticThreatAssessment,
    SemanticThreatVerdict,
    ThreatIntent,
    ThreatSemanticMode,
    assess_threat_signals,
    combine_threat_assessments,
    semantic_followup_recommended,
)


DEFAULT_PREFERENCE_DB = Path("data/preferences.sqlite3")
DEFAULT_YAHOO_PREFERENCE_DB = Path("data/yahoo_preferences.sqlite3")


def summarize_dry_run(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Riepilogo aggregato che non contiene identificativi o testo delle email."""

    return {
        "type": "dry_run_summary",
        "processed": len(results),
        "categories": dict(sorted(Counter(str(item["category"]) for item in results).items())),
        "content_assessments": dict(
            sorted(
                Counter(
                    str(item.get("retention", "uncertain")) for item in results
                ).items()
            )
        ),
        "suggested_actions": dict(
            sorted(Counter(str(item["suggested_action"]) for item in results).items())
        ),
        "changes_mailbox": False,
    }


def _privacy_safe_provider_dry_run_event(
    item: dict[str, Any],
    ordinal: int,
) -> dict[str, Any]:
    """Drop provider-correlatable identity/time before terminal or log output."""

    return {
        "type": "dry_run_result",
        "result_number": ordinal,
        **{
            key: value
            for key, value in item.items()
            if key not in {"account_id", "message_id", "received_at"}
        },
    }


def _local_temporal_drift(
    preferences: PreferenceStore,
    account_id: str,
    scan_profile: str,
    now: datetime,
):  # noqa: ANN202
    evidence = preferences.temporal_preference_evidence(
        account_id,
        scan_profile,
        now,
        recent_days=DEFAULT_RECENT_DAYS,
        historical_days=DEFAULT_HISTORICAL_DAYS,
    )
    return evaluate_temporal_preference_drift(
        account_id,
        scan_profile,
        evidence,
    )


def _message_from_json(
    raw: dict[str, Any], account_id: str, provider: ProviderKind
) -> EmailRecord:
    received_at = datetime.fromisoformat(str(raw["received_at"]).replace("Z", "+00:00"))
    headers = raw.get("headers", {})
    flags = raw.get("flags", [])
    if not isinstance(headers, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in headers.items()
    ):
        raise ValueError("headers deve essere un oggetto stringa:stringa")
    if not isinstance(flags, list) or not all(isinstance(value, str) for value in flags):
        raise ValueError("flags deve essere una lista di stringhe")
    content_type = str(raw.get("content_type", "text/plain"))
    return EmailRecord(
        account_id=account_id,
        provider=provider,
        message_id=str(raw["message_id"]),
        received_at=received_at,
        unread=bool(raw["unread"]),
        sender=str(raw["sender"]),
        subject=str(raw.get("subject", "")),
        body_text=sanitize_body(str(raw.get("body", "")), content_type=content_type),
        headers=headers,
        flags=frozenset(flags),
        known_contact=bool(raw.get("known_contact", False)),
        user_replied=bool(raw.get("user_replied", False)),
        has_attachment=bool(raw.get("has_attachment", False)),
    )


def evaluate_jsonl(
    config_path: Path,
    account_id: str,
    input_path: Path,
    backend: str,
    ollama_model: str,
    now: datetime,
) -> list[dict[str, Any]]:
    policies = load_policies(config_path)
    try:
        policy = policies[account_id]
    except KeyError as exc:
        raise ValueError(f"account non configurato: {account_id}") from exc

    classifier, local_backend = _build_classifier(backend, ollama_model)

    engine = SafetyPolicyEngine()
    output: list[dict[str, Any]] = []
    try:
        with input_path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                if len(output) >= policy.max_candidates_per_run:
                    break
                try:
                    raw = json.loads(line)
                    if not isinstance(raw, dict):
                        raise ValueError("la riga non contiene un oggetto JSON")
                    message = _message_from_json(raw, account_id, policy.provider)
                except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise ValueError(f"input non valido alla riga {line_number}: {exc}") from exc

                classification = classifier.classify(message)
                decision = engine.decide(message, classification, policy, now)
                output.append(
                    {
                        "account_id": account_id,
                        "message_id": message.message_id,
                        "category": classification.category.value,
                        "confidence": round(classification.confidence, 4),
                        "classifier": classification.classifier,
                        "classification_reasons": list(classification.reason_codes),
                        "suggested_action": decision.action.value,
                        "policy_reasons": list(decision.reason_codes),
                        "dry_run": decision.dry_run,
                        "changes_mailbox": decision.changes_mailbox,
                    }
                )
    finally:
        _unload_local_backend(local_backend)
    return output


def _build_classifier(
    backend: str,
    ollama_model: str,
) -> tuple[Classifier, OllamaClassifier | MlxWorkerClassifier | None]:
    heuristic = HeuristicClassifier()
    if backend == "heuristic":
        return heuristic, None
    if backend == "ollama":
        ollama = OllamaClassifier(model=ollama_model)
        return HybridClassifier(ollama, heuristic), ollama
    if backend in {"gemma12", "gemma26"}:
        gemma = MlxWorkerClassifier(backend)
        return HybridClassifier(gemma, heuristic), gemma
    raise ValueError(f"backend non supportato: {backend}")


def _unload_local_backend(
    backend: OllamaClassifier | MlxWorkerClassifier | None,
) -> None:
    if backend is None:
        return
    try:
        backend.unload()
    except RuntimeError:
        # Il classificatore ibrido ha già applicato il fallback prudenziale.
        return


def _semantic_threat_fallback(analyzer: str) -> SemanticThreatAssessment:
    return SemanticThreatAssessment(
        verdict=SemanticThreatVerdict.UNCERTAIN,
        intent=ThreatIntent.UNCERTAIN,
        impersonation=False,
        credential_request=False,
        money_request=False,
        urgency_pressure=False,
        link_action=False,
        plausible_legitimate_context=False,
        confidence=0.0,
        reason_codes=("insufficient_evidence",),
        analyzer=analyzer,
    )


def _apply_threat_protection(
    results: list[DryRunResult],
    local_backend: OllamaClassifier | MlxWorkerClassifier | None,
    preferences: PreferenceStore,
    account_id: str,
    scan_profile: str,
    now: datetime,
    semantic_mode: ThreatSemanticMode | str = ThreatSemanticMode.TARGETED_SEMANTIC,
) -> tuple[list[DryRunResult], dict[str, object]]:
    """Turn high-risk evidence into protection only; never cleanup authority."""

    mode = ThreatSemanticMode(semantic_mode)
    updated: list[DryRunResult] = []
    current_levels: Counter[str] = Counter()
    current_intents: Counter[str] = Counter()
    current_signals: Counter[str] = Counter()
    semantic_failures = 0
    semantic_inferences_requested = 0
    semantic_inferences_skipped = 0
    protected_current = 0
    semantic_analyzer = getattr(local_backend, "assess_threat_semantics", None)
    for result in results:
        semantic_followup_failed = False
        # Authentication-Results remains excluded until a provider adapter can
        # attest provenance instead of merely returning an email header.
        deterministic = assess_threat_signals(
            result.message,
            trusted_authentication_results=False,
        )
        should_request_semantics = semantic_followup_recommended(deterministic, mode)
        if should_request_semantics and callable(semantic_analyzer):
            semantic_inferences_requested += 1
            try:
                semantic = semantic_analyzer(result.message)
            except (RuntimeError, TypeError, ValueError):
                semantic_failures += 1
                semantic_followup_failed = True
                semantic = _semantic_threat_fallback("local-model-failure")
        elif should_request_semantics:
            semantic_inferences_requested += 1
            semantic_failures += 1
            semantic_followup_failed = True
            semantic = _semantic_threat_fallback("local-model-unavailable")
        else:
            semantic_inferences_skipped += 1
            # A message skipped in the confirmed mode may still carry weak
            # signals, so calling it clear would misreport the evidence.
            analyzer = (
                "technical-only"
                if mode is ThreatSemanticMode.TECHNICAL_ONLY
                else "technical-below-alert"
                if deterministic.signals
                else "technical-screen-clear"
            )
            semantic = _semantic_threat_fallback(analyzer)
        assessment = combine_threat_assessments(deterministic, semantic)
        marker_candidate = assessment.protective_review_recommended
        protective_review = (
            (marker_candidate or semantic_followup_failed)
            and result.decision.action is not PolicyAction.KEEP
        )
        preferences.record_threat_assessment(
            result.message,
            scan_profile,
            assessment,
            now,
            protective_review=protective_review,
        )
        current_levels[assessment.level.value] += 1
        current_intents[assessment.semantic.intent.value] += 1
        current_signals.update(signal.value for signal in deterministic.signals)
        if marker_candidate or protective_review:
            if protective_review:
                protected_current += 1
            result = replace(
                result,
                decision=replace(
                    result.decision,
                    action=(
                        PolicyAction.REVIEW
                        if protective_review
                        else result.decision.action
                    ),
                    reason_codes=tuple(
                        dict.fromkeys(
                            (
                                *result.decision.reason_codes,
                                *(
                                    ("threat_protective_review",)
                                    if protective_review
                                    else ()
                                ),
                                *(
                                    ("threat_analysis_incomplete",)
                                    if semantic_followup_failed
                                    else ()
                                ),
                                *(
                                    ("threat_visible_marker_candidate",)
                                    if marker_candidate
                                    else ()
                                ),
                                f"threat_level_{assessment.level.value}",
                            )
                        )
                    ),
                ),
            )
        updated.append(result)
    return updated, {
        "engine_version": THREAT_CONSENSUS_ENGINE_VERSION,
        "operational": True,
        "semantic_mode": mode.value,
        "assessed_current_batch": len(results),
        "protective_reviews_current_batch": protected_current,
        "semantic_inferences_requested_current_batch": semantic_inferences_requested,
        "semantic_inferences_skipped_current_batch": semantic_inferences_skipped,
        "semantic_failures_current_batch": semantic_failures,
        "current_levels": dict(sorted(current_levels.items())),
        "current_intents": dict(sorted(current_intents.items())),
        "current_signals": dict(sorted(current_signals.items())),
        "ledger": preferences.threat_assessment_summary(account_id, scan_profile),
        "authorizes_cleanup": False,
        "stored_plaintext": False,
        "changes_mailbox_by_itself": False,
    }


def _visible_threat_marker_ids(results: list[DryRunResult]) -> list[str]:
    """Return only current high-risk IDs; callers must never expose this list."""

    return list(
        dict.fromkeys(
            result.message.message_id
            for result in results
            if "threat_visible_marker_candidate" in result.decision.reason_codes
        )
    )


def _apply_visible_threat_markers(
    message_ids: list[str],
    apply_message: Callable[[str], Any],
    record_outcome: Callable[[str, str], None],
) -> dict[str, object]:
    outcomes: Counter[str] = Counter()
    for message_id in message_ids:
        try:
            result = apply_message(message_id)
        except Exception:  # noqa: BLE001 - isolated best-effort protective metadata
            outcome = "failed"
        else:
            outcome = result.outcome.value
        outcomes[outcome] += 1
        record_outcome(message_id, outcome)
    return {
        "selected": len(message_ids),
        "applied": outcomes.get("applied", 0),
        "visible": outcomes.get("applied", 0) + outcomes.get("already_applied", 0),
        "outcomes": dict(sorted(outcomes.items())),
    }


def _build_lumegraph_shadow(
    results: list[DryRunResult],
    local_backend: OllamaClassifier | MlxWorkerClassifier | None,
    preferences: PreferenceStore,
    account_id: str,
    scan_profile: str,
    now: datetime,
    read_otp_age_days: int,
) -> dict[str, object]:
    """Build local lifecycle evidence; failures never interrupt ordinary filtering."""

    try:
        return run_lumegraph_shadow(
            results,
            local_backend,
            preferences,
            account_id,
            scan_profile,
            now,
            read_otp_age_days=read_otp_age_days,
        )
    except Exception:  # noqa: BLE001 - strict isolation boundary for shadow research
        return {
            "engine_version": "lumegraph-v2",
            "available": False,
            "error_code": "local_shadow_unavailable",
            "shadow_only": False,
            "authorizes_policy": False,
            "authorizes_actions": False,
            "run_nodes": 0,
            "run_transitions": 0,
            "reads_additional_bodies": False,
            "stored_plaintext": False,
            "changes_mailbox": False,
        }


def _apply_obsolescence_proofs(
    results: list[DryRunResult],
    preferences: PreferenceStore,
    account_id: str,
    provider: ProviderKind,
    scan_profile: str,
    *,
    direct_to_trash: bool,
) -> tuple[list[DryRunResult], dict[str, object]]:
    """Apply verified proofs without ever making Proof a direct-Trash authority."""

    updated: list[DryRunResult] = []
    verified_current = 0
    promoted_to_quarantine = 0
    confirmed_ordinary = 0
    withheld_from_direct_trash = 0
    witnesses: Counter[str] = Counter()
    for result in results:
        if lifecycle_hard_protected(
            result.message,
            result.classification,
            result.decision,
        ):
            updated.append(result)
            continue
        proof = preferences.obsolescence_proof_for_message_id(
            account_id,
            provider,
            result.message.message_id,
            scan_profile,
        )
        if proof is None or proof[0] != "verified" or proof[2] != "quarantine":
            updated.append(result)
            continue
        verified_current += 1
        witnesses[proof[1]] += 1
        if result.decision.action is PolicyAction.KEEP:
            # The deterministic ordinary KEEP gate always has final authority.
            updated.append(result)
            continue
        if result.decision.action is PolicyAction.QUARANTINE:
            confirmed_ordinary += 1
            updated.append(
                replace(
                    result,
                    decision=replace(
                        result.decision,
                        reason_codes=tuple(
                            dict.fromkeys(
                                (*result.decision.reason_codes, "obsolescence_proof_verified")
                            )
                        ),
                    ),
                )
            )
            continue
        if direct_to_trash:
            # A proof can support an existing ordinary Trash candidate, but cannot
            # promote a Review directly into Trash.
            withheld_from_direct_trash += 1
            updated.append(result)
            continue
        promoted_to_quarantine += 1
        updated.append(
            replace(
                result,
                decision=replace(
                    result.decision,
                    action=PolicyAction.QUARANTINE,
                    reason_codes=("obsolescence_proof_verified", proof[1]),
                ),
            )
        )
    ledger = preferences.obsolescence_proof_summary(account_id, scan_profile)
    return updated, {
        **ledger,
        "verified_current_batch": verified_current,
        "promoted_to_quarantine_current_batch": promoted_to_quarantine,
        "confirmed_ordinary_current_batch": confirmed_ordinary,
        "withheld_from_direct_trash_current_batch": withheld_from_direct_trash,
        "current_witnesses": dict(sorted(witnesses.items())),
        "operational": True,
        "authorizes_quarantine": int(ledger.get("verified_total", 0)) > 0,
        "authorizes_trash": False,
        "changes_mailbox_by_itself": False,
    }


def _disabled_module_summary(module: str) -> dict[str, object]:
    """Aggregate-only marker for an optional module skipped by the user."""

    return {
        "engine_version": module,
        "enabled": False,
        "operational": False,
        "authorizes_policy": False,
        "authorizes_actions": False,
        "reads_additional_bodies": False,
        "stored_plaintext": False,
        "changes_mailbox": False,
    }
def _require_gmail_policy(config_path: Path, account_id: str) -> AccountPolicy:
    policies = load_policies(config_path)
    try:
        policy = policies[account_id]
    except KeyError as exc:
        raise ValueError(f"account non configurato: {account_id}") from exc
    if policy.provider is not ProviderKind.GMAIL:
        raise ValueError(f"l'account {account_id} non è configurato come Gmail")
    return policy


def _require_yahoo_policy(config_path: Path, account_id: str) -> AccountPolicy:
    policies = load_policies(config_path)
    try:
        policy = policies[account_id]
    except KeyError as exc:
        raise ValueError(f"account non configurato: {account_id}") from exc
    if policy.provider is not ProviderKind.YAHOO:
        raise ValueError(f"l'account {account_id} non è configurato come Yahoo")
    return policy


def _resolved_policy(
    config_path: Path,
    account_id: str,
    provider: ProviderKind,
    policy_override: AccountPolicy | None,
) -> AccountPolicy:
    if policy_override is None:
        return (
            _require_gmail_policy(config_path, account_id)
            if provider is ProviderKind.GMAIL
            else _require_yahoo_policy(config_path, account_id)
        )
    if (
        policy_override.account_id != account_id
        or policy_override.provider is not provider
    ):
        raise ValueError("policy dinamica non corrispondente all'account")
    return policy_override


def authorize_yahoo(
    config_path: Path,
    account_id: str,
    email_address: str,
    app_password: str,
    store: SecretStore | None = None,
    policy_override: AccountPolicy | None = None,
) -> None:
    _resolved_policy(
        config_path, account_id, ProviderKind.YAHOO, policy_override
    )
    keychain = store or SystemCredentialStore()
    save_yahoo_credentials(
        keychain,
        account_id,
        YahooImapCredentials(email_address, app_password),
    )


def yahoo_probe(
    config_path: Path,
    account_id: str,
    store: SecretStore | None = None,
    policy_override: AccountPolicy | None = None,
) -> dict[str, Any]:
    _resolved_policy(
        config_path, account_id, ProviderKind.YAHOO, policy_override
    )
    keychain = store or SystemCredentialStore()
    mailbox = YahooReadOnlyMailbox.from_secret_store(account_id, keychain)
    try:
        inbox_count = mailbox.transport.inbox_count()
        return {
            "type": "yahoo_probe_summary",
            "inbox_accessible": True,
            "inbox_count": inbox_count,
            "sample_uid_present": inbox_count > 0,
            "move_supported": "MOVE" in mailbox.transport.capabilities,
            "uidplus_supported": "UIDPLUS" in mailbox.transport.capabilities,
            "read_bodies": False,
            "changes_mailbox": False,
            "selected_folder": "INBOX",
        }
    finally:
        mailbox.close()


def authorize_gmail(
    config_path: Path,
    account_id: str,
    client_json_path: Path,
    open_authorization_url: Callable[[str], None],
    timeout_seconds: float = 300,
    store: SecretStore | None = None,
    flow: GoogleDesktopOAuthFlow | None = None,
    policy_override: AccountPolicy | None = None,
) -> None:
    _resolved_policy(
        config_path, account_id, ProviderKind.GMAIL, policy_override
    )
    credentials = OAuthClientCredentials.from_json_file(client_json_path)
    oauth_flow = flow or GoogleDesktopOAuthFlow()
    token = oauth_flow.authorize(
        credentials,
        open_authorization_url,
        timeout_seconds=timeout_seconds,
    )
    if token.refresh_token is None:
        raise GoogleOAuthError("refresh token Google mancante")
    save_authorization(
        store or SystemCredentialStore(),
        account_id,
        credentials,
        token.refresh_token,
    )


def authorize_gmail_quarantine(
    config_path: Path,
    account_id: str,
    open_authorization_url: Callable[[str], None],
    timeout_seconds: float = 300,
    store: SecretStore | None = None,
    flow: GoogleDesktopOAuthFlow | None = None,
    policy_override: AccountPolicy | None = None,
) -> None:
    _resolved_policy(
        config_path, account_id, ProviderKind.GMAIL, policy_override
    )
    keychain = store or SystemCredentialStore()
    credentials, _ = load_authorization(
        keychain,
        account_id,
        GMAIL_READONLY_SCOPE,
    )
    oauth_flow = flow or GoogleDesktopOAuthFlow(scope=GMAIL_MODIFY_SCOPE)
    token = oauth_flow.authorize(
        credentials,
        open_authorization_url,
        timeout_seconds=timeout_seconds,
    )
    if token.refresh_token is None:
        raise GoogleOAuthError("refresh token Google quarantena mancante")
    save_authorization(
        keychain,
        account_id,
        credentials,
        token.refresh_token,
        scope=GMAIL_MODIFY_SCOPE,
    )


def gmail_quarantine_pilot(
    config_path: Path,
    account_id: str,
    now: datetime,
    limit: int,
    search_limit: int,
    scan_profile: str,
    state_db: Path,
    secret_store: SecretStore | None = None,
) -> dict[str, Any]:
    policy = _require_gmail_policy(config_path, account_id)
    if not 1 <= limit <= 5:
        raise ValueError("il pilot consente al massimo 5 email per esecuzione")
    keychain = secret_store or SystemCredentialStore()
    preferences = PreferenceStore(
        state_db,
        load_or_create_hmac_key(keychain, account_id, state_db),
        account_id,
    )
    mailbox = GmailReadOnlyMailbox(
        account_id,
        GoogleAccessTokenProvider(account_id, store=keychain),
    )
    candidates = prepare_verified_quarantine_candidates(
        policy,
        mailbox,
        preferences,
        now,
        limit,
        search_limit,
        scan_profile,
    )
    executor = GmailLabelQuarantineExecutor(
        GoogleAccessTokenProvider(
            account_id,
            store=keychain,
            scope=GMAIL_MODIFY_SCOPE,
        )
    )
    outcomes: Counter[str] = Counter()
    for candidate in candidates:
        result = executor.apply_label_quarantine(
            candidate.message_id,
            candidate.expected_unread,
        )
        outcomes[result.outcome.value] += 1
        preferences.record_quarantine_pilot_execution(
            account_id,
            policy.provider,
            candidate.message_id,
            scan_profile,
            now,
            result.outcome.value,
        )
    return {
        "type": "gmail_label_quarantine_pilot_summary",
        "selected": len(candidates),
        "outcomes": dict(sorted(outcomes.items())),
        "ledger": preferences.quarantine_pilot_summary(account_id, scan_profile),
        "label": QUARANTINE_LABEL_NAME,
        "leaves_messages_in_inbox": True,
        "read_bodies": False,
        "stored_plaintext": False,
        "changes_mailbox": bool(outcomes.get("applied")),
        "permanent_delete_available": False,
    }


def gmail_finalize_quarantine(
    config_path: Path,
    account_id: str,
    now: datetime,
    limit: int,
    search_limit: int,
    scan_profile: str,
    state_db: Path,
    secret_store: SecretStore | None = None,
) -> dict[str, Any]:
    """Finalizza soltanto quarantene mature, con ricontrollo Gmail immediato."""

    policy = _require_gmail_policy(config_path, account_id)
    if not 1 <= limit <= 5:
        raise ValueError("la finalizzazione consente al massimo 5 email per esecuzione")
    keychain = secret_store or SystemCredentialStore()
    preferences = PreferenceStore(
        state_db,
        load_or_create_hmac_key(keychain, account_id, state_db),
        account_id,
    )
    mailbox = GmailReadOnlyMailbox(
        account_id,
        GoogleAccessTokenProvider(account_id, store=keychain),
    )
    candidates = prepare_mature_quarantine_candidates(
        policy,
        mailbox,
        preferences,
        now,
        limit,
        search_limit,
        scan_profile,
    )
    finalizer = GmailQuarantineFinalizer(
        GoogleAccessTokenProvider(
            account_id,
            store=keychain,
            scope=GMAIL_MODIFY_SCOPE,
        )
    )
    outcomes: Counter[str] = Counter()
    for candidate in candidates:
        result = finalizer.finalize(candidate, now)
        outcomes[result.outcome.value] += 1
        preferences.record_quarantine_finalization(
            account_id,
            policy.provider,
            candidate.message_id,
            scan_profile,
            now,
            result.outcome.value,
        )
    return {
        "type": "gmail_quarantine_finalization_summary",
        "selected": len(candidates),
        "outcomes": dict(sorted(outcomes.items())),
        "ledger": preferences.quarantine_finalization_summary(
            account_id,
            scan_profile,
        ),
        "quarantine_delay_days": QUARANTINE_DELAY_DAYS,
        "removing_quarantine_label_cancels": True,
        "starred_or_important_cancels": True,
        "read_bodies": False,
        "stored_plaintext": False,
        "changes_mailbox": any(
            outcomes.get(outcome)
            for outcome in ("moved_to_trash", "moved_to_spam")
        ),
        "permanent_delete_available": False,
        "trash_emptying_available": False,
    }


def probe_gmail(
    config_path: Path,
    account_id: str,
    store: SecretStore | None = None,
    policy_override: AccountPolicy | None = None,
) -> bool:
    _resolved_policy(
        config_path, account_id, ProviderKind.GMAIL, policy_override
    )
    token_provider = GoogleAccessTokenProvider(account_id, store=store)
    mailbox = GmailReadOnlyMailbox(account_id, token_provider)
    return mailbox.probe_inbox()


def count_gmail_candidates(
    config_path: Path,
    account_id: str,
    now: datetime,
    store: SecretStore | None = None,
) -> tuple[int, int, int, int, int, int]:
    policy = _require_gmail_policy(config_path, account_id)
    if now.tzinfo is None:
        raise ValueError("now deve includere il fuso orario")
    token_provider = GoogleAccessTokenProvider(account_id, store=store)
    mailbox = GmailReadOnlyMailbox(account_id, token_provider)
    unread_cutoff = now - timedelta(days=policy.unread_age_days)
    read_otp_cutoff = now - timedelta(days=policy.read_one_time_code_age_days)
    read_access_cutoff = now - timedelta(
        days=policy.read_routine_access_alert_age_days
    )
    return (
        mailbox.estimate_inbox_unread_before(unread_cutoff),
        mailbox.estimate_inbox_read_one_time_code_candidates_before(read_otp_cutoff),
        mailbox.estimate_inbox_read_routine_access_alert_candidates_before(
            read_access_cutoff
        ),
        policy.unread_age_days,
        policy.read_one_time_code_age_days,
        policy.read_routine_access_alert_age_days,
    )


def gmail_dry_run(
    config_path: Path,
    account_id: str,
    backend: str,
    ollama_model: str,
    now: datetime,
    limit: int,
    store: SecretStore | None = None,
    mailbox: ReadOnlyMailbox | None = None,
    classifier: Classifier | None = None,
) -> list[dict[str, Any]]:
    policy = _require_gmail_policy(config_path, account_id)
    keychain = store or SystemCredentialStore()
    actual_mailbox = mailbox or GmailReadOnlyMailbox(
        account_id,
        GoogleAccessTokenProvider(account_id, store=keychain),
    )
    local_backend: OllamaClassifier | MlxWorkerClassifier | None = None
    if classifier is None:
        classifier, local_backend = _build_classifier(backend, ollama_model)
    try:
        return [
            result.as_dict()
            for result in run_dry_scan(
                policy,
                actual_mailbox,
                classifier,
                now,
                limit,
            )
        ]
    finally:
        _unload_local_backend(local_backend)


def gmail_model_evaluation(
    config_path: Path,
    account_id: str,
    model_names: list[str],
    now: datetime,
    search_limit: int,
    state_db: Path,
    progress: Callable[[str], None] | None = None,
    secret_store: SecretStore | None = None,
) -> dict[str, Any]:
    policy = _require_gmail_policy(config_path, account_id)
    keychain = secret_store or SystemCredentialStore()
    preferences = PreferenceStore(
        state_db,
        load_or_create_hmac_key(keychain, account_id, state_db),
        account_id,
    )
    mailbox = GmailReadOnlyMailbox(
        account_id,
        GoogleAccessTokenProvider(account_id, store=keychain),
    )
    labeled = recover_answered_messages(
        policy,
        mailbox,
        preferences,
        now,
        search_limit,
    )
    database_counts = preferences.quiz_answer_counts(account_id)
    recovered_counts = Counter(answer for _, answer in labeled)
    results = evaluate_local_models(
        model_names,
        labeled,
        policy,
        now,
        progress=progress,
    )
    return {
        "type": "model_evaluation_summary",
        "database_labels": database_counts,
        "recovered_labels": {
            answer: recovered_counts[answer]
            for answer in ("keep", "dont_keep", "unsure")
        },
        "search_limit": search_limit,
        "models": results,
        "read_bodies": True,
        "stored_plaintext": False,
        "changes_mailbox": False,
    }


def gmail_shadow_run(
    config_path: Path,
    account_id: str,
    backend: str,
    ollama_model: str,
    now: datetime,
    limit: int,
    search_limit: int,
    state_db: Path,
    secret_store: SecretStore | None = None,
    apply_quarantine_labels: bool = False,
    direct_to_trash: bool = False,
    policy_override: AccountPolicy | None = None,
    oldest_first: bool = False,
    progress: Callable[[int, int], None] | None = None,
    phase: Callable[[str], None] | None = None,
    governor_enforced: bool = False,
    threat_protection_enabled: bool = True,
    threat_semantic_mode: ThreatSemanticMode | str = ThreatSemanticMode.TARGETED_SEMANTIC,
    lumegraph_enabled: bool = True,
    obsolescence_proof_enabled: bool = True,
) -> dict[str, Any]:
    policy = _resolved_policy(
        config_path, account_id, ProviderKind.GMAIL, policy_override
    )
    keychain = secret_store or SystemCredentialStore()
    preferences = PreferenceStore(
        state_db,
        load_or_create_hmac_key(keychain, account_id, state_db),
        account_id,
    )
    if direct_to_trash:
        require_direct_trash_authority(
            backend,
            ollama_model,
            preferences.quiz_answer_counts(account_id),
        )
    mailbox = GmailReadOnlyMailbox(
        account_id,
        GoogleAccessTokenProvider(account_id, store=keychain),
    )
    behavior_feedback = _collect_gmail_behavior_feedback(
        mailbox,
        preferences,
        policy,
        now,
    )
    selected_profile = profile_for_backend(backend, ollama_model)
    scan_profile = (
        scan_profile_for_model(selected_profile)
        if selected_profile is not None
        else "heuristic-policy-v2"
    )
    if threat_protection_enabled:
        preferences.reset_stale_threat_assessments(
            account_id,
            scan_profile,
            threat_semantic_mode,
        )
    classifier, local_backend = _build_classifier(backend, ollama_model)
    try:
        results = run_shadow_scan(
            policy,
            mailbox,
            classifier,
            now,
            limit,
            search_limit,
            preferences,
            scan_profile,
            oldest_first=oldest_first,
            progress=progress,
            defer_completion=True,
        )
        if threat_protection_enabled:
            if phase is not None:
                phase("Checking phishing and scam signals locally…")
            results, threat_protection = _apply_threat_protection(
                results,
                local_backend,
                preferences,
                account_id,
                scan_profile,
                now,
                threat_semantic_mode,
            )
        else:
            threat_protection = _disabled_module_summary(
                THREAT_CONSENSUS_ENGINE_VERSION
            )
            preferences.record_disabled_threat_assessment_batch(
                (result.message for result in results),
                scan_profile,
                now,
            )
        if lumegraph_enabled:
            if phase is not None:
                phase("Building LumeGraph closure evidence locally…")
            lumegraph = _build_lumegraph_shadow(
                results,
                local_backend,
                preferences,
                account_id,
                scan_profile,
                now,
                policy.read_one_time_code_age_days,
            )
        else:
            lumegraph = _disabled_module_summary("lumegraph-v2")
        if obsolescence_proof_enabled:
            if phase is not None:
                phase("Applying Proof of Obsolescence checks…")
            results, proof_of_obsolescence = _apply_obsolescence_proofs(
                results,
                preferences,
                account_id,
                policy.provider,
                scan_profile,
                direct_to_trash=direct_to_trash,
            )
        else:
            proof_of_obsolescence = _disabled_module_summary("proof-of-obsolescence-v1")
        preferences.mark_shadow_batch_complete(
            (
                result.message
                for result in results
                if "local_model_fallback" not in result.classification.reason_codes
            ),
            scan_profile,
            policy_safety_fingerprint(policy),
        )
    finally:
        _unload_local_backend(local_backend)
    if phase is not None:
        phase("Applying permitted mailbox actions…")
    governor_report = evaluate_safety_governor(
        account_id,
        scan_profile,
        preferences.shadow_quarantine_evidence_by_category(
            account_id,
            scan_profile,
        ),
    )
    temporal_drift = _local_temporal_drift(
        preferences,
        account_id,
        scan_profile,
        now,
    )
    governor_gate = operational_quarantine_gate(
        governor_report,
        enforced=governor_enforced,
        protective_drift_families=temporal_drift.restricted_families,
    )
    if governor_gate.enforced and not direct_to_trash:
        allowed_categories = frozenset(
            category.value
            for category in EmailCategory
            if category.value not in governor_gate.blocked_families
        )
    else:
        allowed_categories = None
    blocked_by_governor = sum(
        1
        for result in results
        if result.decision.action is PolicyAction.QUARANTINE
        and not direct_to_trash
        and not governor_gate.permits(result.classification.category.value)
    )
    governor_authorized_direct_trash_candidates = sum(
        1
        for result in results
        if direct_to_trash
        and governor_gate.enforced
        and result.decision.action is PolicyAction.QUARANTINE
        and governor_gate.permits_direct_trash(
            result.classification.category.value
        )
    )
    marker_ids = _visible_threat_marker_ids(results) if threat_protection_enabled else []
    threat_marker_summary: dict[str, object] = {
        "selected": len(marker_ids) if apply_quarantine_labels else 0,
        "applied": 0,
        "visible": 0,
        "outcomes": {},
        "automatic": apply_quarantine_labels,
        "kind": "gmail_label",
        "label": THREAT_LABEL_NAME,
        "leaves_messages_in_inbox": True,
        "authorizes_cleanup": False,
        "stored_plaintext": False,
    }
    if apply_quarantine_labels and marker_ids:
        marker_token = GoogleAccessTokenProvider(
            account_id,
            store=keychain,
            scope=GMAIL_MODIFY_SCOPE,
        )
        marker_executor = GmailThreatMarkerExecutor(marker_token)
        threat_marker_summary.update(
            _apply_visible_threat_markers(
                marker_ids,
                marker_executor.apply,
                lambda message_id, outcome: preferences.record_threat_marker_execution(
                    account_id,
                    policy.provider,
                    message_id,
                    scan_profile,
                    now,
                    "gmail_label",
                    outcome,
                ),
            )
        )
    threat_marker_summary["ledger"] = preferences.threat_marker_summary(
        account_id, scan_profile
    )
    if apply_quarantine_labels:
        destination = "trash" if direct_to_trash else "quarantine"
        success_outcome = "moved_to_trash" if direct_to_trash else "applied"
        if allowed_categories == frozenset():
            quarantine_summary = {
                "selected": 0,
                "outcomes": {},
                "applied": 0,
                "automatic": True,
                "destination": destination,
                "label": QUARANTINE_LABEL_NAME if destination == "quarantine" else None,
                "leaves_messages_in_inbox": destination == "quarantine",
                "permanent_delete_available": False,
                "trash_emptying_available": False,
            }
        else:
            mutation_token = GoogleAccessTokenProvider(
                account_id,
                store=keychain,
                scope=GMAIL_MODIFY_SCOPE,
            )
            if direct_to_trash:
                trash_executor = GmailDirectTrashExecutor(mutation_token)
                apply_message = trash_executor.apply
            else:
                quarantine_executor = GmailLabelQuarantineExecutor(mutation_token)
                apply_message = quarantine_executor.apply_label_quarantine
            quarantine_summary = _apply_shadow_quarantine_results(
                results,
                preferences,
                account_id,
                policy.provider,
                scan_profile,
                now,
                apply_message,
                destination,
                success_outcome,
                allowed_categories=allowed_categories,
            )
            remaining = limit - int(quarantine_summary["selected"])
            if remaining > 0:
                # Recupera proposte pendenti senza rileggere oggetto o corpo.
                pending_candidates = prepare_automatic_quarantine_candidates(
                    policy,
                    mailbox,
                    preferences,
                    now,
                    remaining,
                    1000,
                    scan_profile,
                    allowed_categories=allowed_categories,
                    include_verified_obsolescence=(
                        obsolescence_proof_enabled and not direct_to_trash
                    ),
                    allow_disabled_threat_assessment=(
                        not threat_protection_enabled
                    ),
                )
                recovered = _apply_shadow_quarantine_candidates(
                    pending_candidates,
                    preferences,
                    account_id,
                    policy.provider,
                    scan_profile,
                    now,
                    apply_message,
                    success_outcome,
                )
                quarantine_summary["selected"] += recovered["selected"]
                quarantine_summary["applied"] += recovered["applied"]
                quarantine_summary["outcomes"] = dict(
                    sorted(
                        (
                            Counter(quarantine_summary["outcomes"])
                            + Counter(recovered["outcomes"])
                        ).items()
                    )
                )
    else:
        quarantine_summary = {
            "selected": 0,
            "outcomes": {},
            "applied": 0,
            "automatic": False,
            "destination": "trash" if direct_to_trash else "quarantine",
        }
    run_summary = summarize_dry_run([result.as_dict() for result in results])
    return {
        "type": "shadow_run_summary",
        "scan_profile": scan_profile,
        "newly_processed": len(results),
        "run_categories": run_summary["categories"],
        "run_content_assessments": run_summary["content_assessments"],
        "run_suggested_actions": run_summary["suggested_actions"],
        "ledger": preferences.shadow_scan_summary(account_id, scan_profile),
        "behavior_feedback": behavior_feedback,
        "behavior_ledger": preferences.behavior_event_summary(account_id),
        "temporal_drift": temporal_drift.as_dict(),
        "lumegraph": lumegraph,
        "proof_of_obsolescence": proof_of_obsolescence,
        "threat_protection": threat_protection,
        "threat_marker": threat_marker_summary,
        "modules": {
            "threat_protection": threat_protection_enabled,
            "lumegraph": lumegraph_enabled,
            "obsolescence_proof": obsolescence_proof_enabled,
        },
        "automatic_quarantine": quarantine_summary,
        "safety_governor": {
            **governor_gate.as_dict(),
            "blocked_current_batch": blocked_by_governor,
            "authorized_direct_trash_candidates_current_batch": (
                governor_authorized_direct_trash_candidates
            ),
        },
        "read_bodies": bool(results),
        "stored_plaintext": False,
        "changes_mailbox": (
            quarantine_summary["applied"] > 0
            or int(threat_marker_summary["applied"]) > 0
        ),
    }


def _apply_shadow_quarantine_results(
    results: list[DryRunResult],
    preferences: PreferenceStore,
    account_id: str,
    provider: ProviderKind,
    scan_profile: str,
    now: datetime,
    apply_message: Callable[[str, bool], Any],
    destination: str = "quarantine",
    success_outcome: str = "applied",
    allowed_categories: frozenset[str] | None = None,
) -> dict[str, Any]:
    """Applica la destinazione scelta alle sole proposte sicure del lotto."""

    if destination not in {"quarantine", "trash"}:
        raise ValueError("destinazione automatica non valida")

    outcomes: Counter[str] = Counter()
    selected = 0
    for result in results:
        if result.decision.action is not PolicyAction.QUARANTINE:
            continue
        if (
            allowed_categories is not None
            and result.classification.category.value not in allowed_categories
        ):
            continue
        message_id = result.message.message_id
        if preferences.threat_protects_message_id(
            account_id,
            provider,
            message_id,
            scan_profile,
        ):
            continue
        if preferences.has_quarantine_pilot_execution_id(
            account_id, provider, message_id, scan_profile
        ):
            continue
        # Una correzione esplicita dell'utente prevale sempre sul modello.
        answer = preferences.quiz_answer_for_message_id(
            account_id, provider, message_id
        )
        if answer in {"keep", "unsure"}:
            continue
        selected += 1
        applied = apply_message(message_id, result.message.unread)
        outcomes[applied.outcome.value] += 1
        preferences.record_quarantine_pilot_execution(
            account_id,
            provider,
            message_id,
            scan_profile,
            now,
            applied.outcome.value,
        )
    return {
        "selected": selected,
        "outcomes": dict(sorted(outcomes.items())),
        "applied": outcomes.get(success_outcome, 0),
        "automatic": True,
        "destination": destination,
        "label": QUARANTINE_LABEL_NAME if destination == "quarantine" else None,
        "leaves_messages_in_inbox": destination == "quarantine",
        "permanent_delete_available": False,
        "trash_emptying_available": False,
    }


def _apply_shadow_quarantine_candidates(
    candidates: list[InboxMutationCandidate],
    preferences: PreferenceStore,
    account_id: str,
    provider: ProviderKind,
    scan_profile: str,
    now: datetime,
    apply_message: Callable[[str, bool], Any],
    success_outcome: str = "applied",
) -> dict[str, Any]:
    outcomes: Counter[str] = Counter()
    safe_candidates = [
        candidate
        for candidate in candidates
        if not preferences.threat_protects_message_id(
            account_id,
            provider,
            candidate.message_id,
            scan_profile,
        )
        and preferences.quiz_answer_for_message_id(
            account_id, provider, candidate.message_id
        ) not in {"keep", "unsure"}
        and not preferences.has_quarantine_pilot_execution_id(
            account_id, provider, candidate.message_id, scan_profile
        )
    ]
    selected = 0
    for candidate in safe_candidates:
        message_id = candidate.message_id
        # Re-read the user's correction at the last local boundary before the
        # provider call; a stale recovered list is never sufficient authority.
        if preferences.quiz_answer_for_message_id(
            account_id, provider, message_id
        ) in {"keep", "unsure"}:
            continue
        selected += 1
        applied = apply_message(message_id, candidate.expected_unread)
        outcomes[applied.outcome.value] += 1
        preferences.record_quarantine_pilot_execution(
            account_id,
            provider,
            message_id,
            scan_profile,
            now,
            applied.outcome.value,
        )
    return {
        "selected": selected,
        "outcomes": dict(sorted(outcomes.items())),
        "applied": outcomes.get(success_outcome, 0),
    }


def yahoo_shadow_run(
    config_path: Path,
    account_id: str,
    backend: str,
    ollama_model: str,
    now: datetime,
    limit: int,
    search_limit: int,
    state_db: Path,
    secret_store: SecretStore | None = None,
    apply_quarantine: bool = False,
    direct_to_trash: bool = False,
    policy_override: AccountPolicy | None = None,
    oldest_first: bool = False,
    progress: Callable[[int, int], None] | None = None,
    phase: Callable[[str], None] | None = None,
    governor_enforced: bool = False,
    threat_protection_enabled: bool = True,
    threat_semantic_mode: ThreatSemanticMode | str = ThreatSemanticMode.TARGETED_SEMANTIC,
    lumegraph_enabled: bool = True,
    obsolescence_proof_enabled: bool = True,
) -> dict[str, Any]:
    policy = _resolved_policy(
        config_path, account_id, ProviderKind.YAHOO, policy_override
    )
    keychain = secret_store or SystemCredentialStore()
    preferences = PreferenceStore(
        state_db,
        load_or_create_hmac_key(keychain, account_id, state_db),
        account_id,
    )
    if direct_to_trash:
        require_direct_trash_authority(
            backend,
            ollama_model,
            preferences.quiz_answer_counts(account_id),
        )
    mailbox = YahooReadOnlyMailbox.from_secret_store(account_id, keychain)
    behavior_feedback = _collect_yahoo_restored_feedback(
        mailbox,
        preferences,
        policy,
        now,
    )
    selected_profile = profile_for_backend(backend, ollama_model)
    scan_profile = (
        scan_profile_for_model(selected_profile)
        if selected_profile is not None
        else "heuristic-policy-v2"
    )
    if threat_protection_enabled:
        preferences.reset_stale_threat_assessments(
            account_id,
            scan_profile,
            threat_semantic_mode,
        )
    classifier, local_backend = _build_classifier(backend, ollama_model)
    pending_candidates: list[InboxMutationCandidate] = []
    marker_ids: list[str] = []
    blocked_by_governor = 0
    try:
        results = run_shadow_scan(
            policy,
            mailbox,
            classifier,
            now,
            limit,
            search_limit,
            preferences,
            scan_profile,
            oldest_first=oldest_first,
            progress=progress,
            defer_completion=True,
        )
        if threat_protection_enabled:
            if phase is not None:
                phase("Checking phishing and scam signals locally…")
            results, threat_protection = _apply_threat_protection(
                results,
                local_backend,
                preferences,
                account_id,
                scan_profile,
                now,
                threat_semantic_mode,
            )
        else:
            threat_protection = _disabled_module_summary(
                THREAT_CONSENSUS_ENGINE_VERSION
            )
            preferences.record_disabled_threat_assessment_batch(
                (result.message for result in results),
                scan_profile,
                now,
            )
        if lumegraph_enabled:
            if phase is not None:
                phase("Building LumeGraph closure evidence locally…")
            marker_ids = _visible_threat_marker_ids(results)
            lumegraph = _build_lumegraph_shadow(
                results,
                local_backend,
                preferences,
                account_id,
                scan_profile,
                now,
                policy.read_one_time_code_age_days,
            )
        else:
            marker_ids = _visible_threat_marker_ids(results) if threat_protection_enabled else []
            lumegraph = _disabled_module_summary("lumegraph-v2")
        if obsolescence_proof_enabled:
            if phase is not None:
                phase("Applying Proof of Obsolescence checks…")
            results, proof_of_obsolescence = _apply_obsolescence_proofs(
                results,
                preferences,
                account_id,
                policy.provider,
                scan_profile,
                direct_to_trash=direct_to_trash,
            )
        else:
            proof_of_obsolescence = _disabled_module_summary("proof-of-obsolescence-v1")
        preferences.mark_shadow_batch_complete(
            (
                result.message
                for result in results
                if "local_model_fallback" not in result.classification.reason_codes
            ),
            scan_profile,
            policy_safety_fingerprint(policy),
        )
        governor_report = evaluate_safety_governor(
            account_id,
            scan_profile,
            preferences.shadow_quarantine_evidence_by_category(
                account_id,
                scan_profile,
            ),
        )
        temporal_drift = _local_temporal_drift(
            preferences,
            account_id,
            scan_profile,
            now,
        )
        governor_gate = operational_quarantine_gate(
            governor_report,
            enforced=governor_enforced,
            protective_drift_families=temporal_drift.restricted_families,
        )
        if governor_gate.enforced and not direct_to_trash:
            allowed_categories = frozenset(
                category.value
                for category in EmailCategory
                if category.value not in governor_gate.blocked_families
            )
        else:
            allowed_categories = None
        if apply_quarantine:
            for result in results:
                message_id = result.message.message_id
                if result.decision.action is not PolicyAction.QUARANTINE:
                    continue
                if preferences.threat_protects_message_id(
                    account_id,
                    policy.provider,
                    message_id,
                    scan_profile,
                ):
                    continue
                governor_permits = (
                    True
                    if direct_to_trash
                    else governor_gate.permits(result.classification.category.value)
                )
                if not governor_permits:
                    blocked_by_governor += 1
                    continue
                if preferences.has_quarantine_pilot_execution_id(
                    account_id, policy.provider, message_id, scan_profile
                ):
                    continue
                if preferences.quiz_answer_for_message_id(
                    account_id, policy.provider, message_id
                ) in {"keep", "unsure"}:
                    continue
                pending_candidates.append(
                    InboxMutationCandidate(
                        message_id,
                        result.message.unread,
                    )
                )
            remaining = limit - len(pending_candidates)
            if remaining > 0:
                recovered = prepare_automatic_quarantine_candidates(
                    policy,
                    mailbox,
                    preferences,
                    now,
                    remaining,
                    1000,
                    scan_profile,
                    allowed_categories=allowed_categories,
                    include_verified_obsolescence=(
                        obsolescence_proof_enabled and not direct_to_trash
                    ),
                    allow_disabled_threat_assessment=(
                        not threat_protection_enabled
                    ),
                )
                known_ids = {
                    candidate.message_id for candidate in pending_candidates
                }
                for candidate in recovered:
                    if candidate.message_id in known_ids:
                        continue
                    pending_candidates.append(candidate)
                    known_ids.add(candidate.message_id)
                pending_candidates = pending_candidates[:limit]
    finally:
        _unload_local_backend(local_backend)
        mailbox.close()

    if phase is not None:
        phase("Applying permitted mailbox actions…")
    outcomes: Counter[str] = Counter()
    threat_marker_summary: dict[str, object] = {
        "selected": len(marker_ids) if apply_quarantine else 0,
        "applied": 0,
        "visible": 0,
        "outcomes": {},
        "automatic": apply_quarantine,
        "kind": "yahoo_star",
        "flag": "\\Flagged",
        "leaves_messages_in_inbox": True,
        "authorizes_cleanup": False,
        "stored_plaintext": False,
    }
    if apply_quarantine and marker_ids:
        try:
            marker_credentials = load_yahoo_credentials(keychain, account_id)
            marker_executor = YahooThreatMarkerExecutor(marker_credentials)
        except Exception:  # noqa: BLE001 - marker must not block ordinary filtering
            threat_marker_summary.update(
                {
                    "selected": len(marker_ids),
                    "applied": 0,
                    "visible": 0,
                    "outcomes": {"failed": len(marker_ids)},
                }
            )
            for message_id in marker_ids:
                preferences.record_threat_marker_execution(
                    account_id,
                    policy.provider,
                    message_id,
                    scan_profile,
                    now,
                    "yahoo_star",
                    "failed",
                )
        else:
            try:
                threat_marker_summary.update(
                    _apply_visible_threat_markers(
                        marker_ids,
                        marker_executor.apply,
                        lambda message_id, outcome: preferences.record_threat_marker_execution(
                            account_id,
                            policy.provider,
                            message_id,
                            scan_profile,
                            now,
                            "yahoo_star",
                            outcome,
                        ),
                    )
                )
            finally:
                marker_executor.close()
    threat_marker_summary["ledger"] = preferences.threat_marker_summary(
        account_id, scan_profile
    )
    if apply_quarantine and pending_candidates:
        credentials = load_yahoo_credentials(keychain, account_id)
        if direct_to_trash:
            executor = YahooDirectTrashExecutor(credentials)
            apply_message = executor.apply
            success_outcome = "moved_to_trash"
        else:
            executor = YahooQuarantineExecutor(credentials)
            apply_message = executor.apply_quarantine
            success_outcome = "applied"
        try:
            for candidate in pending_candidates:
                message_id = candidate.message_id
                if preferences.quiz_answer_for_message_id(
                    account_id, policy.provider, message_id
                ) in {"keep", "unsure"}:
                    continue
                if preferences.threat_protects_message_id(
                    account_id,
                    policy.provider,
                    message_id,
                    scan_profile,
                ):
                    continue
                if preferences.has_quarantine_pilot_execution_id(
                    account_id,
                    policy.provider,
                    message_id,
                    scan_profile,
                ):
                    continue
                result = apply_message(message_id, candidate.expected_unread)
                outcomes[result.outcome.value] += 1
                preferences.record_quarantine_pilot_execution(
                    account_id,
                    policy.provider,
                    message_id,
                    scan_profile,
                    now,
                    result.outcome.value,
                )
                # Yahoo MOVE returns a UIDPLUS COPYUID mapping when the
                # server supports it.  Keep that destination-only pointer so
                # the review action can read the reversible folder after the
                # message leaves Inbox, without persisting plaintext or
                # credentials.  Direct Trash has no such review path.
                destination_uid_validity = getattr(
                    result, "destination_uid_validity", None
                )
                destination_uid = getattr(result, "destination_uid", None)
                if (
                    not direct_to_trash
                    and result.outcome.value == "applied"
                    and isinstance(destination_uid_validity, str)
                    and isinstance(destination_uid, str)
                ):
                    preferences.record_quarantine_location(
                        account_id,
                        policy.provider,
                        message_id,
                        scan_profile,
                        YAHOO_QUARANTINE_FOLDER,
                        destination_uid_validity,
                        destination_uid,
                        now,
                    )
        finally:
            executor.close()

    run_summary = summarize_dry_run([result.as_dict() for result in results])
    destination = "trash" if direct_to_trash else "quarantine"
    success_outcome = "moved_to_trash" if direct_to_trash else "applied"
    applied = outcomes.get(success_outcome, 0)
    governor_authorized_direct_trash_candidates = sum(
        1
        for result in results
        if direct_to_trash
        and governor_gate.enforced
        and result.decision.action is PolicyAction.QUARANTINE
        and governor_gate.permits_direct_trash(
            result.classification.category.value
        )
    )
    return {
        "type": "shadow_run_summary",
        "provider": "yahoo",
        "scan_profile": scan_profile,
        "newly_processed": len(results),
        "run_categories": run_summary["categories"],
        "run_content_assessments": run_summary["content_assessments"],
        "run_suggested_actions": run_summary["suggested_actions"],
        "ledger": preferences.shadow_scan_summary(account_id, scan_profile),
        "behavior_feedback": behavior_feedback,
        "behavior_ledger": preferences.behavior_event_summary(account_id),
        "temporal_drift": temporal_drift.as_dict(),
        "lumegraph": lumegraph,
        "proof_of_obsolescence": proof_of_obsolescence,
        "threat_protection": threat_protection,
        "threat_marker": threat_marker_summary,
        "modules": {
            "threat_protection": threat_protection_enabled,
            "lumegraph": lumegraph_enabled,
            "obsolescence_proof": obsolescence_proof_enabled,
        },
        "automatic_quarantine": {
            "selected": len(pending_candidates),
            "applied": applied,
            "outcomes": dict(sorted(outcomes.items())),
            "automatic": apply_quarantine,
            "destination": destination,
            "folder": (
                YAHOO_TRASH_FOLDER
                if destination == "trash"
                else YAHOO_QUARANTINE_FOLDER
            ),
            "leaves_messages_in_inbox": False,
            "permanent_delete_available": False,
            "trash_emptying_available": False,
        },
        "safety_governor": {
            **governor_gate.as_dict(),
            "blocked_current_batch": blocked_by_governor,
            "authorized_direct_trash_candidates_current_batch": (
                governor_authorized_direct_trash_candidates
            ),
        },
        "read_bodies": bool(results),
        "stored_plaintext": False,
        "changes_mailbox": (
            applied > 0 or int(threat_marker_summary["applied"]) > 0
        ),
    }


def _collect_yahoo_restored_feedback(
    mailbox: YahooReadOnlyMailbox,
    preferences: PreferenceStore,
    policy: AccountPolicy,
    now: datetime,
    limit: int = 500,
) -> dict[str, Any]:
    """Reconcile Inbox restores via UID and HMAC Message-ID; never read bodies."""

    if now.tzinfo is None:
        raise ValueError("now deve includere il fuso orario")
    previous = preferences.yahoo_uid_cursor(policy.account_id)
    try:
        if previous is None:
            uid_validity, latest_uid = mailbox.current_inbox_uid_cursor()
            preferences.set_yahoo_uid_cursor(
                policy.account_id,
                uid_validity,
                latest_uid,
                now,
            )
            return {
                "status": "initialized",
                "new_signals": {},
                "read_bodies": False,
            }

        uid_validity, last_uid = previous
        if uid_validity != mailbox.transport.uid_validity:
            current_validity, latest_uid = mailbox.current_inbox_uid_cursor()
            preferences.set_yahoo_uid_cursor(
                policy.account_id,
                current_validity,
                latest_uid,
                now,
            )
            return {
                "status": "uidvalidity_reset_without_inference",
                "new_signals": {},
                "read_bodies": False,
            }

        sync = mailbox.inbox_identities_after(uid_validity, last_uid, limit)
        restored = sum(
            preferences.record_restored_event_for_provider_identity(
                policy.account_id,
                policy.provider,
                identity,
                now,
            )
            for identity in sync.identities
        )
        preferences.set_yahoo_uid_cursor(
            policy.account_id,
            sync.uid_validity,
            sync.latest_processed_uid,
            now,
        )
        return {
            "status": "updated_more_pending" if sync.has_more else "updated",
            "new_signals": (
                {FeedbackSignal.RESTORED.value: restored} if restored else {}
            ),
            "read_bodies": False,
        }
    except YahooImapError:
        # Passive feedback must never make an ordinary scan unavailable.
        return {
            "status": "unavailable_without_inference",
            "new_signals": {},
            "read_bodies": False,
        }


def _collect_gmail_behavior_feedback(
    mailbox: GmailReadOnlyMailbox,
    preferences: PreferenceStore,
    policy: AccountPolicy,
    now: datetime,
) -> dict[str, Any]:
    """Importa solo variazioni label per messaggi già noti, mai corpi o testo."""

    if now.tzinfo is None:
        raise ValueError("now deve includere il fuso orario")
    current_history_id = mailbox.current_history_id()
    previous_history_id = preferences.gmail_history_cursor(policy.account_id)
    if previous_history_id is None:
        preferences.set_gmail_history_cursor(
            policy.account_id,
            current_history_id,
            now,
        )
        return {
            "status": "initialized",
            "new_signals": {},
            "read_bodies": False,
        }
    try:
        behavior_sync = getattr(mailbox, "behavior_label_changes_since", None)
        sync = (
            behavior_sync(previous_history_id)
            if callable(behavior_sync)
            else mailbox.inbox_label_changes_since(previous_history_id)
        )
    except GmailHistoryExpired:
        preferences.set_gmail_history_cursor(
            policy.account_id,
            current_history_id,
            now,
        )
        return {
            "status": "history_reset_without_inference",
            "new_signals": {},
            "read_bodies": False,
        }

    signals: Counter[str] = Counter()
    for change in sync.changes:
        candidates: list[FeedbackSignal] = []
        if "UNREAD" in change.removed_labels:
            candidates.append(FeedbackSignal.OPENED)
        if "STARRED" in change.added_labels:
            candidates.append(FeedbackSignal.STARRED)
        if "IMPORTANT" in change.added_labels:
            candidates.append(FeedbackSignal.MARKED_IMPORTANT)
        quarantine_label_removed = any(
            label.startswith("Label_") for label in change.removed_labels
        )
        restored = "INBOX" in change.added_labels or (
            quarantine_label_removed and "TRASH" not in change.added_labels
        )
        if restored and preferences.record_restored_event_for_message_id(
            policy.account_id,
            policy.provider,
            change.message_id,
            now,
        ):
            signals[FeedbackSignal.RESTORED.value] += 1
        for signal in candidates:
            if preferences.record_behavior_event_for_message_id(
                policy.account_id,
                policy.provider,
                change.message_id,
                signal,
                now,
            ):
                signals[signal.value] += 1
    preferences.set_gmail_history_cursor(
        policy.account_id,
        sync.latest_history_id,
        now,
    )
    return {
        "status": "updated",
        "new_signals": dict(sorted(signals.items())),
        "read_bodies": False,
    }


def _quiz_card(candidate, position: int, total: int) -> str:  # noqa: ANN001
    message = candidate.message
    preview = normalize_plain_text(message.body_text, max_chars=900) or "(corpo vuoto)"
    sender = normalize_plain_text(message.sender, max_chars=320) or "(mittente assente)"
    subject = normalize_plain_text(message.subject, max_chars=500) or "(senza oggetto)"
    state = "non letta" if message.unread else "letta"
    return (
        f"\n--- Email {position}/{total} ---\n"
        f"Da: {sender}\n"
        f"Oggetto: {subject}\n"
        f"Data: {message.received_at.astimezone().isoformat(timespec='minutes')} ({state})\n"
        f"Classificazione proposta: {candidate.classification.category.value} "
        f"({candidate.classification.confidence:.0%})\n"
        f"Anteprima locale:\n{preview}\n"
    )


def gmail_calibration_quiz(
    config_path: Path,
    account_id: str,
    backend: str,
    ollama_model: str,
    quiz_limit: int,
    sample_limit: int,
    state_db: Path,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
    secret_store: SecretStore | None = None,
    mailbox: ReadOnlyMailbox | None = None,
    classifier: Classifier | None = None,
) -> dict[str, int]:
    policy = _require_gmail_policy(config_path, account_id)
    keychain = secret_store or SystemCredentialStore()
    preference_store = PreferenceStore(
        state_db,
        load_or_create_hmac_key(keychain, account_id, state_db),
        account_id,
    )
    actual_mailbox = mailbox or GmailReadOnlyMailbox(
        account_id,
        GoogleAccessTokenProvider(account_id, store=keychain),
    )
    local_backend: OllamaClassifier | MlxWorkerClassifier | None = None
    if classifier is None:
        classifier, local_backend = _build_classifier(backend, ollama_model)
    try:
        candidates = prepare_quiz(
            policy,
            actual_mailbox,
            classifier,
            preference_store,
            quiz_limit,
            sample_limit,
        )
        quiz = CalibrationQuiz(preference_store)
        counts = {"keep": 0, "dont_keep": 0, "unsure": 0, "presented": 0}
        choices = {
            "t": QuizAnswer.KEEP,
            "tieni": QuizAnswer.KEEP,
            "n": QuizAnswer.DONT_KEEP,
            "non tenere": QuizAnswer.DONT_KEEP,
            "?": QuizAnswer.UNSURE,
            "s": QuizAnswer.UNSURE,
            "non so": QuizAnswer.UNSURE,
        }
        for position, candidate in enumerate(candidates, start=1):
            output_fn(_quiz_card(candidate, position, len(candidates)))
            while True:
                raw = input_fn("Scelta [t]ieni / [n]on tenere / [?] non so / [q] esci: ")
                normalized = raw.strip().casefold()
                if normalized == "q":
                    return counts
                answer = choices.get(normalized)
                if answer is not None:
                    break
                output_fn("Scelta non riconosciuta.")
            quiz.answer(candidate, answer)
            counts[answer.value] += 1
            counts["presented"] += 1
        return counts
    finally:
        _unload_local_backend(local_backend)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="inboxlume",
        description=(
            "Valuta email localmente; ogni azione reale usa un comando, "
            "un token e un flag separati."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    evaluate = subparsers.add_parser("evaluate", help="classifica un file JSONL locale")
    evaluate.add_argument("--config", type=Path, required=True)
    evaluate.add_argument("--account", required=True)
    evaluate.add_argument("--input", type=Path, required=True)
    evaluate.add_argument(
        "--backend",
        choices=LOCAL_BACKEND_CHOICES,
        default="heuristic",
    )
    evaluate.add_argument("--ollama-model", default="qwen3-vl:8b")
    evaluate.add_argument(
        "--now",
        help="istante ISO-8601 per test riproducibili; predefinito: adesso UTC",
    )

    authorize = subparsers.add_parser(
        "gmail-authorize",
        help="autorizza Gmail read-only e conserva il refresh token nel Portachiavi",
    )
    authorize.add_argument("--config", type=Path, required=True)
    authorize.add_argument("--account", required=True)
    authorize.add_argument("--client-json", type=Path, required=True)
    authorize.add_argument(
        "--no-browser",
        action="store_true",
        help="mostra l'URL invece di aprire il browser predefinito",
    )
    authorize.add_argument("--timeout", type=float, default=300)

    authorize_quarantine = subparsers.add_parser(
        "gmail-authorize-quarantine",
        help=(
            "salva un token separato gmail.modify usato soltanto "
            "dall'esecutore di etichetta"
        ),
    )
    authorize_quarantine.add_argument("--config", type=Path, required=True)
    authorize_quarantine.add_argument("--account", required=True)
    authorize_quarantine.add_argument(
        "--no-browser",
        action="store_true",
        help="mostra l'URL invece di aprire il browser predefinito",
    )
    authorize_quarantine.add_argument("--timeout", type=float, default=300)

    probe = subparsers.add_parser(
        "gmail-probe",
        help="verifica Gmail elencando al massimo un ID Inbox, senza leggere il messaggio",
    )
    probe.add_argument("--config", type=Path, required=True)
    probe.add_argument("--account", required=True)

    count = subparsers.add_parser(
        "gmail-count",
        help="stima i candidati Inbox senza leggere alcun corpo",
    )
    count.add_argument("--config", type=Path, required=True)
    count.add_argument("--account", required=True)
    count.add_argument(
        "--now",
        help="istante ISO-8601; predefinito: adesso UTC",
    )

    dry_run = subparsers.add_parser(
        "gmail-dry-run",
        help="legge vecchi non letti Inbox e stampa solo proposte non operative",
    )
    dry_run.add_argument("--config", type=Path, required=True)
    dry_run.add_argument("--account", required=True)
    dry_run.add_argument(
        "--backend",
        choices=LOCAL_BACKEND_CHOICES,
        default="heuristic",
    )
    dry_run.add_argument("--ollama-model", default="qwen3-vl:8b")
    dry_run.add_argument("--limit", type=int, default=10)
    dry_run.add_argument(
        "--now",
        help="istante ISO-8601; predefinito: adesso UTC",
    )
    dry_run.add_argument(
        "--confirm-read-bodies",
        action="store_true",
        help="conferma esplicita che i corpi Inbox saranno letti localmente",
    )

    model_eval = subparsers.add_parser(
        "gmail-model-eval",
        help="confronta modelli locali sulle sole email già valutate nel quiz",
    )
    model_eval.add_argument("--config", type=Path, required=True)
    model_eval.add_argument("--account", required=True)
    model_eval.add_argument(
        "--models",
        nargs="+",
        choices=MODEL_NAMES,
        default=list(MODEL_NAMES),
    )
    model_eval.add_argument("--search-limit", type=int, default=500)
    model_eval.add_argument("--state-db", type=Path, default=DEFAULT_PREFERENCE_DB)
    model_eval.add_argument(
        "--confirm-read-bodies",
        action="store_true",
        help="conferma che le email già etichettate saranno rilette solo in RAM",
    )

    shadow = subparsers.add_parser(
        "gmail-shadow-run",
        help="scansiona nuovi candidati e salva soltanto un registro HMAC locale",
    )
    shadow.add_argument("--config", type=Path, required=True)
    shadow.add_argument("--account", required=True)
    shadow.add_argument(
        "--backend",
        choices=LOCAL_BACKEND_CHOICES,
        default="gemma26",
    )
    shadow.add_argument("--ollama-model", default="qwen3-vl:8b")
    shadow.add_argument("--limit", type=int, default=50)
    shadow.add_argument("--search-limit", type=int, default=500)
    shadow.add_argument("--state-db", type=Path, default=DEFAULT_PREFERENCE_DB)
    shadow.add_argument(
        "--confirm-read-bodies",
        action="store_true",
        help="conferma che i nuovi candidati saranno letti localmente",
    )
    shadow.add_argument(
        "--apply-shadow-labels",
        action="store_true",
        help=(
            "applica automaticamente l'etichetta Quarantena alle sole proposte "
            "del lotto corrente, lasciandole nella Inbox"
        ),
    )
    shadow.add_argument(
        "--direct-to-trash",
        action="store_true",
        help=(
            "sposta le proposte direttamente nel Cestino invece di applicare "
            "l'etichetta Quarantena; non abilita delete o emptyTrash"
        ),
    )
    shadow.add_argument(
        "--enforce-safety-governor",
        action="store_true",
        help="applica il gate per account, modello e famiglia prima di ogni azione",
    )

    yahoo_authorize_parser = subparsers.add_parser(
        "yahoo-authorize",
        help="salva indirizzo e password per app Yahoo nel Portachiavi separato",
    )
    yahoo_authorize_parser.add_argument("--config", type=Path, required=True)
    yahoo_authorize_parser.add_argument("--account", required=True)

    yahoo_probe_parser = subparsers.add_parser(
        "yahoo-probe",
        help="verifica la sola Inbox Yahoo senza leggere alcun corpo",
    )
    yahoo_probe_parser.add_argument("--config", type=Path, required=True)
    yahoo_probe_parser.add_argument("--account", required=True)

    yahoo_shadow_parser = subparsers.add_parser(
        "yahoo-shadow-run",
        help="scansiona nuovi candidati Yahoo con stato e credenziali separati",
    )
    yahoo_shadow_parser.add_argument("--config", type=Path, required=True)
    yahoo_shadow_parser.add_argument("--account", required=True)
    yahoo_shadow_parser.add_argument(
        "--backend",
        choices=LOCAL_BACKEND_CHOICES,
        default="gemma26",
    )
    yahoo_shadow_parser.add_argument("--ollama-model", default="qwen3-vl:8b")
    yahoo_shadow_parser.add_argument("--limit", type=int, default=50)
    yahoo_shadow_parser.add_argument("--search-limit", type=int, default=0)
    yahoo_shadow_parser.add_argument(
        "--state-db", type=Path, default=DEFAULT_YAHOO_PREFERENCE_DB
    )
    yahoo_shadow_parser.add_argument("--confirm-read-bodies", action="store_true")
    yahoo_shadow_parser.add_argument(
        "--apply-shadow-quarantine",
        action="store_true",
        help=(
            "sposta automaticamente le proposte del lotto nella sola cartella "
            f"{YAHOO_QUARANTINE_FOLDER}"
        ),
    )
    yahoo_shadow_parser.add_argument(
        "--direct-to-trash",
        action="store_true",
        help=(
            "sposta le proposte direttamente nella cartella Yahoo Trash invece "
            f"di {YAHOO_QUARANTINE_FOLDER}; non usa EXPUNGE"
        ),
    )
    yahoo_shadow_parser.add_argument(
        "--enforce-safety-governor",
        action="store_true",
        help="applica il gate per account, modello e famiglia prima di ogni azione",
    )

    quarantine_pilot = subparsers.add_parser(
        "gmail-quarantine-pilot",
        help=(
            "applica solo l'etichetta pilot a email Inbox già proposte e "
            "confermate Non tenere"
        ),
    )
    quarantine_pilot.add_argument("--config", type=Path, required=True)
    quarantine_pilot.add_argument("--account", required=True)
    quarantine_pilot.add_argument("--limit", type=int, default=1)
    quarantine_pilot.add_argument("--search-limit", type=int, default=500)
    quarantine_pilot.add_argument(
        "--scan-profile",
        default="gemma26-policy-v2",
    )
    quarantine_pilot.add_argument(
        "--state-db",
        type=Path,
        default=DEFAULT_PREFERENCE_DB,
    )
    quarantine_pilot.add_argument(
        "--apply-verified-labels",
        action="store_true",
        help="conferma l'applicazione reale dell'etichetta, senza rimuovere INBOX",
    )

    finalize_quarantine = subparsers.add_parser(
        "gmail-finalize-quarantine",
        help=(
            "dopo 3 giorni sposta soltanto quarantene ancora valide in "
            "Cestino o Spam, senza eliminazione permanente"
        ),
    )
    finalize_quarantine.add_argument("--config", type=Path, required=True)
    finalize_quarantine.add_argument("--account", required=True)
    finalize_quarantine.add_argument("--limit", type=int, default=1)
    finalize_quarantine.add_argument("--search-limit", type=int, default=500)
    finalize_quarantine.add_argument(
        "--scan-profile",
        default="gemma26-policy-v2",
    )
    finalize_quarantine.add_argument(
        "--state-db",
        type=Path,
        default=DEFAULT_PREFERENCE_DB,
    )
    finalize_quarantine.add_argument(
        "--move-mature-quarantine",
        action="store_true",
        help=(
            "conferma lo spostamento reale delle sole quarantene mature; "
            "non abilita eliminazione permanente o svuotamento Cestino"
        ),
    )

    quiz = subparsers.add_parser(
        "gmail-quiz",
        help="quiz manuale locale su email Inbox reali; non modifica la casella",
    )
    quiz.add_argument("--config", type=Path, required=True)
    quiz.add_argument("--account", required=True)
    quiz.add_argument(
        "--backend",
        choices=LOCAL_BACKEND_CHOICES,
        default="heuristic",
    )
    quiz.add_argument("--ollama-model", default="qwen3-vl:8b")
    quiz.add_argument("--limit", type=int, default=12)
    quiz.add_argument("--sample-limit", type=int, default=60)
    quiz.add_argument("--state-db", type=Path, default=DEFAULT_PREFERENCE_DB)
    quiz.add_argument(
        "--confirm-read-bodies",
        action="store_true",
        help="conferma esplicita che i corpi Inbox saranno letti e mostrati localmente",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "evaluate":
        now = (
            datetime.fromisoformat(args.now.replace("Z", "+00:00"))
            if args.now
            else datetime.now(timezone.utc)
        )
        try:
            results = evaluate_jsonl(
                args.config,
                args.account,
                args.input,
                args.backend,
                args.ollama_model,
                now,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"errore: {exc}", file=sys.stderr)
            return 2
        for item in results:
            print(json.dumps(item, ensure_ascii=False, sort_keys=True))
        return 0
    if args.command == "gmail-authorize":
        if not 30 <= args.timeout <= 900:
            print("errore: --timeout deve essere tra 30 e 900 secondi", file=sys.stderr)
            return 2

        def open_url(url: str) -> None:
            if args.no_browser:
                print("Apri questo URL nel browser per autorizzare Gmail:")
                print(url)
                return
            if not webbrowser.open(url, new=1, autoraise=True):
                raise GoogleOAuthError(
                    "impossibile aprire il browser; riprova con --no-browser"
                )

        try:
            authorize_gmail(
                args.config,
                args.account,
                args.client_json,
                open_url,
                timeout_seconds=args.timeout,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"errore: {exc}", file=sys.stderr)
            return 2
        print(
            "Gmail autorizzato in sola lettura; credenziali salvate nel Portachiavi. "
            "Nessun messaggio è stato letto o modificato."
        )
        return 0
    if args.command == "yahoo-authorize":
        try:
            email_address = input("Indirizzo email Yahoo completo: ").strip()
            app_password = getpass.getpass("Password per app Yahoo: ")
            authorize_yahoo(
                args.config,
                args.account,
                email_address,
                app_password,
            )
        except (EOFError, KeyboardInterrupt):
            print("\nConfigurazione Yahoo annullata.", file=sys.stderr)
            return 130
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"errore: {exc}", file=sys.stderr)
            return 2
        print(
            "Credenziali Yahoo salvate nel Portachiavi separato. "
            "Nessuna connessione è stata aperta e nessuna email è stata modificata."
        )
        return 0
    if args.command == "yahoo-probe":
        try:
            summary = yahoo_probe(args.config, args.account)
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"errore: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
        return 0
    if args.command == "yahoo-shadow-run":
        if not args.confirm_read_bodies:
            print(
                "errore: occorre --confirm-read-bodies perché la scansione Yahoo "
                "legge i nuovi candidati soltanto sul Mac",
                file=sys.stderr,
            )
            return 2
        if args.direct_to_trash and not args.apply_shadow_quarantine:
            print(
                "errore: --direct-to-trash richiede --apply-shadow-quarantine",
                file=sys.stderr,
            )
            return 2
        try:
            if args.direct_to_trash:
                require_direct_trash_model(args.backend, args.ollama_model)
                require_direct_trash_authority(
                    args.backend,
                    args.ollama_model,
                    calibration_answer_counts(
                        args.state_db,
                        args.account,
                        SystemCredentialStore(),
                    ),
                )
            summary = yahoo_shadow_run(
                args.config,
                args.account,
                args.backend,
                args.ollama_model,
                datetime.now(timezone.utc),
                args.limit,
                args.search_limit,
                args.state_db,
                apply_quarantine=args.apply_shadow_quarantine,
                direct_to_trash=args.direct_to_trash,
                governor_enforced=args.enforce_safety_governor,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"errore: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
        return 0
    if args.command == "gmail-authorize-quarantine":
        if not 30 <= args.timeout <= 900:
            print("errore: --timeout deve essere tra 30 e 900 secondi", file=sys.stderr)
            return 2

        def open_quarantine_url(url: str) -> None:
            if args.no_browser:
                print("Apri questo URL nel browser per autorizzare la quarantena Gmail:")
                print(url)
                return
            if not webbrowser.open(url, new=1, autoraise=True):
                raise GoogleOAuthError(
                    "impossibile aprire il browser; riprova con --no-browser"
                )

        try:
            authorize_gmail_quarantine(
                args.config,
                args.account,
                open_quarantine_url,
                timeout_seconds=args.timeout,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"errore: {exc}", file=sys.stderr)
            return 2
        print(
            "Token gmail.modify separato salvato nel Portachiavi. "
            "Nessun messaggio è stato letto o modificato; l'esecutore locale "
            "ammette soltanto l'etichetta InboxLume/Quarantena."
        )
        return 0
    if args.command == "gmail-probe":
        try:
            has_message = probe_gmail(args.config, args.account)
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"errore: {exc}", file=sys.stderr)
            return 2
        state = "accessibile e non vuota" if has_message else "accessibile e vuota"
        print(
            f"Inbox Gmail {state}. Il test ha elencato al massimo un ID: "
            "nessun corpo è stato letto e nulla è stato modificato."
        )
        return 0
    if args.command == "gmail-count":
        try:
            now = (
                datetime.fromisoformat(args.now.replace("Z", "+00:00"))
                if args.now
                else datetime.now(timezone.utc)
            )
            (
                unread_estimate,
                otp_estimate,
                access_estimate,
                unread_age_days,
                otp_age_days,
                access_age_days,
            ) = count_gmail_candidates(args.config, args.account, now)
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"errore: {exc}", file=sys.stderr)
            return 2
        print(
            json.dumps(
                {
                    "type": "candidate_count",
                    "estimated": unread_estimate,
                    "estimated_old_unread": unread_estimate,
                    "estimated_read_otp_prefilter": otp_estimate,
                    "estimated_read_routine_access_prefilter": access_estimate,
                    "unread_age_days": unread_age_days,
                    "read_one_time_code_age_days": otp_age_days,
                    "read_routine_access_alert_age_days": access_age_days,
                    "read_bodies": False,
                    "changes_mailbox": False,
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 0
    if args.command == "gmail-dry-run":
        if not args.confirm_read_bodies:
            print(
                "errore: occorre --confirm-read-bodies perché questa prova legge "
                "il testo delle email Inbox sul Mac",
                file=sys.stderr,
            )
            return 2
        try:
            now = (
                datetime.fromisoformat(args.now.replace("Z", "+00:00"))
                if args.now
                else datetime.now(timezone.utc)
            )
            results = gmail_dry_run(
                args.config,
                args.account,
                args.backend,
                args.ollama_model,
                now,
                args.limit,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"errore: {exc}", file=sys.stderr)
            return 2
        for ordinal, item in enumerate(results, start=1):
            print(
                json.dumps(
                    _privacy_safe_provider_dry_run_event(item, ordinal),
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
        print(json.dumps(summarize_dry_run(results), ensure_ascii=False, sort_keys=True))
        return 0
    if args.command == "gmail-model-eval":
        if not args.confirm_read_bodies:
            print(
                "errore: occorre --confirm-read-bodies perché il confronto rilegge "
                "sul Mac le email già valutate",
                file=sys.stderr,
            )
            return 2
        try:
            now = datetime.now(timezone.utc)
            summary = gmail_model_evaluation(
                args.config,
                args.account,
                list(dict.fromkeys(args.models)),
                now,
                args.search_limit,
                args.state_db,
                progress=lambda name: print(
                    f"Valutazione locale {name}…",
                    file=sys.stderr,
                    flush=True,
                ),
            )
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"errore: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
        return 0
    if args.command == "gmail-shadow-run":
        if not args.confirm_read_bodies:
            print(
                "errore: occorre --confirm-read-bodies perché la scansione shadow "
                "legge i nuovi candidati sul Mac",
                file=sys.stderr,
            )
            return 2
        if args.direct_to_trash and not args.apply_shadow_labels:
            print(
                "errore: --direct-to-trash richiede --apply-shadow-labels",
                file=sys.stderr,
            )
            return 2
        try:
            if args.direct_to_trash:
                require_direct_trash_model(args.backend, args.ollama_model)
                require_direct_trash_authority(
                    args.backend,
                    args.ollama_model,
                    calibration_answer_counts(
                        args.state_db,
                        args.account,
                        SystemCredentialStore(),
                    ),
                )
            summary = gmail_shadow_run(
                args.config,
                args.account,
                args.backend,
                args.ollama_model,
                datetime.now(timezone.utc),
                args.limit,
                args.search_limit,
                args.state_db,
                apply_quarantine_labels=args.apply_shadow_labels,
                direct_to_trash=args.direct_to_trash,
                governor_enforced=args.enforce_safety_governor,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"errore: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
        return 0
    if args.command == "gmail-quarantine-pilot":
        if not args.apply_verified_labels:
            print(
                "errore: occorre --apply-verified-labels perché il pilot modifica "
                "davvero le etichette Gmail",
                file=sys.stderr,
            )
            return 2
        try:
            summary = gmail_quarantine_pilot(
                args.config,
                args.account,
                datetime.now(timezone.utc),
                args.limit,
                args.search_limit,
                args.scan_profile,
                args.state_db,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"errore: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
        return 0
    if args.command == "gmail-finalize-quarantine":
        if not args.move_mature_quarantine:
            print(
                "errore: occorre --move-mature-quarantine perché il comando "
                "sposta davvero le quarantene mature in Cestino o Spam",
                file=sys.stderr,
            )
            return 2
        try:
            summary = gmail_finalize_quarantine(
                args.config,
                args.account,
                datetime.now(timezone.utc),
                args.limit,
                args.search_limit,
                args.scan_profile,
                args.state_db,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"errore: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
        return 0
    if args.command == "gmail-quiz":
        if not args.confirm_read_bodies:
            print(
                "errore: occorre --confirm-read-bodies perché il quiz mostra "
                "email Inbox reali nel Terminale",
                file=sys.stderr,
            )
            return 2
        if not sys.stdin.isatty():
            print("errore: gmail-quiz richiede un Terminale interattivo", file=sys.stderr)
            return 2
        try:
            counts = gmail_calibration_quiz(
                args.config,
                args.account,
                args.backend,
                args.ollama_model,
                args.limit,
                args.sample_limit,
                args.state_db,
            )
        except KeyboardInterrupt:
            print("\nQuiz interrotto; le risposte già date restano salvate localmente.")
            return 130
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"errore: {exc}", file=sys.stderr)
            return 2
        print(
            "Quiz concluso: "
            f"{counts['presented']} risposte "
            f"({counts['keep']} tieni, {counts['dont_keep']} non tenere, "
            f"{counts['unsure']} non so). Nessuna email è stata modificata."
        )
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
