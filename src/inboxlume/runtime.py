from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from datetime import datetime, timedelta, timezone

from .config import AccountPolicy, load_policies, policy_safety_fingerprint
from .duration_estimator import (
    ScanDurationEstimate,
    ScanTimingSample,
    estimate_scan_duration,
    hardware_timing_key,
)
from .learning import PreferenceStore, load_or_create_hmac_key
from .local_models import HardwareProfile, scan_profile_for_model
from .models import ProviderKind
from .providers.contracts import ReadOnlyMailbox
from .providers.gmail import GmailReadOnlyMailbox
from .providers.google_oauth import SecretStore
from .providers.google_oauth import GoogleAccessTokenProvider
from .providers.yahoo import YahooReadOnlyMailbox
from .safety_governor import SafetyGovernorReport, evaluate_safety_governor
from .safety_backtest import (
    BACKTEST_ENGINE_VERSION,
    VersionedSafetyBacktestReport,
    evaluate_versioned_safety_backtest,
)
from .settings import AccountSettings
from .temporal_drift import (
    DEFAULT_HISTORICAL_DAYS,
    DEFAULT_RECENT_DAYS,
    TemporalDriftReport,
    evaluate_temporal_preference_drift,
)


LEGACY_ACCOUNT_DATABASES = {
    "gmail_personale": "preferences.sqlite3",
    "yahoo_personale": "yahoo_preferences.sqlite3",
}


def default_runtime_config_path(project_root: Path | None = None) -> Path:
    """Preferisce il file di sviluppo, con fallback alla policy inclusa nel pacchetto."""

    if project_root is not None:
        development = project_root / "config" / "accounts.example.json"
        if development.is_file():
            return development
    bundled = Path(__file__).with_name("default_policy.json")
    if not bundled.is_file():
        raise FileNotFoundError("policy predefinita InboxLume non disponibile")
    return bundled


def runtime_policy(
    config_path: Path,
    account_id: str,
    provider: ProviderKind,
    *,
    unread_age_days: int = 30,
    read_one_time_code_age_days: int = 7,
) -> AccountPolicy:
    """Clona una policy provider sicura per un account creato dalla GUI."""

    policies = load_policies(config_path)
    exact = policies.get(account_id)
    if exact is not None:
        if exact.provider is not provider:
            raise ValueError("provider account non coerente con la policy")
        template = exact
    else:
        template = next(
            (policy for policy in policies.values() if policy.provider is provider),
            None,
        )
        if template is None:
            raise ValueError(f"nessuna policy modello disponibile per {provider.value}")
    return replace(
        template,
        account_id=account_id,
        unread_age_days=unread_age_days,
        read_one_time_code_age_days=read_one_time_code_age_days,
    )


def state_database_path(
    settings_path: Path,
    project_root: Path,
    account: AccountSettings,
) -> Path:
    """Mantiene lo storico del prototipo e isola ogni nuovo account."""

    legacy_name = LEGACY_ACCOUNT_DATABASES.get(account.account_id)
    if legacy_name is not None:
        legacy = project_root / "data" / legacy_name
        if legacy.exists():
            return legacy
    return settings_path.parent / "accounts" / account.account_id / "preferences.sqlite3"


def calibration_answer_counts(
    state_db: Path,
    account_id: str,
    secret_store: SecretStore,
) -> dict[str, int]:
    state_db.parent.mkdir(parents=True, exist_ok=True)
    preferences = PreferenceStore(
        state_db,
        load_or_create_hmac_key(secret_store, account_id, state_db),
        account_id,
    )
    return preferences.quiz_answer_counts(account_id)


def local_lumegraph_summary(
    state_db: Path,
    account_id: str,
    secret_store: SecretStore,
    scan_profile: str,
) -> dict[str, object]:
    """Read only aggregate private-graph counts for the desktop status panel."""

    preferences = PreferenceStore(
        state_db,
        load_or_create_hmac_key(secret_store, account_id, state_db),
        account_id,
    )
    return preferences.lumegraph_summary(account_id, scan_profile)


def local_threat_assessment_summary(
    state_db: Path,
    account_id: str,
    secret_store: SecretStore,
    scan_profile: str,
) -> dict[str, object]:
    """Read aggregate protective-threat counts without reopening messages."""

    preferences = PreferenceStore(
        state_db,
        load_or_create_hmac_key(secret_store, account_id, state_db),
        account_id,
    )
    return preferences.threat_assessment_summary(account_id, scan_profile)


def local_obsolescence_proof_summary(
    state_db: Path,
    account_id: str,
    secret_store: SecretStore,
    scan_profile: str,
) -> dict[str, object]:
    """Read aggregate proof counts without exposing messages or graph relations."""

    preferences = PreferenceStore(
        state_db,
        load_or_create_hmac_key(secret_store, account_id, state_db),
        account_id,
    )
    return preferences.obsolescence_proof_summary(account_id, scan_profile)


def local_operational_status_summary(
    state_db: Path,
    account_id: str,
    secret_store: SecretStore,
    scan_profile: str,
) -> dict[str, object]:
    """Return the account-scoped aggregates used by the desktop dashboard.

    The dashboard deliberately reads the existing privacy-preserving ledgers:
    no message is reopened and no provider identifier or plaintext is exposed.
    Keeping the snapshot behind one runtime boundary also prevents the UI from
    presenting counts assembled from different account/model scopes.
    """

    preferences = PreferenceStore(
        state_db,
        load_or_create_hmac_key(secret_store, account_id, state_db),
        account_id,
    )
    governor_evidence = preferences.shadow_quarantine_evidence_by_category(
        account_id,
        scan_profile,
    )
    return {
        "scan": preferences.shadow_scan_summary(account_id, scan_profile),
        "quarantine": preferences.quarantine_pilot_summary(
            account_id,
            scan_profile,
        ),
        "threat": preferences.threat_assessment_summary(account_id, scan_profile),
        "lumegraph": preferences.lumegraph_summary(account_id, scan_profile),
        "proof": preferences.obsolescence_proof_summary(account_id, scan_profile),
        "governor": evaluate_safety_governor(
            account_id,
            scan_profile,
            governor_evidence,
        ),
    }


def local_safety_governor_report(
    state_db: Path,
    account_id: str,
    secret_store: SecretStore,
    scan_profile: str,
) -> SafetyGovernorReport:
    """Evaluate only aggregate, HMAC-linked local evidence for one account."""
    preferences = PreferenceStore(
        state_db,
        load_or_create_hmac_key(secret_store, account_id, state_db),
        account_id,
    )
    evidence = preferences.shadow_quarantine_evidence_by_category(
        account_id,
        scan_profile,
    )
    return evaluate_safety_governor(account_id, scan_profile, evidence)


def local_temporal_drift_report(
    state_db: Path,
    account_id: str,
    secret_store: SecretStore,
    scan_profile: str,
    *,
    created_at: datetime | None = None,
) -> TemporalDriftReport:
    """Evaluate timestamped, HMAC-linked preference evidence only."""

    now = created_at or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("created_at must include a timezone")
    preferences = PreferenceStore(
        state_db,
        load_or_create_hmac_key(secret_store, account_id, state_db),
        account_id,
    )
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


def local_versioned_safety_backtest(
    state_db: Path,
    account_id: str,
    secret_store: SecretStore,
    scan_profile: str,
    *,
    created_at: datetime | None = None,
) -> VersionedSafetyBacktestReport:
    """Backtest existing HMAC-linked decisions without mailbox or model access."""

    now = created_at or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("created_at must include a timezone")
    preferences = PreferenceStore(
        state_db,
        load_or_create_hmac_key(secret_store, account_id, state_db),
        account_id,
    )
    evidence = preferences.shadow_quarantine_evidence_by_category(
        account_id,
        scan_profile,
    )
    previous = preferences.latest_safety_backtest_evidence(
        account_id,
        scan_profile,
        BACKTEST_ENGINE_VERSION,
    )
    report = evaluate_versioned_safety_backtest(
        account_id,
        scan_profile,
        evidence,
        now,
        previous_evidence_by_family=previous[1] if previous else None,
        previous_evidence_fingerprint=previous[0] if previous else None,
    )
    recorded = False
    if report.safety_report.overall.proposals:
        recorded = preferences.record_safety_backtest_evidence(
            account_id,
            scan_profile,
            report.engine_version,
            report.evidence_fingerprint,
            now,
            evidence,
        )
    return report.with_snapshot_recorded(recorded)


def local_scan_duration_estimate(
    state_db: Path,
    config_path: Path,
    account: AccountSettings,
    secret_store: SecretStore,
    hardware: HardwareProfile,
    *,
    created_at: datetime | None = None,
    mailbox: ReadOnlyMailbox | None = None,
) -> ScanDurationEstimate:
    """Count opaque candidate IDs and estimate one configured scan locally."""

    now = created_at or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("created_at must include a timezone")
    policy = runtime_policy(
        config_path,
        account.account_id,
        account.provider,
        unread_age_days=account.unread_age_days,
        read_one_time_code_age_days=account.read_one_time_code_age_days,
    )
    preferences = PreferenceStore(
        state_db,
        load_or_create_hmac_key(secret_store, account.account_id, state_db),
        account.account_id,
    )
    scan_profile = scan_profile_for_model(account.model_profile)
    was_scanned = preferences.shadow_scan_membership_checker(
        account.account_id,
        account.provider,
        scan_profile,
        policy_safety_fingerprint(policy),
    )
    selected_mailbox = mailbox
    close_mailbox = False
    if selected_mailbox is None:
        if account.provider is ProviderKind.GMAIL:
            selected_mailbox = GmailReadOnlyMailbox(
                account.account_id,
                GoogleAccessTokenProvider(account.account_id, store=secret_store),
            )
        else:
            selected_mailbox = YahooReadOnlyMailbox.from_secret_store(
                account.account_id,
                secret_store,
            )
            close_mailbox = True
    try:
        count, limit_reached = selected_mailbox.count_inbox_unprocessed_candidate_ids(
            now - timedelta(days=policy.unread_age_days),
            now - timedelta(days=policy.read_one_time_code_age_days),
            now - timedelta(days=policy.read_routine_access_alert_age_days),
            was_scanned,
            maximum=None if account.batch_size == 0 else account.batch_size,
        )
    finally:
        if close_mailbox:
            selected_mailbox.close()  # type: ignore[attr-defined]

    ledger = preferences.shadow_scan_summary(account.account_id, scan_profile)
    processed_total = int(ledger.get("processed_total", 0))
    actions = ledger.get("suggested_actions")
    suggested_actions = actions if isinstance(actions, dict) else {}
    action_fraction = (
        min(1.0, int(suggested_actions.get("quarantine", 0)) / processed_total)
        if processed_total > 0
        else 0.30
    )
    graph_ledger = preferences.lumegraph_summary(account.account_id, scan_profile)
    graph_nodes = int(graph_ledger.get("nodes_total", 0))
    lifecycle_fraction = (
        min(1.0, graph_nodes / processed_total)
        if processed_total > 0
        else 0.30
    )
    timing_key = hardware_timing_key(
        hardware,
        threat_protection_enabled=account.threat_protection_enabled,
        threat_semantic_mode=account.threat_semantic_mode,
        lumegraph_enabled=account.lumegraph_enabled,
        obsolescence_proof_enabled=account.obsolescence_proof_enabled,
    )
    stored_samples = preferences.scan_timing_samples(
        account.account_id,
        scan_profile,
        timing_key,
        account.provider,
        account.destination.value,
        account.safety_governor_enforced,
    )
    samples = tuple(
        ScanTimingSample(processed, elapsed)
        for processed, elapsed in stored_samples
    )
    return estimate_scan_duration(
        eligible_unprocessed=count,
        session_limit_reached=limit_reached,
        model_profile=account.model_profile,
        hardware=hardware,
        provider=account.provider,
        destination=account.destination,
        governor_enforced=account.safety_governor_enforced,
        action_fraction=action_fraction,
        lifecycle_fraction=lifecycle_fraction,
        threat_protection_enabled=account.threat_protection_enabled,
        threat_semantic_mode=account.threat_semantic_mode,
        lumegraph_enabled=account.lumegraph_enabled,
        obsolescence_proof_enabled=account.obsolescence_proof_enabled,
        timing_samples=samples,
    )


def record_local_scan_timing(
    state_db: Path,
    account: AccountSettings,
    secret_store: SecretStore,
    hardware: HardwareProfile,
    processed_messages: int,
    elapsed_seconds: float,
    *,
    recorded_at: datetime | None = None,
) -> None:
    """Record aggregate timing from a completed scan for later estimates."""

    now = recorded_at or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("recorded_at must include a timezone")
    preferences = PreferenceStore(
        state_db,
        load_or_create_hmac_key(secret_store, account.account_id, state_db),
        account.account_id,
    )
    preferences.record_scan_timing_sample(
        account.account_id,
        scan_profile_for_model(account.model_profile),
        hardware_timing_key(
            hardware,
            threat_protection_enabled=account.threat_protection_enabled,
            threat_semantic_mode=account.threat_semantic_mode,
            lumegraph_enabled=account.lumegraph_enabled,
            obsolescence_proof_enabled=account.obsolescence_proof_enabled,
        ),
        account.provider,
        account.destination.value,
        account.safety_governor_enforced,
        processed_messages,
        elapsed_seconds,
        now,
    )
