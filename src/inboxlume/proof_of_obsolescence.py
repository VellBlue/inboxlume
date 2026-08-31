from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from .lumegraph import (
    DateRelation,
    LifecycleCondition,
    LifecycleObservation,
    LifecycleState,
    UtilityKind,
    verified_expiry_date,
)
from .models import (
    Classification,
    EmailCategory,
    EmailRecord,
    PolicyDecision,
    PolicyAction,
    PreferenceSnapshot,
    RetentionSignal,
)
from .semantic_guardrails import (
    AccessAlertKind,
    access_alert_kind,
    has_permanent_transaction_record,
)


PROOF_ENGINE_VERSION = "proof-obsolescence-v1"


class ProofStatus(StrEnum):
    VERIFIED = "verified"
    BLOCKED_PROTECTED_UTILITY = "blocked_protected_utility"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class ClosureWitness(StrEnum):
    DETERMINISTIC_OTP_EXPIRY = "deterministic_otp_expiry"
    SUCCESSOR_COMPLETED = "successor_completed"
    SUCCESSOR_REPLACED = "successor_replaced"
    VERIFIED_DATE_ELAPSED = "verified_date_elapsed"
    MULTI_SIGNAL_CONSENSUS = "multi_signal_consensus"
    NONE = "none"


class ProofDestination(StrEnum):
    QUARANTINE = "quarantine"


@dataclass(frozen=True, slots=True)
class ObsolescenceProof:
    status: ProofStatus
    witness: ClosureWitness
    maximum_destination: ProofDestination
    reason_codes: tuple[str, ...]
    confidence_bucket: int

    def __post_init__(self) -> None:
        if (
            isinstance(self.confidence_bucket, bool)
            or not isinstance(self.confidence_bucket, int)
            or not 0 <= self.confidence_bucket <= 9
        ):
            raise ValueError("invalid proof confidence bucket")
        if not 1 <= len(self.reason_codes) <= 6:
            raise ValueError("invalid proof reason count")
        if self.status is ProofStatus.VERIFIED and self.witness is ClosureWitness.NONE:
            raise ValueError("a verified proof needs a closure witness")

    @property
    def verified(self) -> bool:
        return self.status is ProofStatus.VERIFIED


@dataclass(frozen=True, slots=True)
class StoredLifecycleEvidence:
    kind: UtilityKind
    state: LifecycleState
    condition: LifecycleCondition
    operational: bool
    evidentiary: bool
    personal: bool
    security: bool
    hard_protected: bool
    confidence_bucket: int
    reason_codes: tuple[str, ...]
    extractor: str

    @property
    def has_protected_utility(self) -> bool:
        return self.evidentiary or self.personal or self.security


HARD_POLICY_REASONS = frozenset(
    {
        "protected_mailbox_flag",
        "known_relationship",
        "self_sent_message",
        "transaction_record",
        "high_risk_access_alert",
        "unread_access_alert",
        "banking_record_or_notice",
        "protected_sender",
        "protected_keyword",
        "protected_category",
        "attachment_requires_review",
        "conflicting_similar_examples",
        "similar_content_previously_kept",
        "recent_behavior_conflicts_with_explicit_feedback",
        "similar_content_opened_recently",
        "content_requires_retention",
        "uncertain_content_retention",
        "threat_protective_review",
    }
)


def has_hard_policy_reason(reason_codes: tuple[str, ...]) -> bool:
    return bool(set(reason_codes).intersection(HARD_POLICY_REASONS))


def lifecycle_hard_protected(
    message: EmailRecord,
    classification: Classification,
    decision: PolicyDecision,
) -> bool:
    """Freeze safety facts needed after plaintext has left memory."""

    return (
        has_hard_policy_reason(decision.reason_codes)
        or message.has_attachment
        or has_permanent_transaction_record(message)
        or access_alert_kind(message) is AccessAlertKind.HIGH_RISK
        or classification.category is EmailCategory.BANKING
    )


def deterministic_otp_proof(
    message: EmailRecord,
    classification: Classification,
    observation: LifecycleObservation,
    decision: PolicyDecision,
    now: datetime,
    minimum_age_days: int,
) -> ObsolescenceProof | None:
    if observation.kind is not UtilityKind.ONE_TIME_CODE:
        return None
    if lifecycle_hard_protected(message, classification, decision):
        return ObsolescenceProof(
            ProofStatus.BLOCKED_PROTECTED_UTILITY,
            ClosureWitness.NONE,
            ProofDestination.QUARANTINE,
            ("hard_guardrail",),
            min(9, int(observation.confidence * 10)),
        )
    # Read codes beyond the configured age have deterministically lost token and
    # security utility. Evidentiary/personal value and hard guardrails still win.
    protected_utility = (
        observation.utility.evidentiary or observation.utility.personal
    )
    verified = (
        classification.category is EmailCategory.ONE_TIME_CODE
        and classification.confidence >= 0.80
        and not message.unread
        and message.age_days(now) >= minimum_age_days
        and not protected_utility
    )
    if verified:
        return ObsolescenceProof(
            ProofStatus.VERIFIED,
            ClosureWitness.DETERMINISTIC_OTP_EXPIRY,
            ProofDestination.QUARANTINE,
            ("read_otp", "age_threshold", "expired_state", "no_protected_utility"),
            9,
        )
    status = (
        ProofStatus.BLOCKED_PROTECTED_UTILITY
        if protected_utility
        else ProofStatus.INSUFFICIENT_EVIDENCE
    )
    return ObsolescenceProof(
        status,
        ClosureWitness.NONE,
        ProofDestination.QUARANTINE,
        (
            "protected_utility_remains"
            if protected_utility
            else "otp_closure_not_verified",
        ),
        min(9, int(observation.confidence * 10)),
    )


def deterministic_date_proof(
    message: EmailRecord,
    classification: Classification,
    observation: LifecycleObservation,
    decision: PolicyDecision,
    now: datetime,
) -> ObsolescenceProof | None:
    """Verify an explicitly dated, elapsed promotion without trusting prose alone."""

    if observation.kind is not UtilityKind.PROMOTION:
        return None
    if lifecycle_hard_protected(message, classification, decision):
        return ObsolescenceProof(
            ProofStatus.BLOCKED_PROTECTED_UTILITY,
            ClosureWitness.NONE,
            ProofDestination.QUARANTINE,
            ("hard_guardrail",),
            min(9, int(observation.confidence * 10)),
        )
    protected_utility = (
        observation.utility.operational
        or observation.utility.evidentiary
        or observation.utility.personal
        or observation.utility.security
    )
    expiry = verified_expiry_date(message, now)
    verified = (
        expiry is not None
        and expiry < now.date()
        and classification.category is EmailCategory.ADVERTISING
        and classification.confidence >= 0.90
        and not protected_utility
    )
    if verified:
        return ObsolescenceProof(
            ProofStatus.VERIFIED,
            ClosureWitness.VERIFIED_DATE_ELAPSED,
            ProofDestination.QUARANTINE,
            ("explicit_expiry_date", "date_elapsed", "no_protected_utility"),
            9,
        )
    return ObsolescenceProof(
        (
            ProofStatus.BLOCKED_PROTECTED_UTILITY
            if protected_utility
            else ProofStatus.INSUFFICIENT_EVIDENCE
        ),
        ClosureWitness.NONE,
        ProofDestination.QUARANTINE,
        (
            "protected_utility_remains"
            if protected_utility
            else "date_closure_not_verified"
        ),
        min(9, int(observation.confidence * 10)),
    )


def multi_signal_consensus_proof(
    message: EmailRecord,
    classification: Classification,
    decision: PolicyDecision,
    preference: PreferenceSnapshot,
) -> ObsolescenceProof | None:
    """Require model, repeated corrections and the current behavior regime to agree."""

    supported = {
        EmailCategory.ADVERTISING,
        EmailCategory.SOCIAL,
        EmailCategory.SPAM,
    }
    if classification.category not in supported:
        return None
    if lifecycle_hard_protected(message, classification, decision):
        return ObsolescenceProof(
            ProofStatus.BLOCKED_PROTECTED_UTILITY,
            ClosureWitness.NONE,
            ProofDestination.QUARANTINE,
            ("hard_guardrail",),
            0,
        )
    if decision.action is PolicyAction.KEEP:
        return ObsolescenceProof(
            ProofStatus.BLOCKED_PROTECTED_UTILITY,
            ClosureWitness.NONE,
            ProofDestination.QUARANTINE,
            ("ordinary_policy_keep",),
            0,
        )
    model_signal = (
        classification.retention is RetentionSignal.DISCARD_CANDIDATE
        and classification.confidence >= 0.90
        and classification.retention_confidence >= 0.90
    )
    correction_signal = (
        preference.dont_keep_similarity >= 0.90
        and preference.dont_keep_similar_examples >= 3
        and preference.keep_similarity <= 0.35
        and preference.keep_similar_examples == 0
    )
    current_regime_signal = (
        preference.recent_content_score <= 0.20
        and preference.recent_content_evidence >= 3.0
        and preference.recent_content_examples >= 3
    )
    if model_signal and correction_signal and current_regime_signal:
        return ObsolescenceProof(
            ProofStatus.VERIFIED,
            ClosureWitness.MULTI_SIGNAL_CONSENSUS,
            ProofDestination.QUARANTINE,
            ("model_discard", "repeated_corrections", "current_regime_agrees"),
            9,
        )
    return ObsolescenceProof(
        ProofStatus.INSUFFICIENT_EVIDENCE,
        ClosureWitness.NONE,
        ProofDestination.QUARANTINE,
        ("independent_signal_consensus_missing",),
        sum((model_signal, correction_signal, current_regime_signal)) * 3,
    )
def successor_transition_proof(
    predecessor: StoredLifecycleEvidence,
    successor: StoredLifecycleEvidence,
    scan_profile: str,
) -> ObsolescenceProof:
    """Verify only a narrow, high-precision shipment successor cycle."""

    if predecessor.kind is not UtilityKind.SHIPMENT or successor.kind is not UtilityKind.SHIPMENT:
        return ObsolescenceProof(
            ProofStatus.INSUFFICIENT_EVIDENCE,
            ClosureWitness.NONE,
            ProofDestination.QUARANTINE,
            ("unsupported_lifecycle_family",),
            min(predecessor.confidence_bucket, successor.confidence_bucket),
        )
    if (
        predecessor.hard_protected
        or successor.hard_protected
        or predecessor.has_protected_utility
        or successor.has_protected_utility
    ):
        return ObsolescenceProof(
            ProofStatus.BLOCKED_PROTECTED_UTILITY,
            ClosureWitness.NONE,
            ProofDestination.QUARANTINE,
            ("protected_utility_remains",),
            min(predecessor.confidence_bucket, successor.confidence_bucket),
        )
    supported_model = scan_profile.startswith("gemma26-")
    model_consensus = (
        predecessor.extractor.startswith("mlx-lifecycle:gemma26")
        and successor.extractor.startswith("mlx-lifecycle:gemma26")
        and predecessor.confidence_bucket >= 9
        and successor.confidence_bucket >= 9
    )
    predecessor_open = (
        predecessor.state in {LifecycleState.ACTIVE, LifecycleState.PENDING}
        and predecessor.operational
    )
    successor_closed = (
        successor.state in {LifecycleState.COMPLETED, LifecycleState.REPLACED}
        and successor.condition is LifecycleCondition.COMPLETED_CONDITION
        and not successor.operational
    )
    language_witness = (
        "completion_language" in successor.reason_codes
        if successor.state is LifecycleState.COMPLETED
        else "replacement_language" in successor.reason_codes
    )
    if supported_model and model_consensus and predecessor_open and successor_closed and language_witness:
        witness = (
            ClosureWitness.SUCCESSOR_COMPLETED
            if successor.state is LifecycleState.COMPLETED
            else ClosureWitness.SUCCESSOR_REPLACED
        )
        return ObsolescenceProof(
            ProofStatus.VERIFIED,
            witness,
            ProofDestination.QUARANTINE,
            ("opaque_relation_match", "ordered_successor", "no_protected_utility"),
            min(predecessor.confidence_bucket, successor.confidence_bucket),
        )
    return ObsolescenceProof(
        ProofStatus.INSUFFICIENT_EVIDENCE,
        ClosureWitness.NONE,
        ProofDestination.QUARANTINE,
        ("successor_closure_not_verified",),
        min(predecessor.confidence_bucket, successor.confidence_bucket),
    )
