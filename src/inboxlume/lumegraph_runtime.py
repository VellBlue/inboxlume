from __future__ import annotations

from collections import Counter
from dataclasses import replace
from datetime import datetime
from typing import Iterable, Protocol

from .learning import PreferenceStore
from .lumegraph import (
    LUMEGRAPH_ENGINE_VERSION,
    HeuristicLifecycleExtractor,
    LifecycleObservation,
    UtilityKind,
    lifecycle_candidate_kind,
    lifecycle_relation_materials,
)
from .models import Classification, EmailRecord, PolicyDecision
from .proof_of_obsolescence import (
    deterministic_date_proof,
    deterministic_otp_proof,
    lifecycle_hard_protected,
    multi_signal_consensus_proof,
)


class _LifecycleResult(Protocol):
    message: EmailRecord
    classification: Classification
    decision: PolicyDecision


class _LifecycleBackend(Protocol):
    def extract_lifecycle(
        self,
        message: EmailRecord,
        expected_kind: UtilityKind,
        now: datetime,
    ) -> LifecycleObservation: ...


def run_lumegraph_shadow(
    results: Iterable[_LifecycleResult],
    backend: object | None,
    store: PreferenceStore,
    account_id: str,
    scan_profile: str,
    now: datetime,
    read_otp_age_days: int = 7,
) -> dict[str, object]:
    """Build the private utility graph and narrowly verified closure proofs."""

    if now.tzinfo is None:
        raise ValueError("now must include a timezone")
    if not account_id.strip():
        raise ValueError("account is required")
    fallback = HeuristicLifecycleExtractor()
    extractor = getattr(backend, "extract_lifecycle", None)
    kinds: Counter[str] = Counter()
    states: Counter[str] = Counter()
    inserted_nodes = 0
    transitions = 0
    model_inferences = 0
    fallbacks = 0
    failures = 0
    proof_observations = 0
    for result in results:
        decision = getattr(result, "decision", None)
        if isinstance(decision, PolicyDecision):
            consensus = multi_signal_consensus_proof(
                result.message,
                result.classification,
                decision,
                store.interest_for(result.message, result.classification, now),
            )
            if consensus is not None:
                store.record_obsolescence_proof(
                    result.message,
                    scan_profile,
                    consensus,
                    now,
                )
                proof_observations += 1
        kind = lifecycle_candidate_kind(result.message, result.classification)
        if kind is UtilityKind.NONE:
            continue
        observation: LifecycleObservation
        if callable(extractor):
            model_inferences += 1
            try:
                observation = extractor(result.message, kind, now)
            except (RuntimeError, ValueError, TypeError):
                failures += 1
                fallbacks += 1
                fallback_observation = fallback.extract_lifecycle(
                    result.message,
                    kind,
                    now,
                )
                observation = replace(
                    fallback_observation,
                    reason_codes=tuple(
                        dict.fromkeys(
                            (*fallback_observation.reason_codes, "model_failure")
                        )
                    ),
                    extractor="heuristic-lifecycle-v1:model-failure",
                )
        else:
            fallbacks += 1
            observation = fallback.extract_lifecycle(result.message, kind, now)
        hard_protected = (
            lifecycle_hard_protected(
                result.message,
                result.classification,
                decision,
            )
            if isinstance(decision, PolicyDecision)
            else True
        )
        inserted, linked = store.record_lumegraph_observation(
            result.message,
            observation,
            scan_profile,
            now,
            lifecycle_relation_materials(result.message, kind),
            hard_protected=hard_protected,
        )
        otp_proof = (
            deterministic_otp_proof(
                result.message,
                result.classification,
                observation,
                decision,
                now,
                read_otp_age_days,
            )
            if isinstance(decision, PolicyDecision)
            else None
        )
        if otp_proof is not None:
            store.record_obsolescence_proof(
                result.message,
                scan_profile,
                otp_proof,
                now,
            )
            proof_observations += 1
        date_proof = (
            deterministic_date_proof(
                result.message,
                result.classification,
                observation,
                decision,
                now,
            )
            if isinstance(decision, PolicyDecision)
            else None
        )
        if date_proof is not None:
            store.record_obsolescence_proof(
                result.message,
                scan_profile,
                date_proof,
                now,
            )
            proof_observations += 1
        if inserted:
            inserted_nodes += 1
            kinds[observation.kind.value] += 1
            states[observation.state.value] += 1
        transitions += int(linked)
    proof_summary = store.obsolescence_proof_summary(account_id, scan_profile)
    has_verified_proof = int(proof_summary.get("verified_total", 0)) > 0
    return {
        "engine_version": LUMEGRAPH_ENGINE_VERSION,
        "shadow_only": False,
        "authorizes_policy": has_verified_proof,
        "authorizes_actions": (
            "reversible_quarantine_only" if has_verified_proof else False
        ),
        "run_nodes": inserted_nodes,
        "run_transitions": transitions,
        "run_kinds": dict(sorted(kinds.items())),
        "run_states": dict(sorted(states.items())),
        "model_inferences": model_inferences,
        "fallback_nodes": fallbacks,
        "model_failures": failures,
        "ledger": store.lumegraph_summary(account_id, scan_profile),
        "proof_observations": proof_observations,
        "proof_of_obsolescence": proof_summary,
        "reads_additional_bodies": False,
        "stored_plaintext": False,
        "changes_mailbox": False,
    }
