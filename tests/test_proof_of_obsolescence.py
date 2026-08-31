from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from inboxlume.learning import PreferenceStore
from inboxlume.cli import _apply_obsolescence_proofs
from inboxlume.lumegraph import (
    DateRelation,
    HeuristicLifecycleExtractor,
    LifecycleCondition,
    LifecycleObservation,
    LifecycleState,
    UtilityKind,
    UtilityVector,
)
from inboxlume.lumegraph_runtime import run_lumegraph_shadow
from inboxlume.models import (
    Classification,
    EmailCategory,
    PolicyAction,
    PolicyDecision,
    PreferenceSnapshot,
    RetentionSignal,
)
from inboxlume.proof_of_obsolescence import (
    ClosureWitness,
    ObsolescenceProof,
    ProofDestination,
    ProofStatus,
    StoredLifecycleEvidence,
    deterministic_date_proof,
    deterministic_otp_proof,
    multi_signal_consensus_proof,
    successor_transition_proof,
)
from inboxlume.pipeline import DryRunResult

from tests.helpers import make_message


NOW = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)


def classification(category: EmailCategory, *, discard: bool = False) -> Classification:
    return Classification(
        category,
        0.96,
        ("test",),
        "mlx:gemma26",
        RetentionSignal.DISCARD_CANDIDATE if discard else RetentionSignal.UNCERTAIN,
        0.96 if discard else 0.0,
    )


class ProofOfObsolescenceTests(unittest.TestCase):
    def test_proof_confidence_bucket_rejects_boolean_values(self) -> None:
        with self.assertRaises(ValueError):
            ObsolescenceProof(
                ProofStatus.INSUFFICIENT_EVIDENCE,
                ClosureWitness.NONE,
                ProofDestination.QUARANTINE,
                ("test",),
                True,
            )

    def test_expired_read_otp_is_verified_but_attachment_is_blocked(self) -> None:
        message = make_message(
            received_at=NOW - timedelta(days=9),
            unread=False,
            subject="Codice monouso 123456",
        )
        result = classification(EmailCategory.ONE_TIME_CODE)
        decision = PolicyDecision(PolicyAction.QUARANTINE, ("expired_read_one_time_code",))
        observation = HeuristicLifecycleExtractor().extract_lifecycle(
            message, UtilityKind.ONE_TIME_CODE, NOW
        )
        proof = deterministic_otp_proof(message, result, observation, decision, NOW, 7)
        self.assertIsNotNone(proof)
        self.assertEqual(proof.status, ProofStatus.VERIFIED)  # type: ignore[union-attr]
        self.assertEqual(
            proof.witness, ClosureWitness.DETERMINISTIC_OTP_EXPIRY  # type: ignore[union-attr]
        )

        protected = make_message(
            received_at=message.received_at,
            unread=False,
            subject=message.subject,
            has_attachment=True,
        )
        blocked = deterministic_otp_proof(
            protected, result, observation, decision, NOW, 7
        )
        self.assertEqual(blocked.status, ProofStatus.BLOCKED_PROTECTED_UTILITY)  # type: ignore[union-attr]

    def test_elapsed_explicit_promotion_date_is_deterministically_verified(self) -> None:
        result = classification(EmailCategory.ADVERTISING, discard=True)
        decision = PolicyDecision(PolicyAction.REVIEW, ("test",))
        for subject in (
            "Offerta scade il 2026-08-20",
            "Promozione termina il 20 agosto 2026",
            "Offer ends August 20, 2026",
        ):
            with self.subTest(subject=subject):
                message = make_message(subject=subject)
                observation = HeuristicLifecycleExtractor().extract_lifecycle(
                    message, UtilityKind.PROMOTION, NOW
                )
                proof = deterministic_date_proof(
                    message, result, observation, decision, NOW
                )
                self.assertIsNotNone(proof)
                self.assertEqual(proof.status, ProofStatus.VERIFIED)  # type: ignore[union-attr]
                self.assertEqual(  # type: ignore[union-attr]
                    proof.witness, ClosureWitness.VERIFIED_DATE_ELAPSED
                )

    def test_consensus_requires_model_corrections_and_current_regime(self) -> None:
        message = make_message(subject="Weekly offers")
        result = classification(EmailCategory.ADVERTISING, discard=True)
        decision = PolicyDecision(PolicyAction.REVIEW, ("low_interest",))
        preference = PreferenceSnapshot(
            score=0.1,
            observations=20,
            keep_similarity=0.1,
            dont_keep_similarity=0.95,
            keep_similar_examples=0,
            dont_keep_similar_examples=4,
            recent_content_score=0.15,
            recent_content_evidence=4.0,
            recent_content_examples=4,
        )
        proof = multi_signal_consensus_proof(message, result, decision, preference)
        self.assertEqual(proof.status, ProofStatus.VERIFIED)  # type: ignore[union-attr]
        self.assertEqual(proof.witness, ClosureWitness.MULTI_SIGNAL_CONSENSUS)  # type: ignore[union-attr]

        conflicted = replace(
            preference,
            keep_similarity=0.95,
            keep_similar_examples=1,
        )
        insufficient = multi_signal_consensus_proof(
            message, result, decision, conflicted
        )
        self.assertEqual(insufficient.status, ProofStatus.INSUFFICIENT_EVIDENCE)  # type: ignore[union-attr]

    def test_successor_witness_needs_supported_model_and_no_protected_utility(self) -> None:
        previous = StoredLifecycleEvidence(
            UtilityKind.SHIPMENT,
            LifecycleState.PENDING,
            LifecycleCondition.EXTERNAL_ACTION_PENDING,
            True,
            False,
            False,
            False,
            False,
            9,
            ("pending_language",),
            "mlx-lifecycle:gemma26",
        )
        completed = StoredLifecycleEvidence(
            UtilityKind.SHIPMENT,
            LifecycleState.COMPLETED,
            LifecycleCondition.COMPLETED_CONDITION,
            False,
            False,
            False,
            False,
            False,
            9,
            ("completion_language",),
            "mlx-lifecycle:gemma26",
        )
        verified = successor_transition_proof(
            previous, completed, "gemma26-policy-v2"
        )
        self.assertEqual(verified.status, ProofStatus.VERIFIED)
        unsupported = successor_transition_proof(previous, completed, "qwen8-policy-v2")
        self.assertEqual(unsupported.status, ProofStatus.INSUFFICIENT_EVIDENCE)

    def test_newest_first_graph_still_links_older_to_newer_and_proves_old(self) -> None:
        class Backend:
            def extract_lifecycle(self, message, expected_kind, now):  # noqa: ANN001
                completed = "Delivered" in message.subject
                return LifecycleObservation(
                    expected_kind,
                    LifecycleState.COMPLETED if completed else LifecycleState.PENDING,
                    UtilityVector(not completed, False, False, False),
                    DateRelation.UNCERTAIN,
                    (
                        LifecycleCondition.COMPLETED_CONDITION
                        if completed
                        else LifecycleCondition.EXTERNAL_ACTION_PENDING
                    ),
                    0.96,
                    ("completion_language" if completed else "pending_language",),
                    "mlx-lifecycle:gemma26",
                )

        old = make_message(
            message_id="old-private-id",
            received_at=NOW - timedelta(days=15),
            subject="Shipped",
            body_text="Tracking number: ZX-98765",
        )
        new = make_message(
            message_id="new-private-id",
            received_at=NOW - timedelta(days=1),
            subject="Delivered",
            body_text="Tracking number: ZX-98765",
        )
        ordinary = PolicyDecision(PolicyAction.REVIEW, ("test",))
        result = classification(EmailCategory.TRANSACTIONAL)
        batch = [
            SimpleNamespace(message=new, classification=result, decision=ordinary),
            SimpleNamespace(message=old, classification=result, decision=ordinary),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proof.sqlite3"
            store = PreferenceStore(path, b"p" * 32)
            summary = run_lumegraph_shadow(
                batch, Backend(), store, old.account_id, "gemma26-policy-v2", NOW
            )
            proof = store.obsolescence_proof_for_message_id(
                old.account_id, old.provider, old.message_id, "gemma26-policy-v2"
            )
            self.assertEqual(summary["run_transitions"], 1)
            self.assertEqual(proof[0], "verified")  # type: ignore[index]
            self.assertEqual(proof[1], "successor_completed")  # type: ignore[index]
            raw = path.read_bytes().lower()
            self.assertNotIn(b"old-private-id", raw)
            self.assertNotIn(b"new-private-id", raw)
            self.assertNotIn(b"zx-98765", raw)

    def test_verified_proof_promotes_only_quarantine_not_direct_trash(self) -> None:
        message = make_message(message_id="proof-policy-private")
        result = DryRunResult(
            message,
            classification(EmailCategory.ADVERTISING, discard=True),
            PolicyDecision(PolicyAction.REVIEW, ("ordinary_review",)),
            message.age_days(NOW),
        )
        proof = ObsolescenceProof(
            ProofStatus.VERIFIED,
            ClosureWitness.MULTI_SIGNAL_CONSENSUS,
            ProofDestination.QUARANTINE,
            ("model_discard", "repeated_corrections", "current_regime_agrees"),
            9,
        )
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "policy.sqlite3", b"x" * 32)
            store.record_obsolescence_proof(
                message, "gemma26-policy-v2", proof, NOW
            )
            quarantine, summary = _apply_obsolescence_proofs(
                [result],
                store,
                message.account_id,
                message.provider,
                "gemma26-policy-v2",
                direct_to_trash=False,
            )
            direct_trash, trash_summary = _apply_obsolescence_proofs(
                [result],
                store,
                message.account_id,
                message.provider,
                "gemma26-policy-v2",
                direct_to_trash=True,
            )
        self.assertEqual(quarantine[0].decision.action, PolicyAction.QUARANTINE)
        self.assertEqual(summary["promoted_to_quarantine_current_batch"], 1)
        self.assertEqual(direct_trash[0].decision.action, PolicyAction.REVIEW)
        self.assertEqual(trash_summary["withheld_from_direct_trash_current_batch"], 1)

    def test_stale_verified_proof_cannot_override_current_hard_guardrail(self) -> None:
        message = make_message(message_id="stale-hard-proof", has_attachment=True)
        result = DryRunResult(
            message,
            classification(EmailCategory.ADVERTISING, discard=True),
            PolicyDecision(PolicyAction.REVIEW, ("attachment_requires_review",)),
            message.age_days(NOW),
        )
        proof = ObsolescenceProof(
            ProofStatus.VERIFIED,
            ClosureWitness.VERIFIED_DATE_ELAPSED,
            ProofDestination.QUARANTINE,
            ("verified_date_elapsed",),
            9,
        )
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "stale.sqlite3", b"h" * 32)
            store.record_obsolescence_proof(
                message, "gemma26-policy-v2", proof, NOW
            )
            protected, _ = _apply_obsolescence_proofs(
                [result],
                store,
                message.account_id,
                message.provider,
                "gemma26-policy-v2",
                direct_to_trash=False,
            )

        self.assertEqual(protected[0].decision.action, PolicyAction.REVIEW)


if __name__ == "__main__":
    unittest.main()
