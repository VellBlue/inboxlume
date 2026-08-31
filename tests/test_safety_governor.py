from __future__ import annotations

import math
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from inboxlume.learning import FeedbackSignal, PreferenceStore
from inboxlume.models import (
    Classification,
    EmailCategory,
    PolicyAction,
    PolicyDecision,
    ProviderKind,
)
from inboxlume.safety_governor import (
    GovernorStatus,
    evaluate_safety_governor,
    lower_binomial_error_rate,
    operational_governor_available,
    operational_quarantine_gate,
    upper_binomial_error_rate,
)

from tests.helpers import make_message


class SafetyGovernorTests(unittest.TestCase):
    def test_zero_error_bound_matches_the_documented_exact_formula(self) -> None:
        observed = upper_binomial_error_rate(0, 40)
        expected = 1.0 - math.pow(0.05, 1.0 / 40)
        self.assertIsNotNone(observed)
        self.assertAlmostEqual(float(observed), expected, places=12)
        self.assertAlmostEqual(float(observed), 0.0721575, places=6)

    def test_shadow_qualification_needs_about_299_zero_error_reviews(self) -> None:
        not_yet = evaluate_safety_governor(
            "account",
            "gemma26-policy-v2",
            {"advertising": {"dont_keep": 298}},
        )
        qualified = evaluate_safety_governor(
            "account",
            "gemma26-policy-v2",
            {"advertising": {"dont_keep": 299}},
        )
        self.assertEqual(not_yet.overall.status, GovernorStatus.NOT_QUALIFIED)
        self.assertEqual(qualified.overall.status, GovernorStatus.QUALIFIED_SHADOW)
        self.assertFalse(qualified.authorizes_actions)
        self.assertTrue(qualified.shadow_only)

    def test_exact_bound_remains_finite_with_observed_errors(self) -> None:
        self.assertAlmostEqual(
            float(upper_binomial_error_rate(1, 100)),
            0.0465598115,
            places=9,
        )
        self.assertAlmostEqual(
            float(lower_binomial_error_rate(3, 40)),
            0.0207536015,
            places=9,
        )
        majority = upper_binomial_error_rate(9, 10)
        self.assertIsNotNone(majority)
        self.assertGreater(float(majority), 0.95)
        self.assertLess(float(majority), 1.0)

    def test_operational_gate_preserves_ordinary_flow_and_blocks_repeated_family_errors(self) -> None:
        collecting = evaluate_safety_governor(
            "account",
            "gemma26-policy-v2",
            {"advertising": {"dont_keep": 298}},
        )
        qualified = evaluate_safety_governor(
            "account",
            "gemma26-policy-v2",
            {"advertising": {"dont_keep": 299}},
        )

        collecting_gate = operational_quarantine_gate(collecting, enforced=True)
        self.assertTrue(collecting_gate.permits("advertising"))
        self.assertTrue(collecting_gate.permits("spam"))
        self.assertEqual(collecting_gate.blocked_families, frozenset())
        gate = operational_quarantine_gate(qualified, enforced=True)
        self.assertTrue(gate.permits("advertising"))
        self.assertTrue(gate.permits_direct_trash("advertising"))
        self.assertTrue(gate.permits("spam"))
        self.assertTrue(bool(gate.as_dict()["authorizes_trash"]))
        disabled_gate = operational_quarantine_gate(collecting, enforced=False)
        self.assertTrue(disabled_gate.permits("spam"))
        self.assertTrue(disabled_gate.permits_direct_trash("spam"))
        self.assertFalse(bool(disabled_gate.as_dict()["authorizes_trash"]))
        one_error = evaluate_safety_governor(
            "account",
            "gemma26-policy-v2",
            {"advertising": {"dont_keep": 999, "keep": 1}},
        )
        strict_gate = operational_quarantine_gate(one_error, enforced=True)
        self.assertTrue(strict_gate.permits("advertising"))
        self.assertFalse(strict_gate.permits_direct_trash("advertising"))

        repeated_errors = evaluate_safety_governor(
            "account",
            "gemma26-policy-v2",
            {"advertising": {"dont_keep": 37, "keep": 3}},
        )
        adaptive_gate = operational_quarantine_gate(repeated_errors, enforced=True)
        self.assertFalse(adaptive_gate.permits("advertising"))
        self.assertTrue(adaptive_gate.permits("spam"))
        self.assertEqual(adaptive_gate.blocked_families, frozenset({"advertising"}))

        diluted_errors = evaluate_safety_governor(
            "account",
            "gemma26-policy-v2",
            {"advertising": {"dont_keep": 97, "keep": 3}},
        )
        released_gate = operational_quarantine_gate(diluted_errors, enforced=True)
        self.assertTrue(released_gate.permits("advertising"))
        self.assertEqual(released_gate.blocked_families, frozenset())

    def test_operational_gate_cannot_activate_before_forty_conclusive_reviews(self) -> None:
        thirty_nine = evaluate_safety_governor(
            "account",
            "gemma26-policy-v2",
            {"advertising": {"dont_keep": 36, "keep": 3}},
        )
        forty = evaluate_safety_governor(
            "account",
            "gemma26-policy-v2",
            {"advertising": {"dont_keep": 37, "keep": 3}},
        )

        self.assertFalse(operational_governor_available(thirty_nine))
        premature = operational_quarantine_gate(thirty_nine, enforced=True)
        self.assertFalse(premature.enforced)
        self.assertTrue(premature.permits("advertising"))

        self.assertTrue(operational_governor_available(forty))
        available = operational_quarantine_gate(forty, enforced=True)
        self.assertTrue(available.enforced)
        self.assertFalse(available.permits("advertising"))

    def test_protective_temporal_drift_can_only_restrict_an_operational_gate(self) -> None:
        qualified = evaluate_safety_governor(
            "account",
            "gemma26-policy-v2",
            {"advertising": {"dont_keep": 299}},
        )
        active = operational_quarantine_gate(
            qualified,
            enforced=True,
            protective_drift_families={"advertising"},
        )
        inactive = operational_quarantine_gate(
            qualified,
            enforced=False,
            protective_drift_families={"advertising"},
        )

        self.assertFalse(active.permits("advertising"))
        self.assertFalse(active.permits_direct_trash("advertising"))
        self.assertEqual(
            active.temporal_drift_restricted_families,
            frozenset({"advertising"}),
        )
        self.assertTrue(inactive.permits("advertising"))
        self.assertTrue(inactive.permits_direct_trash("advertising"))
        self.assertEqual(
            inactive.temporal_drift_restricted_families,
            frozenset(),
        )

    def test_evidence_is_account_scoped_aggregate_and_contains_no_plaintext(self) -> None:
        now = datetime(2026, 8, 30, tzinfo=timezone.utc)
        profile = "gemma26-policy-v2"
        classification = Classification(
            EmailCategory.ADVERTISING,
            0.98,
            ("test",),
            "test",
        )
        decision = PolicyDecision(PolicyAction.QUARANTINE, ("test",))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.sqlite3"
            store = PreferenceStore(path, b"g" * 32)
            discard = make_message(
                message_id="private-discard-id",
                subject="Private advertising example",
            )
            keep = make_message(
                message_id="private-keep-id",
                subject="Private protected example",
            )
            other_account = make_message(
                account_id="yahoo_personale",
                provider=ProviderKind.YAHOO,
                message_id="private-other-id",
            )
            for message, answer, signal in (
                (
                    discard,
                    "dont_keep",
                    FeedbackSignal.EXPLICIT_NOT_INTERESTED,
                ),
                (keep, "keep", FeedbackSignal.EXPLICIT_KEEP),
                (
                    other_account,
                    "dont_keep",
                    FeedbackSignal.EXPLICIT_NOT_INTERESTED,
                ),
            ):
                store.record_shadow_scan(
                    message,
                    classification,
                    decision,
                    profile,
                    now,
                )
                store.record_quiz_answer(message, classification, answer, signal)

            evidence = store.shadow_quarantine_evidence_by_category(
                "gmail_personale",
                profile,
            )
            database_bytes = path.read_bytes()

        self.assertEqual(
            evidence,
            {
                "advertising": {
                    "dont_keep": 1,
                    "keep": 1,
                    "unsure": 0,
                    "unreviewed": 0,
                }
            },
        )
        self.assertNotIn(b"private-discard-id", database_bytes)
        self.assertNotIn(b"Private advertising example", database_bytes)


if __name__ == "__main__":
    unittest.main()
