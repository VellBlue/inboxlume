from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from inboxlume.learning import (
    FeedbackSignal,
    PreferenceStore,
    load_or_create_hmac_key,
)
from inboxlume.models import (
    Classification,
    EmailCategory,
    PolicyAction,
    PolicyDecision,
)
from inboxlume.runtime import local_versioned_safety_backtest
from inboxlume.safety_backtest import (
    BACKTEST_ENGINE_VERSION,
    BacktestTrend,
    evaluate_versioned_safety_backtest,
)

from tests.helpers import make_message


class FakeSecretStore:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get(self, service: str, account: str) -> str | None:
        return self.values.get((service, account))

    def set(self, service: str, account: str, secret: str) -> None:
        self.values[(service, account)] = secret


class SafetyBacktestTests(unittest.TestCase):
    def test_first_backtest_is_a_reproducible_non_authorising_baseline(self) -> None:
        now = datetime(2026, 8, 30, 17, 0, tzinfo=timezone.utc)
        evidence = {
            "advertising": {
                "dont_keep": 37,
                "keep": 3,
                "unsure": 2,
                "unreviewed": 14,
            }
        }
        first = evaluate_versioned_safety_backtest(
            "account",
            "gemma26-policy-v2",
            evidence,
            now,
        )
        repeated = evaluate_versioned_safety_backtest(
            "account",
            "gemma26-policy-v2",
            evidence,
            now + timedelta(minutes=1),
            previous_evidence_by_family=evidence,
            previous_evidence_fingerprint=first.evidence_fingerprint,
        )

        self.assertEqual(first.engine_version, BACKTEST_ENGINE_VERSION)
        self.assertEqual(first.trend, BacktestTrend.BASELINE)
        self.assertEqual(first.false_cleanup_delta, 0)
        self.assertEqual(first.regressed_families, ())
        self.assertEqual(repeated.trend, BacktestTrend.UNCHANGED)
        self.assertEqual(first.evidence_fingerprint, repeated.evidence_fingerprint)
        payload = first.as_dict()
        self.assertFalse(payload["authorizes_actions"])
        self.assertFalse(payload["read_bodies"])
        self.assertFalse(payload["changes_mailbox"])
        self.assertFalse(payload["stored_plaintext"])

    def test_new_keep_correction_is_a_family_specific_protective_regression(self) -> None:
        previous = {"advertising": {"dont_keep": 40}}
        current = {
            "advertising": {"dont_keep": 40, "keep": 1},
            "one_time_code": {"dont_keep": 10},
        }
        baseline = evaluate_versioned_safety_backtest(
            "account",
            "gemma26-policy-v2",
            previous,
            datetime(2026, 8, 30, tzinfo=timezone.utc),
        )
        report = evaluate_versioned_safety_backtest(
            "account",
            "gemma26-policy-v2",
            current,
            datetime(2026, 8, 31, tzinfo=timezone.utc),
            previous_evidence_by_family=previous,
            previous_evidence_fingerprint=baseline.evidence_fingerprint,
        )

        self.assertEqual(report.trend, BacktestTrend.PROTECTIVE_REGRESSION)
        self.assertEqual(report.false_cleanup_delta, 1)
        self.assertEqual(report.regressed_families, ("advertising",))

    def test_more_confirmations_improve_the_conservative_bound(self) -> None:
        previous = {"advertising": {"dont_keep": 40}}
        current = {"advertising": {"dont_keep": 80}}
        baseline = evaluate_versioned_safety_backtest(
            "account",
            "gemma26-policy-v2",
            previous,
            datetime(2026, 8, 30, tzinfo=timezone.utc),
        )
        report = evaluate_versioned_safety_backtest(
            "account",
            "gemma26-policy-v2",
            current,
            datetime(2026, 8, 31, tzinfo=timezone.utc),
            previous_evidence_by_family=previous,
            previous_evidence_fingerprint=baseline.evidence_fingerprint,
        )

        self.assertEqual(report.trend, BacktestTrend.IMPROVED_EVIDENCE)
        self.assertEqual(report.conclusive_review_delta, 40)
        self.assertLess(float(report.upper_bound_delta), 0.0)

    def test_runtime_records_only_changed_aggregate_snapshots_without_plaintext(self) -> None:
        now = datetime(2026, 8, 30, tzinfo=timezone.utc)
        profile = "gemma26-policy-v2"
        account = "gmail_personale"
        secret_store = FakeSecretStore()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "backtest.sqlite3"
            preferences = PreferenceStore(
                path,
                load_or_create_hmac_key(secret_store, account),
            )
            first_message = make_message(
                message_id="private-baseline-id",
                subject="Private baseline subject",
            )
            classification = Classification(
                EmailCategory.ADVERTISING,
                0.98,
                ("test",),
                "test",
            )
            decision = PolicyDecision(PolicyAction.QUARANTINE, ("test",))
            preferences.record_shadow_scan(
                first_message,
                classification,
                decision,
                profile,
                now,
            )
            preferences.record_quiz_answer(
                first_message,
                classification,
                "dont_keep",
                FeedbackSignal.EXPLICIT_NOT_INTERESTED,
            )

            baseline = local_versioned_safety_backtest(
                path,
                account,
                secret_store,
                profile,
                created_at=now,
            )
            unchanged = local_versioned_safety_backtest(
                path,
                account,
                secret_store,
                profile,
                created_at=now + timedelta(minutes=1),
            )

            restored_message = make_message(
                message_id="private-regression-id",
                subject="Private regression subject",
            )
            preferences.record_shadow_scan(
                restored_message,
                classification,
                decision,
                profile,
                now,
            )
            preferences.record_quiz_answer(
                restored_message,
                classification,
                "keep",
                FeedbackSignal.EXPLICIT_KEEP,
            )
            regression = local_versioned_safety_backtest(
                path,
                account,
                secret_store,
                profile,
                created_at=now + timedelta(minutes=2),
            )
            database_bytes = path.read_bytes()

        self.assertTrue(baseline.snapshot_recorded)
        self.assertEqual(baseline.trend, BacktestTrend.BASELINE)
        self.assertFalse(unchanged.snapshot_recorded)
        self.assertEqual(unchanged.trend, BacktestTrend.UNCHANGED)
        self.assertTrue(regression.snapshot_recorded)
        self.assertEqual(regression.trend, BacktestTrend.PROTECTIVE_REGRESSION)
        self.assertNotIn(b"private-baseline-id", database_bytes)
        self.assertNotIn(b"Private baseline subject", database_bytes)
        self.assertNotIn(b"private-regression-id", database_bytes)
        self.assertNotIn(b"Private regression subject", database_bytes)


if __name__ == "__main__":
    unittest.main()
