from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from inboxlume.learning import FeedbackSignal, PreferenceStore
from inboxlume.models import (
    Classification,
    EmailCategory,
    PolicyAction,
    PolicyDecision,
)
from inboxlume.temporal_drift import (
    TemporalDriftStatus,
    evaluate_temporal_preference_drift,
)

from tests.helpers import make_message


NOW = datetime(2026, 8, 30, 17, 0, tzinfo=timezone.utc)
PROFILE = "gemma26-policy-v2"


class TemporalDriftTests(unittest.TestCase):
    def test_repeated_recent_protection_restricts_only_the_affected_family(self) -> None:
        report = evaluate_temporal_preference_drift(
            "account",
            PROFILE,
            {
                "advertising": {
                    "historical": {"messages": 5, "quiz_dont_keep": 5},
                    "recent": {"messages": 5, "quiz_keep": 5},
                },
                "spam": {
                    "historical": {"messages": 5, "quiz_dont_keep": 5},
                    "recent": {"messages": 5, "quiz_dont_keep": 5},
                },
            },
        )
        families = {item.family: item for item in report.families}
        self.assertEqual(
            families["advertising"].status,
            TemporalDriftStatus.PROTECTIVE_SHIFT,
        )
        self.assertTrue(families["advertising"].restricts_cleanup)
        self.assertEqual(families["spam"].status, TemporalDriftStatus.STABLE)
        self.assertEqual(report.restricted_families, frozenset({"advertising"}))
        payload = report.as_dict()
        self.assertFalse(payload["authorizes_actions"])
        self.assertTrue(payload["restricts_only"])
        self.assertFalse(payload["read_bodies"])
        self.assertFalse(payload["changes_mailbox"])

    def test_declining_interest_is_visible_but_never_authorises_cleanup(self) -> None:
        report = evaluate_temporal_preference_drift(
            "account",
            PROFILE,
            {
                "advertising": {
                    "historical": {"messages": 5, "quiz_keep": 5},
                    "recent": {"messages": 5, "quiz_dont_keep": 5},
                }
            },
        )
        family = report.families[0]
        self.assertEqual(family.status, TemporalDriftStatus.DECLINING_INTEREST)
        self.assertFalse(family.restricts_cleanup)
        self.assertEqual(report.restricted_families, frozenset())

    def test_small_or_weak_windows_keep_collecting(self) -> None:
        report = evaluate_temporal_preference_drift(
            "account",
            PROFILE,
            {
                "advertising": {
                    "historical": {"messages": 4, "quiz_dont_keep": 4},
                    "recent": {"messages": 4, "opened": 4},
                }
            },
        )
        self.assertEqual(report.families[0].status, TemporalDriftStatus.COLLECTING)
        self.assertEqual(report.restricted_families, frozenset())

    def test_store_uses_answer_times_and_keeps_message_data_out_of_plaintext(self) -> None:
        classification = Classification(
            EmailCategory.ADVERTISING,
            0.98,
            ("test",),
            "test",
        )
        decision = PolicyDecision(PolicyAction.QUARANTINE, ("test",))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "temporal.sqlite3"
            store = PreferenceStore(path, b"t" * 32)
            for index in range(5):
                historical = make_message(
                    message_id=f"private-historical-{index}",
                    subject=f"Private historical {index}",
                )
                at = NOW - timedelta(days=90 + index)
                store.record_shadow_scan(
                    historical, classification, decision, PROFILE, at
                )
                store.record_quiz_answer(
                    historical,
                    classification,
                    "dont_keep",
                    FeedbackSignal.EXPLICIT_NOT_INTERESTED,
                    answered_at=at,
                )
                recent = make_message(
                    message_id=f"private-recent-{index}",
                    subject=f"Private recent {index}",
                )
                recent_at = NOW - timedelta(days=5 + index)
                store.record_shadow_scan(
                    recent, classification, decision, PROFILE, recent_at
                )
                store.record_quiz_answer(
                    recent,
                    classification,
                    "keep",
                    FeedbackSignal.EXPLICIT_KEEP,
                    answered_at=recent_at,
                )

            evidence = store.temporal_preference_evidence(
                "gmail_personale",
                PROFILE,
                NOW,
                recent_days=45,
                historical_days=180,
            )
            report = evaluate_temporal_preference_drift(
                "gmail_personale",
                PROFILE,
                evidence,
            )
            database_bytes = path.read_bytes()

        self.assertEqual(
            evidence["advertising"]["recent"]["quiz_keep"], 5
        )
        self.assertEqual(
            evidence["advertising"]["historical"]["quiz_dont_keep"], 5
        )
        self.assertEqual(
            report.families[0].status,
            TemporalDriftStatus.PROTECTIVE_SHIFT,
        )
        self.assertNotIn(b"private-recent", database_bytes)
        self.assertNotIn(b"Private historical", database_bytes)


if __name__ == "__main__":
    unittest.main()
