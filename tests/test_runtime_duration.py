from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from inboxlume.duration_estimator import EstimateConfidence
from inboxlume.local_models import HardwareProfile, LocalModelProfile
from inboxlume.runtime import (
    local_scan_duration_estimate,
    record_local_scan_timing,
)
from inboxlume.settings import ApplicationSettings


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 8, 30, tzinfo=timezone.utc)
HARDWARE = HardwareProfile("Darwin", "arm64", 24.0)


class FakeSecretStore:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get(self, service: str, account: str) -> str | None:
        return self.values.get((service, account))

    def set(self, service: str, account: str, secret: str) -> None:
        self.values[(service, account)] = secret


class IdOnlyMailbox:
    def __init__(self, count: int, reached: bool) -> None:
        self.count = count
        self.reached = reached
        self.calls: list[tuple[object, ...]] = []

    def count_inbox_unprocessed_candidate_ids(self, *args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        self.calls.append((*args, kwargs))
        return self.count, self.reached


class RuntimeDurationTests(unittest.TestCase):
    def test_estimate_uses_id_only_count_and_respects_session_limit(self) -> None:
        store = FakeSecretStore()
        account = replace(
            ApplicationSettings.defaults().accounts[0],
            batch_size=50,
            model_profile=LocalModelProfile.GEMMA26,
        )
        mailbox = IdOnlyMailbox(50, True)
        with tempfile.TemporaryDirectory() as directory:
            estimate = local_scan_duration_estimate(
                Path(directory) / "state.sqlite3",
                ROOT / "config" / "accounts.example.json",
                account,
                store,
                HARDWARE,
                created_at=NOW,
                mailbox=mailbox,  # type: ignore[arg-type]
            )

        self.assertEqual(estimate.planned_messages, 50)
        self.assertTrue(estimate.session_limit_reached)
        self.assertEqual(estimate.confidence, EstimateConfidence.LOW)
        self.assertEqual(mailbox.calls[0][-1]["maximum"], 50)
        self.assertFalse(estimate.reads_bodies)
        self.assertFalse(estimate.loads_model)
        self.assertFalse(estimate.changes_mailbox)

    def test_matching_completed_runs_raise_estimate_confidence(self) -> None:
        store = FakeSecretStore()
        account = replace(
            ApplicationSettings.defaults().accounts[0],
            batch_size=0,
            model_profile=LocalModelProfile.GEMMA26,
        )
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "state.sqlite3"
            for elapsed in (75.0, 78.0, 80.0):
                record_local_scan_timing(
                    database,
                    account,
                    store,
                    HARDWARE,
                    50,
                    elapsed,
                    recorded_at=NOW,
                )
            estimate = local_scan_duration_estimate(
                database,
                ROOT / "config" / "accounts.example.json",
                account,
                store,
                HARDWARE,
                created_at=NOW,
                mailbox=IdOnlyMailbox(100, False),  # type: ignore[arg-type]
            )
            database_bytes = database.read_bytes()

        self.assertEqual(estimate.confidence, EstimateConfidence.HIGH)
        self.assertEqual(estimate.basis, "matching_local_sessions")
        self.assertEqual(estimate.timing_sample_count, 3)
        self.assertNotIn(b"Darwin", database_bytes)
        self.assertNotIn(b"arm64", database_bytes)


if __name__ == "__main__":
    unittest.main()
