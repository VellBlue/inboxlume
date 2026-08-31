from __future__ import annotations

import json
import tempfile
import unittest
from argparse import Namespace
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from inboxlume.desktop_worker import terminal_scan_receipt
from inboxlume.diagnostics import (
    append_diagnostic,
    diagnostic_for_terminal_status,
    diagnostic_from_summary,
    latest_diagnostic,
)


def _failure(**overrides: object):
    arguments: dict[str, object] = {
        "status": "failed",
        "trigger": "manual",
        "provider": "gmail",
        "destination": "quarantine",
        "scan_profile": "synthetic-profile",
        "phase": "classification",
        "processed": 0,
        "mailbox_outcome": "unchanged",
        "governor_requested": False,
    }
    arguments.update(overrides)
    return diagnostic_for_terminal_status(**arguments)  # type: ignore[arg-type]


class DiagnosticTests(unittest.TestCase):
    def test_concurrent_aggregate_appends_do_not_lose_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run.diagnostics.jsonl"

            def write(index: int) -> None:
                append_diagnostic(
                    path,
                    _failure(
                        recorded_at=datetime(2026, 8, 30, tzinfo=timezone.utc)
                        + timedelta(seconds=index),
                    ),
                )

            with ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(write, range(40)))

            lines = path.read_text(encoding="utf-8").splitlines()
            records = [json.loads(line) for line in lines]

        self.assertEqual(len(records), 40)
        self.assertTrue(all(record["status"] == "failed" for record in records))
        self.assertTrue(all(record["stored_plaintext"] is False for record in records))

    def test_latest_diagnostic_accepts_cancelled_aggregate_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run.diagnostics.jsonl"
            append_diagnostic(
                path,
                _failure(
                    status="cancelled",
                    trigger="scheduled",
                    provider="yahoo",
                    destination="trash",
                    scan_profile="gemma26-policy-v2",
                    governor_requested=True,
                ),
            )
            latest = latest_diagnostic(path)

        self.assertIsNotNone(latest)
        self.assertEqual(latest["status"], "cancelled")  # type: ignore[index]
        self.assertEqual(latest["processed"], 0)  # type: ignore[index]

    def test_interrupted_run_records_phase_count_and_mailbox_outcome(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run.diagnostics.jsonl"
            append_diagnostic(
                path,
                _failure(
                    phase="mailbox_actions",
                    processed=73,
                    mailbox_outcome="unknown",
                ),
            )
            latest = latest_diagnostic(path)

        assert latest is not None
        self.assertEqual(latest["status"], "failed")
        self.assertEqual(latest["phase"], "mailbox_actions")
        self.assertEqual(latest["processed"], 73)
        self.assertEqual(latest["mailbox_outcome"], "unknown")

    def test_failure_before_any_mailbox_action_stays_distinguishable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run.diagnostics.jsonl"
            append_diagnostic(path, _failure(phase="threat_protection", processed=12))
            latest = latest_diagnostic(path)

        assert latest is not None
        self.assertEqual(latest["phase"], "threat_protection")
        self.assertEqual(latest["processed"], 12)
        self.assertEqual(latest["mailbox_outcome"], "unchanged")

    def test_completed_run_states_the_outcome_from_its_own_summary(self) -> None:
        applied = diagnostic_from_summary(
            {
                "scan_profile": "gemma26-policy-v2",
                "newly_processed": 100,
                "automatic_quarantine": {"applied": 5},
            },
            trigger="manual",
            provider="gmail",
            destination="quarantine",
            governor_requested=False,
        ).as_dict()
        untouched = diagnostic_from_summary(
            {
                "scan_profile": "gemma26-policy-v2",
                "newly_processed": 100,
                "automatic_quarantine": {"applied": 0},
            },
            trigger="manual",
            provider="gmail",
            destination="quarantine",
            governor_requested=False,
        ).as_dict()

        self.assertEqual(applied["phase"], "completed")
        self.assertEqual(applied["mailbox_outcome"], "changed")
        self.assertEqual(untouched["phase"], "completed")
        self.assertEqual(untouched["mailbox_outcome"], "unchanged")

    def test_worker_receipt_and_persisted_record_agree(self) -> None:
        arguments = Namespace(command="scan")
        setattr(arguments, "_worker_stage", "mailbox_actions")
        setattr(arguments, "_worker_processed", 41)
        setattr(arguments, "_mailbox_mutation_started", True)

        phase, processed, mailbox_outcome = terminal_scan_receipt(arguments)
        record = _failure(
            phase=phase,
            processed=processed,
            mailbox_outcome=mailbox_outcome,
        ).as_dict()

        self.assertEqual(record["phase"], "mailbox_actions")
        self.assertEqual(record["processed"], 41)
        self.assertEqual(record["mailbox_outcome"], "unknown")

    def test_records_written_before_the_phase_existed_stay_readable(self) -> None:
        legacy = {
            "applied": 0,
            "destination": "quarantine",
            "governor_blocked": 0,
            "governor_enforced": False,
            "governor_requested": False,
            "lumegraph_available": False,
            "lumegraph_model_failures": 0,
            "lumegraph_nodes": 0,
            "lumegraph_transitions": 0,
            "processed": 0,
            "provider": "yahoo",
            "recorded_at": "2026-08-31T11:26:33.880084+00:00",
            "scan_profile": "gemma26-policy-v2",
            "schema": "run-diagnostic-v1",
            "status": "failed",
            "stored_plaintext": False,
            "trigger": "manual",
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run.diagnostics.jsonl"
            path.write_text(
                json.dumps(legacy, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            latest = latest_diagnostic(path)

        assert latest is not None
        self.assertEqual(latest["status"], "failed")
        self.assertEqual(latest["phase"], "unspecified")
        self.assertEqual(latest["mailbox_outcome"], "unknown")

    def test_a_completed_legacy_record_keeps_its_provable_outcome(self) -> None:
        legacy = {
            "applied": 5,
            "destination": "quarantine",
            "governor_blocked": 0,
            "governor_enforced": False,
            "governor_requested": False,
            "lumegraph_available": True,
            "lumegraph_model_failures": 3,
            "lumegraph_nodes": 30,
            "lumegraph_transitions": 0,
            "processed": 100,
            "provider": "gmail",
            "recorded_at": "2026-08-30T21:48:01.298324+00:00",
            "scan_profile": "gemma26-policy-v2",
            "schema": "run-diagnostic-v1",
            "status": "completed",
            "stored_plaintext": False,
            "trigger": "manual",
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run.diagnostics.jsonl"
            path.write_text(
                json.dumps(legacy, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            applied = latest_diagnostic(path)
            path.write_text(
                json.dumps({**legacy, "applied": 0}, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            untouched = latest_diagnostic(path)

        assert applied is not None and untouched is not None
        self.assertEqual(applied["phase"], "completed")
        self.assertEqual(applied["mailbox_outcome"], "changed")
        self.assertEqual(untouched["phase"], "completed")
        self.assertEqual(untouched["mailbox_outcome"], "unchanged")

    def test_reader_rejects_an_unknown_phase_or_outcome(self) -> None:
        for field, value in (("phase", "elsewhere"), ("mailbox_outcome", "maybe")):
            with self.subTest(field=field):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "run.diagnostics.jsonl"
                    append_diagnostic(path, _failure())
                    record = json.loads(path.read_text(encoding="utf-8").splitlines()[-1])
                    record[field] = value
                    path.write_text(
                        json.dumps(record, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                    with self.assertRaises(ValueError):
                        latest_diagnostic(path)

    def test_completed_status_cannot_claim_an_interrupted_phase(self) -> None:
        with self.assertRaises(ValueError):
            _failure(status="completed", phase="mailbox_actions")


if __name__ == "__main__":
    unittest.main()
