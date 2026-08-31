from __future__ import annotations

import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from inboxlume.diagnostics import (
    append_diagnostic,
    diagnostic_for_terminal_status,
    latest_diagnostic,
)


class DiagnosticTests(unittest.TestCase):
    def test_concurrent_aggregate_appends_do_not_lose_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run.diagnostics.jsonl"

            def write(index: int) -> None:
                append_diagnostic(
                    path,
                    diagnostic_for_terminal_status(
                        status="failed",
                        trigger="manual",
                        provider="gmail",
                        destination="quarantine",
                        scan_profile="synthetic-profile",
                        governor_requested=False,
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
                diagnostic_for_terminal_status(
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


if __name__ == "__main__":
    unittest.main()
