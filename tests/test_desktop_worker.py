from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from inboxlume.diagnostics import diagnostic_path, latest_diagnostic
from inboxlume.desktop_worker import (
    build_parser,
    execute_scan,
    execute_shadow_review,
    execute_threat_backtest,
    main,
)
from inboxlume.threat_signals import (
    SemanticThreatAssessment,
    SemanticThreatVerdict,
    ThreatIntent,
)


ROOT = Path(__file__).resolve().parents[1]


class FakeSecretStore:
    def __init__(self) -> None:
        self.values = {}

    def get(self, service, account):  # noqa: ANN001
        return self.values.get((service, account))

    def set(self, service, account, secret):  # noqa: ANN001
        self.values[(service, account)] = secret


class FakeThreatBackend:
    def __init__(self) -> None:
        self.unloaded = False

    def assess_threat_semantics(self, message):  # noqa: ANN001, ANN201
        malicious = message.message_id.startswith("threat-")
        return SemanticThreatAssessment(
            SemanticThreatVerdict.LIKELY_PHISHING if malicious else SemanticThreatVerdict.BENIGN,
            ThreatIntent.CREDENTIAL_THEFT if malicious else ThreatIntent.NONE,
            malicious,
            malicious,
            False,
            malicious,
            malicious,
            not malicious,
            0.95,
            ("credential_harvest_language",) if malicious else ("benign_context",),
            "synthetic-worker-test",
        )

    def unload(self) -> None:
        self.unloaded = True


class DesktopWorkerTests(unittest.TestCase):
    @staticmethod
    def _main_scan_arguments(state_db: Path) -> list[str]:
        return [
            "scan",
            "--config",
            str(ROOT / "config/accounts.example.json"),
            "--account",
            "gmail_secondo",
            "--provider",
            "gmail",
            "--state-db",
            str(state_db),
            "--unread-days",
            "15",
            "--otp-days",
            "4",
            "--confirm-read-bodies",
            "--limit",
            "3",
            "--search-limit",
            "0",
            "--scan-order",
            "oldest_first",
            "--destination",
            "quarantine",
            "--apply-safe-actions",
        ]

    def test_runtime_failure_receipt_is_actionable_and_privacy_safe(self) -> None:
        output = io.StringIO()

        def fail_before_mutation(args, stream):  # noqa: ANN001, ANN202, ARG001
            args._worker_stage = "classification"
            args._mailbox_mutation_started = False
            args._worker_processed = 0
            raise RuntimeError(
                "timeout del processo MLX locale: /private/sensitive/path"
            )

        with (
            tempfile.TemporaryDirectory() as directory,
            patch("inboxlume.desktop_worker.execute_scan", fail_before_mutation),
            patch("inboxlume.desktop_worker._record_terminal_scan_status"),
            patch("sys.stdout", output),
        ):
            exit_code = main(
                self._main_scan_arguments(Path(directory) / "state.sqlite3")
            )

        event = json.loads(output.getvalue())
        self.assertEqual(exit_code, 2)
        self.assertEqual(event["type"], "error")
        self.assertEqual(event["error_code"], "local_model_runtime")
        self.assertEqual(event["stage"], "classification")
        self.assertEqual(event["mailbox_outcome"], "unchanged")
        self.assertFalse(event["mailbox_changes_unknown"])
        self.assertNotIn("RuntimeError", output.getvalue())
        self.assertNotIn("sensitive", output.getvalue())

    def test_failure_after_mutation_boundary_requires_mailbox_review(self) -> None:
        output = io.StringIO()

        def fail_after_mutation(args, stream):  # noqa: ANN001, ANN202, ARG001
            args._worker_stage = "mailbox_actions"
            args._mailbox_mutation_started = True
            args._worker_processed = 2
            raise OSError("provider detail must stay private")

        with (
            tempfile.TemporaryDirectory() as directory,
            patch("inboxlume.desktop_worker.execute_scan", fail_after_mutation),
            patch("inboxlume.desktop_worker._record_terminal_scan_status"),
            patch("sys.stdout", output),
        ):
            exit_code = main(
                self._main_scan_arguments(Path(directory) / "state.sqlite3")
            )

        event = json.loads(output.getvalue())
        self.assertEqual(exit_code, 2)
        self.assertEqual(event["mailbox_outcome"], "unknown")
        self.assertTrue(event["mailbox_changes_unknown"])
        self.assertEqual(event["processed_before_stop"], 2)
        self.assertNotIn("provider detail", output.getvalue())

    def test_persisted_failure_record_states_where_the_scan_stopped(self) -> None:
        output = io.StringIO()

        def fail_after_mutation(args, stream):  # noqa: ANN001, ANN202, ARG001
            args._worker_stage = "mailbox_actions"
            args._mailbox_mutation_started = True
            args._worker_processed = 17
            raise OSError("provider detail must stay private")

        with (
            tempfile.TemporaryDirectory() as directory,
            patch("inboxlume.desktop_worker.execute_scan", fail_after_mutation),
            patch("sys.stdout", output),
        ):
            state_db = Path(directory) / "state.sqlite3"
            exit_code = main(self._main_scan_arguments(state_db))
            record = latest_diagnostic(diagnostic_path(state_db))

        self.assertEqual(exit_code, 2)
        assert record is not None
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["phase"], "mailbox_actions")
        self.assertEqual(record["processed"], 17)
        self.assertEqual(record["mailbox_outcome"], "unknown")

    def test_persisted_failure_record_clears_a_mailbox_never_touched(self) -> None:
        output = io.StringIO()

        def fail_before_mutation(args, stream):  # noqa: ANN001, ANN202, ARG001
            args._worker_stage = "threat_protection"
            args._mailbox_mutation_started = False
            args._worker_processed = 9
            raise RuntimeError("timeout del processo MLX locale")

        with (
            tempfile.TemporaryDirectory() as directory,
            patch("inboxlume.desktop_worker.execute_scan", fail_before_mutation),
            patch("sys.stdout", output),
        ):
            state_db = Path(directory) / "state.sqlite3"
            main(self._main_scan_arguments(state_db))
            record = latest_diagnostic(diagnostic_path(state_db))

        assert record is not None
        self.assertEqual(record["phase"], "threat_protection")
        self.assertEqual(record["processed"], 9)
        self.assertEqual(record["mailbox_outcome"], "unchanged")

    def test_threat_backtest_needs_no_account_and_streams_aggregate_progress(self) -> None:
        backend = FakeThreatBackend()
        args = build_parser().parse_args(
            ["threat-backtest", "--backend", "gemma26"]
        )
        output = io.StringIO()
        summary = execute_threat_backtest(
            args,
            output,
            backend_factory=lambda backend_name, model_name: (object(), backend),
        )
        events = [json.loads(line) for line in output.getvalue().splitlines()]

        self.assertEqual(events[0]["type"], "phase")
        self.assertEqual(events[-1]["type"], "local_threat_backtest")
        self.assertEqual(
            len([event for event in events if event["type"] == "progress"]),
            25,
        )
        self.assertTrue(summary["diagnostic_passed"])
        self.assertTrue(backend.unloaded)
        self.assertFalse(summary["reads_mailbox"])
        self.assertFalse(summary["changes_mailbox"])
        self.assertNotIn("Urgent: account suspended", output.getvalue())

    def _arguments(
        self,
        state_db: Path,
        *,
        apply: bool = True,
        governor: bool = False,
    ):  # noqa: ANN001
        values = [
            "scan",
            "--config",
            str(ROOT / "config/accounts.example.json"),
            "--account",
            "gmail_secondo",
            "--provider",
            "gmail",
            "--state-db",
            str(state_db),
            "--unread-days",
            "15",
            "--otp-days",
            "4",
            "--confirm-read-bodies",
            "--limit",
            "3",
            "--search-limit",
            "0",
            "--scan-order",
            "oldest_first",
            "--destination",
            "quarantine",
        ]
        if apply:
            values.append("--apply-safe-actions")
        if governor:
            values.append("--enforce-safety-governor")
        return build_parser().parse_args(values)

    def test_scan_uses_dynamic_account_policy_and_streams_aggregate_progress(self) -> None:
        captured = {}

        def fake_runner(**kwargs):  # noqa: ANN003, ANN202
            captured.update(kwargs)
            kwargs["progress"](1, kwargs["limit"])
            return {
                "type": "shadow_run_summary",
                "newly_processed": 1,
                "ledger": {"processed_total": 1},
                "automatic_quarantine": {
                    "applied": 0,
                    "destination": "quarantine",
                },
                "stored_plaintext": False,
            }

        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            summary = execute_scan(
                self._arguments(Path(directory) / "account" / "state.sqlite3"),
                output,
                secret_store=object(),
                gmail_runner=fake_runner,
            )

        events = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual([event["type"] for event in events], ["phase", "progress", "shadow_run_summary"])
        self.assertEqual(captured["policy_override"].account_id, "gmail_secondo")
        self.assertEqual(captured["policy_override"].unread_age_days, 15)
        self.assertEqual(captured["policy_override"].read_one_time_code_age_days, 4)
        self.assertTrue(captured["oldest_first"])
        self.assertTrue(captured["apply_quarantine_labels"])
        self.assertFalse(captured["governor_enforced"])
        self.assertFalse(summary["stored_plaintext"])
        self.assertGreaterEqual(summary["elapsed_seconds"], 0.0)
        self.assertNotIn("sender", output.getvalue())

    def test_scan_refuses_to_mutate_without_internal_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = self._arguments(Path(directory) / "state.sqlite3", apply=False)
            with self.assertRaisesRegex(ValueError, "conferma"):
                execute_scan(args, io.StringIO(), secret_store=object())

    def test_shadow_review_reads_only_existing_quarantine_proposals(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_db = Path(directory) / "state.sqlite3"
            args = build_parser().parse_args(
                [
                    "shadow-review",
                    "--config", str(ROOT / "config/accounts.example.json"),
                    "--account", "gmail_secondo",
                    "--provider", "gmail",
                    "--state-db", str(state_db),
                    "--unread-days", "15",
                    "--otp-days", "4",
                    "--confirm-read-bodies",
                    "--backend", "gemma26",
                    "--limit", "12",
                    "--search-limit", "500",
                ]
            )
            output = io.StringIO()
            with patch(
                "inboxlume.desktop_worker.run_shadow_review_bridge",
                return_value={"presented": 1, "stopped": False},
                ) as bridge:
                result = execute_shadow_review(
                    args, io.StringIO(), output, secret_store=FakeSecretStore()
                )

        self.assertEqual(result["presented"], 1)
        self.assertEqual(bridge.call_args.args[2:5], (12, 500, "gemma26-policy-v2"))
        events = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(events[0]["type"], "phase")
        self.assertNotIn("email", output.getvalue().casefold())

    def test_operational_governor_and_direct_trash_are_passed_independently(self) -> None:
        captured = {}

        def fake_runner(**kwargs):  # noqa: ANN003, ANN202
            captured.update(kwargs)
            return {
                "type": "shadow_run_summary",
                "newly_processed": 0,
                "automatic_quarantine": {"applied": 0},
                "safety_governor": {
                    "enforced": True,
                    "blocked_current_batch": 0,
                },
                "stored_plaintext": False,
            }

        with tempfile.TemporaryDirectory() as directory:
            args = self._arguments(
                Path(directory) / "state.sqlite3",
                governor=True,
            )
            execute_scan(
                args,
                io.StringIO(),
                secret_store=object(),
                gmail_runner=fake_runner,
            )
            self.assertTrue(captured["governor_enforced"])

            args.destination = "trash"
            args.enforce_safety_governor = False
            args.backend = "gemma26"
            with patch(
                "inboxlume.desktop_worker.calibration_answer_counts",
                return_value={"keep": 3, "dont_keep": 37, "unsure": 0},
            ):
                execute_scan(
                    args,
                    io.StringIO(),
                    secret_store=object(),
                    gmail_runner=fake_runner,
                )
            self.assertTrue(captured["direct_to_trash"])
            self.assertFalse(captured["governor_enforced"])

    def test_unlimited_scan_stops_after_the_first_incomplete_internal_batch(self) -> None:
        processed_per_call = [500, 17]
        calls = []

        def fake_runner(**kwargs):  # noqa: ANN003, ANN202
            current = processed_per_call[len(calls)]
            calls.append(kwargs)
            kwargs["progress"](current, kwargs["limit"])
            return {
                "type": "shadow_run_summary",
                "newly_processed": current,
                "run_categories": {"advertising": current},
                "run_content_assessments": {"discard_candidate": current},
                "run_suggested_actions": {"quarantine": current},
                "ledger": {"processed_total": sum(processed_per_call[: len(calls)])},
                "automatic_quarantine": {
                    "selected": current,
                    "applied": current,
                    "outcomes": {"applied": current},
                },
                "threat_protection": {
                    "assessed_current_batch": current,
                    "protective_reviews_current_batch": 1,
                    "semantic_inferences_requested_current_batch": 2,
                    "semantic_inferences_skipped_current_batch": current - 2,
                    "semantic_failures_current_batch": 0,
                    "current_levels": {"minimal": current - 1, "high": 1},
                    "current_intents": {"none": current},
                    "current_signals": {"brand_domain_mismatch": 1},
                    "ledger": {
                        "assessed_total": sum(processed_per_call[: len(calls)])
                    },
                },
                "proof_of_obsolescence": {
                    "verified_current_batch": 1,
                    "promoted_to_quarantine_current_batch": 1,
                    "confirmed_ordinary_current_batch": 0,
                    "withheld_from_direct_trash_current_batch": 0,
                    "current_witnesses": {"successor": 1},
                },
                "behavior_feedback": {
                    "status": "updated",
                    "new_signals": {"opened": 1},
                    "read_bodies": False,
                },
                "read_bodies": current > 0,
                "stored_plaintext": False,
                "changes_mailbox": current > 0,
            }

        with tempfile.TemporaryDirectory() as directory:
            args = self._arguments(Path(directory) / "state.sqlite3")
            args.limit = 0
            output = io.StringIO()
            summary = execute_scan(
                args,
                output,
                secret_store=object(),
                gmail_runner=fake_runner,
            )

        self.assertEqual(len(calls), 2)
        self.assertTrue(all(call["limit"] == 500 for call in calls))
        self.assertEqual(summary["newly_processed"], 517)
        self.assertEqual(summary["automatic_quarantine"]["applied"], 517)
        self.assertEqual(
            summary["threat_protection"]["assessed_current_batch"], 517
        )
        self.assertEqual(
            summary["threat_protection"]["protective_reviews_current_batch"], 2
        )
        self.assertEqual(
            summary["threat_protection"]["current_levels"],
            {"high": 2, "minimal": 515},
        )
        self.assertEqual(
            summary["threat_protection"][
                "semantic_inferences_requested_current_batch"
            ],
            4,
        )
        self.assertEqual(
            summary["proof_of_obsolescence"]["verified_current_batch"], 2
        )
        self.assertEqual(
            summary["proof_of_obsolescence"]["current_witnesses"],
            {"successor": 2},
        )
        self.assertEqual(summary["behavior_feedback"]["new_signals"], {"opened": 2})
        self.assertTrue(summary["exhausted"])
        progress_events = [
            json.loads(line)
            for line in output.getvalue().splitlines()
            if json.loads(line).get("type") == "progress"
        ]
        self.assertEqual(
            [(event["processed"], event["limit"]) for event in progress_events],
            [(500, 0), (517, 0)],
        )

    def test_direct_trash_is_blocked_by_worker_until_calibration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = self._arguments(Path(directory) / "state.sqlite3")
            args.destination = "trash"
            args.backend = "gemma26"
            with self.assertRaisesRegex(ValueError, "calibrazione"):
                execute_scan(
                    args,
                    io.StringIO(),
                    secret_store=FakeSecretStore(),
                )

    def test_qualified_direct_trash_request_reaches_provider_with_governor(self) -> None:
        captured = {}

        def fake_runner(**kwargs):  # noqa: ANN003, ANN202
            captured.update(kwargs)
            return {
                "type": "shadow_run_summary",
                "newly_processed": 0,
                "automatic_quarantine": {
                    "applied": 0,
                    "destination": "trash",
                },
                "safety_governor": {
                    "enforced": True,
                    "blocked_current_batch": 0,
                },
                "stored_plaintext": False,
            }

        with tempfile.TemporaryDirectory() as directory:
            args = self._arguments(
                Path(directory) / "state.sqlite3",
                governor=True,
            )
            args.destination = "trash"
            args.backend = "gemma26"
            with patch(
                "inboxlume.desktop_worker.calibration_answer_counts",
                return_value={"keep": 3, "dont_keep": 37, "unsure": 0},
            ):
                execute_scan(
                    args,
                    io.StringIO(),
                    secret_store=FakeSecretStore(),
                    gmail_runner=fake_runner,
                )

        self.assertTrue(captured["direct_to_trash"])
        self.assertTrue(captured["governor_enforced"])
        self.assertEqual(
            captured["policy_override"].quarantine_confidence,
            0.80,
        )

    def test_qwen_uses_stricter_policy_and_never_direct_trash(self) -> None:
        captured = {}

        def fake_runner(**kwargs):  # noqa: ANN003, ANN202
            captured.update(kwargs)
            return {
                "type": "shadow_run_summary",
                "newly_processed": 0,
                "automatic_quarantine": {"applied": 0},
                "stored_plaintext": False,
            }

        with tempfile.TemporaryDirectory() as directory:
            args = self._arguments(Path(directory) / "state.sqlite3")
            args.backend = "ollama"
            execute_scan(
                args,
                io.StringIO(),
                secret_store=object(),
                gmail_runner=fake_runner,
            )
            self.assertEqual(
                captured["policy_override"].quarantine_confidence,
                0.90,
            )

            args.destination = "trash"
            args.enforce_safety_governor = True
            with self.assertRaisesRegex(ValueError, "solo la Quarantena"):
                execute_scan(
                    args,
                    io.StringIO(),
                    secret_store=object(),
                    gmail_runner=fake_runner,
                )


if __name__ == "__main__":
    unittest.main()
