from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from inboxlume.models import ProviderKind
from inboxlume.local_models import LocalModelProfile
from inboxlume.diagnostics import diagnostic_path, latest_diagnostic
from inboxlume.scheduled_run import (
    ScheduledRunLock,
    _record_scheduled_failure,
    main,
    run_scheduled_scan,
)
from inboxlume.settings import (
    AccountSettings,
    ApplicationSettings,
    ScheduleSettings,
    SettingsStore,
)


class ScheduledRunTests(unittest.TestCase):
    def test_disabled_schedule_fails_before_starting_the_model(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings_path = Path(directory) / "settings.json"
            SettingsStore(settings_path).save(
                ApplicationSettings(
                    (AccountSettings("gmail_test", ProviderKind.GMAIL),)
                )
            )
            called = False

            def executor(*args, **kwargs):  # noqa: ANN002, ANN003
                nonlocal called
                called = True
                return {}

            with self.assertRaisesRegex(RuntimeError, "disattivata"):
                run_scheduled_scan(
                    "gmail_test",
                    settings_path,
                    io.StringIO(),
                    executor=executor,
                )
            self.assertFalse(called)

    def test_enabled_schedule_uses_only_saved_account_rules(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings_path = Path(directory) / "settings.json"
            account = AccountSettings(
                "yahoo_test",
                ProviderKind.YAHOO,
                unread_age_days=18,
                batch_size=75,
                model_profile=LocalModelProfile.GEMMA12,
                safety_governor_enforced=True,
                schedule=ScheduleSettings(enabled=True, hour=3),
            )
            SettingsStore(settings_path).save(ApplicationSettings((account,)))
            captured = None

            def executor(args, output_stream):  # noqa: ANN001
                nonlocal captured
                captured = args
                return {"type": "shadow_run_summary", "changes_mailbox": False}

            output = io.StringIO()
            summary = run_scheduled_scan(
                "yahoo_test",
                settings_path,
                output,
                executor=executor,
                calibration_reader=lambda *_: {
                    "keep": 3,
                    "dont_keep": 30,
                    "unsure": 7,
                },
            )

            self.assertEqual(summary["type"], "shadow_run_summary")
            self.assertEqual(captured.provider, "yahoo")
            self.assertEqual(captured.limit, 75)
            self.assertEqual(captured.unread_days, 18)
            self.assertEqual(captured.backend, "gemma12")
            self.assertTrue(captured.confirm_read_bodies)
            self.assertTrue(captured.apply_safe_actions)
            self.assertTrue(captured.enforce_safety_governor)
            self.assertEqual(captured.search_limit, 0)
            self.assertTrue(captured.operation_lock_held)
            self.assertEqual(len(output.getvalue().splitlines()), 1)
            self.assertIn("scheduled_run_complete", output.getvalue())
            self.assertFalse((settings_path.parent / "runlocks/yahoo_test.lock").exists())

    def test_enabled_schedule_refuses_incomplete_calibration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings_path = Path(directory) / "settings.json"
            account = AccountSettings(
                "gmail_test",
                ProviderKind.GMAIL,
                schedule=ScheduleSettings(enabled=True),
            )
            SettingsStore(settings_path).save(ApplicationSettings((account,)))
            called = False

            def executor(*args, **kwargs):  # noqa: ANN002, ANN003
                nonlocal called
                called = True
                return {}

            with self.assertRaisesRegex(RuntimeError, "calibrazione iniziale"):
                run_scheduled_scan(
                    "gmail_test",
                    settings_path,
                    io.StringIO(),
                    executor=executor,
                    calibration_reader=lambda *_: {
                        "keep": 1,
                        "dont_keep": 20,
                        "unsure": 19,
                    },
                )
            self.assertFalse(called)

    def test_run_lock_rejects_overlap_and_keeps_a_stable_inode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "account.lock"
            with ScheduledRunLock(path):
                self.assertTrue(path.exists())
                with self.assertRaisesRegex(RuntimeError, "già in esecuzione"):
                    with ScheduledRunLock(path):
                        pass
            self.assertTrue(path.exists())

    def test_stale_lock_file_is_reused_safely_after_a_crash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "account.lock"
            path.write_text("stale-pid\n", encoding="utf-8")
            with ScheduledRunLock(path):
                self.assertTrue(path.exists())
            self.assertTrue(path.exists())

    def test_scheduled_failure_record_states_where_the_scan_stopped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings_path = Path(directory) / "settings.json"
            account = AccountSettings(
                "yahoo_test",
                ProviderKind.YAHOO,
                model_profile=LocalModelProfile.GEMMA12,
                schedule=ScheduleSettings(enabled=True, hour=3),
            )
            SettingsStore(settings_path).save(ApplicationSettings((account,)))
            started: list[object] = []

            def executor(args, output_stream):  # noqa: ANN001
                args._worker_stage = "mailbox_actions"
                args._mailbox_mutation_started = True
                args._worker_processed = 23
                raise OSError("provider detail must stay private")

            with self.assertRaises(OSError):
                run_scheduled_scan(
                    "yahoo_test",
                    settings_path,
                    io.StringIO(),
                    executor=executor,
                    calibration_reader=lambda *_: {
                        "keep": 3,
                        "dont_keep": 30,
                        "unsure": 7,
                    },
                    arguments_sink=started.append,
                )

            self.assertEqual(len(started), 1)
            _record_scheduled_failure("yahoo_test", settings_path, started[-1])
            state_db = settings_path.parent / "accounts/yahoo_test/preferences.sqlite3"
            record = latest_diagnostic(diagnostic_path(state_db))

        assert record is not None
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["trigger"], "scheduled")
        self.assertEqual(record["phase"], "mailbox_actions")
        self.assertEqual(record["processed"], 23)
        self.assertEqual(record["mailbox_outcome"], "unknown")

    def test_failure_before_the_scan_namespace_exists_clears_the_mailbox(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings_path = Path(directory) / "settings.json"
            account = AccountSettings(
                "yahoo_test",
                ProviderKind.YAHOO,
                model_profile=LocalModelProfile.GEMMA12,
                schedule=ScheduleSettings(enabled=True, hour=3),
            )
            SettingsStore(settings_path).save(ApplicationSettings((account,)))

            _record_scheduled_failure("yahoo_test", settings_path, None)
            state_db = settings_path.parent / "accounts/yahoo_test/preferences.sqlite3"
            record = latest_diagnostic(diagnostic_path(state_db))

        assert record is not None
        self.assertEqual(record["phase"], "startup")
        self.assertEqual(record["processed"], 0)
        self.assertEqual(record["mailbox_outcome"], "unchanged")

    def test_final_scheduler_boundary_never_prints_raw_exception_text(self) -> None:
        output = io.StringIO()
        with (
            patch(
                "inboxlume.scheduled_run.run_scheduled_scan",
                side_effect=RuntimeError(
                    "SYNTHETIC_PRIVATE_VALUE /Users/example/private"
                ),
            ),
            patch("inboxlume.scheduled_run._record_scheduled_failure"),
            redirect_stdout(output),
        ):
            status = main(
                [
                    "--account",
                    "gmail_test",
                    "--settings",
                    "/tmp/synthetic-settings.json",
                ]
            )

        self.assertEqual(status, 2)
        self.assertNotIn("SYNTHETIC_PRIVATE_VALUE", output.getvalue())
        self.assertNotIn("/Users/example/private", output.getvalue())
        self.assertIn("scheduled_run_failed", output.getvalue())

    def test_the_log_says_when_a_run_began_and_not_only_when_it_ended(self):
        output = io.StringIO()
        with (
            patch(
                "inboxlume.scheduled_run.run_scheduled_scan",
                side_effect=RuntimeError("synthetic"),
            ),
            patch("inboxlume.scheduled_run._record_scheduled_failure"),
            redirect_stdout(output),
        ):
            main(
                [
                    "--account",
                    "gmail_test",
                    "--settings",
                    "/tmp/synthetic-settings.json",
                ]
            )

        first, last = output.getvalue().strip().splitlines()
        # One line written at the end carries a timestamp that reads like a
        # start time, and a long run that fails late then looks like a run that
        # began late. Both ends have to be on the record.
        self.assertEqual(json.loads(first)["type"], "scheduled_run_started")
        self.assertIn("started_at", json.loads(first))
        self.assertEqual(json.loads(last)["type"], "scheduled_run_error")

    def test_a_running_scan_publishes_counts_for_the_window_to_read(self):
        from inboxlume.scheduled_run import ProgressJournal

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run.progress.json"
            ticks = iter([0.0, 10.0, 20.0, 30.0, 40.0])
            journal = ProgressJournal(path, clock=lambda: next(ticks))

            journal.write(
                '{"type":"phase","phase":"classification","message":"x"}\n'
            )
            journal.write('{"type":"progress","processed":13,"limit":200}\n')
            published = json.loads(path.read_text())

            # This is what the window shows while a run it did not start works.
            self.assertEqual(published["processed"], 13)
            self.assertEqual(published["limit"], 200)
            self.assertEqual(published["phase"], "classification")
            self.assertFalse(published["stored_plaintext"])

            journal.clear()
            self.assertFalse(path.exists())

    def test_the_journal_never_publishes_anything_from_a_message(self):
        from inboxlume.scheduled_run import ProgressJournal

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run.progress.json"
            journal = ProgressJournal(path, clock=lambda: 0.0)
            journal.write('{"type":"phase","phase":"classification"}\n')
            journal.write(
                '{"type":"candidate","subject":"SYNTHETIC_SUBJECT",'
                '"sender":"someone@example.com"}\n'
            )

            # A run publishes counts so it can be watched, and nothing else:
            # the file sits outside the encrypted ledger.
            written = path.read_text()
            self.assertNotIn("SYNTHETIC_SUBJECT", written)
            self.assertNotIn("example.com", written)

    def test_the_boundary_names_the_class_of_a_failure_it_will_not_quote(self):
        class SyntheticRefusal(ValueError):
            pass

        output = io.StringIO()
        with (
            patch(
                "inboxlume.scheduled_run.run_scheduled_scan",
                side_effect=SyntheticRefusal("SYNTHETIC_PRIVATE_VALUE"),
            ),
            patch("inboxlume.scheduled_run._record_scheduled_failure"),
            redirect_stdout(output),
        ):
            status = main(
                [
                    "--account",
                    "gmail_test",
                    "--settings",
                    "/tmp/synthetic-settings.json",
                ]
            )

        self.assertEqual(status, 2)
        record = json.loads(output.getvalue().strip().splitlines()[-1])
        # Nobody is watching a scheduled run, so the log is the only account of
        # it. The class name separates a setting the worker refused from a
        # mailbox it could not reach, which the shared message alone cannot.
        self.assertEqual(record["failure"], "SyntheticRefusal")
        self.assertNotIn("SYNTHETIC_PRIVATE_VALUE", output.getvalue())


if __name__ == "__main__":
    unittest.main()
