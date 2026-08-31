from __future__ import annotations

import plistlib
import tempfile
import unittest
from pathlib import Path
from typing import Sequence

from inboxlume.native_scheduler import (
    CommandResult,
    LinuxSystemdScheduler,
    MacOSLaunchdScheduler,
    ScheduleRequest,
    WindowsTaskScheduler,
    native_scheduler,
)
from inboxlume.settings import ScheduleFrequency, ScheduleSettings


class FakeRunner:
    def __init__(self, results: list[int] | None = None) -> None:
        self.results = list(results or [])
        self.calls: list[tuple[str, ...]] = []

    def run(self, arguments: Sequence[str]) -> CommandResult:
        self.calls.append(tuple(arguments))
        code = self.results.pop(0) if self.results else 0
        return CommandResult(code)


def request(
    root: Path,
    *,
    frequency: ScheduleFrequency = ScheduleFrequency.DAILY,
    weekday: int = 1,
    packaged_worker: bool = False,
) -> ScheduleRequest:
    return ScheduleRequest(
        "gmail_test",
        root / "settings.json",
        Path("/usr/bin/python3"),
        ScheduleSettings(
            enabled=True,
            hour=4,
            minute=15,
            frequency=frequency,
            weekday=weekday,
        ),
        packaged_worker=packaged_worker,
    )


class NativeSchedulerTests(unittest.TestCase):
    def test_launchd_job_is_one_shot_and_contains_only_the_fixed_entry_point(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = FakeRunner()
            scheduler = MacOSLaunchdScheduler(root / "LaunchAgents", runner, uid=501)

            status = scheduler.install(request(root))
            path = root / "LaunchAgents/local.inboxlume.schedule.gmail_test.plist"
            document = plistlib.loads(path.read_bytes())

            self.assertTrue(status.installed)
            self.assertFalse(document["RunAtLoad"])
            self.assertFalse(document["KeepAlive"])
            self.assertEqual(
                document["ProgramArguments"],
                [
                    "/usr/bin/python3",
                    "-m",
                    "inboxlume.scheduled_run",
                    "--account",
                    "gmail_test",
                    "--settings",
                    str(root / "settings.json"),
                ],
            )
            self.assertEqual(document["StartCalendarInterval"], {"Hour": 4, "Minute": 15})
            self.assertFalse(any("shell" in item for call in runner.calls for item in call))

            runner.results.extend((0, 1))
            scheduler.remove("gmail_test")
            self.assertFalse(path.exists())

    def test_launchd_weekdays_use_only_monday_through_friday(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scheduler = MacOSLaunchdScheduler(root, FakeRunner(), uid=501)
            scheduler.install(request(root, frequency=ScheduleFrequency.WEEKDAYS))
            document = plistlib.loads(
                (root / "local.inboxlume.schedule.gmail_test.plist").read_bytes()
            )
            self.assertEqual(
                [item["Weekday"] for item in document["StartCalendarInterval"]],
                [2, 3, 4, 5, 6],
            )

    def test_windows_task_runs_least_privilege_and_ignores_overlap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = FakeRunner([0, 0, 0, 0, 1])
            scheduler = WindowsTaskScheduler(root / "tasks", runner)

            scheduler.install(
                request(root, frequency=ScheduleFrequency.WEEKLY, weekday=7)
            )
            xml_path = root / "tasks/InboxLume-gmail_test.xml"
            xml = xml_path.read_bytes().decode("utf-16")

            self.assertIn("<RunLevel>LeastPrivilege</RunLevel>", xml)
            self.assertIn("<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>", xml)
            self.assertIn("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>", xml)
            self.assertIn("<Sunday />", xml)
            self.assertIn("inboxlume.scheduled_run", xml)
            self.assertNotIn("powershell", xml.casefold())
            self.assertIn("/Create", runner.calls[0])

            scheduler.remove("gmail_test")
            self.assertFalse(xml_path.exists())

    def test_systemd_timer_is_one_shot_hardened_and_has_no_shell(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = FakeRunner([0, 0, 0, 0, 1, 0])
            scheduler = LinuxSystemdScheduler(root / "systemd", runner)

            scheduler.install(
                request(root, frequency=ScheduleFrequency.WEEKLY, weekday=3)
            )
            service = (root / "systemd/inboxlume-gmail_test.service").read_text()
            timer = (root / "systemd/inboxlume-gmail_test.timer").read_text()

            self.assertIn("Type=oneshot", service)
            self.assertIn("NoNewPrivileges=true", service)
            self.assertIn("ProtectSystem=full", service)
            self.assertIn('"-m" "inboxlume.scheduled_run"', service)
            self.assertNotIn("/bin/sh", service)
            self.assertIn("OnCalendar=Wed *-*-* 04:15:00", timer)
            self.assertIn("Persistent=true", timer)

            scheduler.remove("gmail_test")
            self.assertFalse((root / "systemd/inboxlume-gmail_test.timer").exists())

    def test_packaged_schedule_dispatches_to_the_dedicated_worker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            worker = root / "InboxLumeWorker"
            packaged = ScheduleRequest(
                "gmail_test",
                root / "settings.json",
                worker,
                ScheduleSettings(enabled=True, hour=4, minute=15),
                packaged_worker=True,
            )
            self.assertEqual(
                packaged.program_arguments,
                (
                    str(worker),
                    "scheduled-run",
                    "--account",
                    "gmail_test",
                    "--settings",
                    str(root / "settings.json"),
                ),
            )

    def test_factory_selects_only_the_native_backend(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = root / "settings.json"
            self.assertIsInstance(
                native_scheduler(
                    settings,
                    system_name="Darwin",
                    home=root,
                    runner=FakeRunner(),
                    uid=501,
                ),
                MacOSLaunchdScheduler,
            )
            self.assertIsInstance(
                native_scheduler(
                    settings,
                    system_name="Windows",
                    home=root,
                    runner=FakeRunner(),
                ),
                WindowsTaskScheduler,
            )
            self.assertIsInstance(
                native_scheduler(
                    settings,
                    system_name="Linux",
                    home=root,
                    runner=FakeRunner(),
                ),
                LinuxSystemdScheduler,
            )


if __name__ == "__main__":
    unittest.main()
