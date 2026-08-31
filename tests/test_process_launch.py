from __future__ import annotations

import os
import unittest
from pathlib import Path

from inboxlume.process_launch import (
    desktop_worker_launch,
    packaged_worker_path,
    scheduled_worker_launch,
    source_python_path,
)


class ProcessLaunchTests(unittest.TestCase):
    def test_source_launch_preserves_virtualenv_path_without_resolving(self) -> None:
        executable = (
            r"C:\synthetic\venv\Scripts\python.exe"
            if os.name == "nt"
            else "/synthetic/venv/bin/python"
        )
        launch = desktop_worker_launch(
            ["-m", "inboxlume.desktop_worker", "scan", "--account", "test"],
            executable=executable,
            frozen=False,
        )
        self.assertEqual(launch.program, Path(executable))
        self.assertEqual(
            launch.arguments[:3],
            ("-m", "inboxlume.worker_launcher", "desktop-worker"),
        )
        scheduled, packaged = scheduled_worker_launch(
            executable=executable, frozen=False
        )
        self.assertEqual(scheduled, Path(executable))
        self.assertFalse(packaged)

    def test_frozen_gui_uses_a_sibling_worker_not_itself(self) -> None:
        gui = "/Applications/InboxLume.app/Contents/MacOS/InboxLume"
        launch = desktop_worker_launch(
            ["-m", "inboxlume.desktop_worker", "scan"],
            executable=gui,
            frozen=True,
        )
        self.assertEqual(
            launch.program,
            Path("/Applications/InboxLume.app/Contents/MacOS/InboxLumeWorker"),
        )
        self.assertNotEqual(launch.program, Path(gui))
        self.assertEqual(launch.arguments, ("desktop-worker", "scan"))
        scheduled, packaged = scheduled_worker_launch(
            executable=gui, frozen=True
        )
        self.assertEqual(scheduled, launch.program)
        self.assertTrue(packaged)

    def test_windows_worker_keeps_exe_suffix(self) -> None:
        self.assertEqual(
            packaged_worker_path(r"C:\Program Files\InboxLume\InboxLume.exe").name,
            "InboxLumeWorker.exe",
        )

    def test_rejects_arbitrary_worker_module(self) -> None:
        with self.assertRaises(ValueError):
            desktop_worker_launch(
                ["-m", "untrusted.module", "scan"],
                executable="/synthetic/python",
                frozen=False,
            )


if __name__ == "__main__":
    unittest.main()
