from __future__ import annotations

import os
import signal
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


DESKTOP_WORKER_MODULE = "inboxlume.desktop_worker"
WORKER_LAUNCHER_MODULE = "inboxlume.worker_launcher"
WORKER_EXECUTABLE_STEM = "InboxLumeWorker"


@dataclass(frozen=True, slots=True)
class ProcessLaunch:
    program: Path
    arguments: tuple[str, ...]


def is_frozen_application() -> bool:
    return bool(getattr(sys, "frozen", False))


def packaged_worker_path(executable: str | os.PathLike[str]) -> Path:
    """Return the worker installed next to the frozen GUI executable."""

    current = Path(executable)
    suffix = ".exe" if current.suffix.casefold() == ".exe" else ""
    return current.with_name(f"{WORKER_EXECUTABLE_STEM}{suffix}")


def source_python_path(executable: str | os.PathLike[str]) -> Path:
    """Keep a virtualenv interpreter path without dereferencing its symlink."""

    value = os.fspath(executable)
    return Path(value if os.path.isabs(value) else os.path.abspath(value))


def desktop_worker_launch(
    arguments: Sequence[str],
    *,
    executable: str | os.PathLike[str] | None = None,
    frozen: bool | None = None,
) -> ProcessLaunch:
    prefix = ("-m", DESKTOP_WORKER_MODULE)
    supplied = tuple(str(item) for item in arguments)
    if supplied[:2] != prefix:
        raise ValueError("comando worker desktop non valido")
    worker_arguments = ("desktop-worker", *supplied[2:])
    selected_executable = executable or sys.executable
    use_frozen = is_frozen_application() if frozen is None else frozen
    if use_frozen:
        return ProcessLaunch(
            packaged_worker_path(selected_executable),
            worker_arguments,
        )
    return ProcessLaunch(
        source_python_path(selected_executable),
        ("-m", WORKER_LAUNCHER_MODULE, *worker_arguments),
    )


def scheduled_worker_launch(
    *,
    executable: str | os.PathLike[str] | None = None,
    frozen: bool | None = None,
) -> tuple[Path, bool]:
    selected_executable = executable or sys.executable
    use_frozen = is_frozen_application() if frozen is None else frozen
    if use_frozen:
        return packaged_worker_path(selected_executable), True
    return source_python_path(selected_executable), False


def _posix_descendant_pids(root_pid: int) -> tuple[int, ...]:
    try:
        completed = subprocess.run(
            ["ps", "-axo", "pid=,ppid="],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=3,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ()
    if completed.returncode != 0:
        return ()
    children: dict[int, list[int]] = {}
    for line in completed.stdout.splitlines():
        fields = line.split()
        if len(fields) != 2 or not all(field.isdigit() for field in fields):
            continue
        pid, parent = (int(field) for field in fields)
        children.setdefault(parent, []).append(pid)
    descendants: list[int] = []
    pending = list(children.get(root_pid, ()))
    while pending:
        pid = pending.pop()
        descendants.append(pid)
        pending.extend(children.get(pid, ()))
    return tuple(reversed(descendants))


def terminate_process_tree(process_id: int, *, force: bool = False) -> bool:
    """Signal a worker process group without invoking a shell.

    The worker launcher creates a new POSIX session.  Windows uses the native
    task-tree command because QProcess does not expose Job Objects uniformly.
    False means that the caller should fall back to QProcess.terminate/kill.
    """

    if not isinstance(process_id, int) or isinstance(process_id, bool) or process_id <= 0:
        return False
    if os.name == "posix":
        selected_signal = signal.SIGKILL if force else signal.SIGTERM
        for descendant in _posix_descendant_pids(process_id):
            try:
                os.killpg(descendant, selected_signal)
            except (OSError, ProcessLookupError):
                try:
                    os.kill(descendant, selected_signal)
                except (OSError, ProcessLookupError):
                    pass
        try:
            os.killpg(process_id, selected_signal)
        except (OSError, ProcessLookupError):
            return False
        return True
    if os.name == "nt":  # pragma: no cover - exercised on Windows
        command = ["taskkill.exe", "/PID", str(process_id), "/T"]
        if force:
            command.append("/F")
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=5,
                creationflags=creationflags,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return completed.returncode == 0
    return False
