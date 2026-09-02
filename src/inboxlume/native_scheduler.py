from __future__ import annotations

import os
import platform
import plistlib
import re
import subprocess
import tempfile
import getpass
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Sequence
from xml.sax.saxutils import escape

from .settings import ScheduleFrequency, ScheduleSettings


_ACCOUNT_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")
_WEEKDAY_NAMES = {
    1: "Mon",
    2: "Tue",
    3: "Wed",
    4: "Thu",
    5: "Fri",
    6: "Sat",
    7: "Sun",
}


class SchedulerError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class CommandRunner(Protocol):
    def run(self, arguments: Sequence[str]) -> CommandResult: ...


class SubprocessCommandRunner:
    """Esegue solo vettori di argomenti predefiniti; non usa mai una shell."""

    def run(self, arguments: Sequence[str]) -> CommandResult:
        try:
            completed = subprocess.run(
                list(arguments),
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
        except FileNotFoundError:
            return CommandResult(127)
        except subprocess.TimeoutExpired:
            return CommandResult(124)
        return CommandResult(completed.returncode, completed.stdout, completed.stderr)


@dataclass(frozen=True, slots=True)
class ScheduleRequest:
    account_id: str
    settings_path: Path
    python_executable: Path
    schedule: ScheduleSettings
    packaged_worker: bool = False
    source_root: Path | None = None

    def __post_init__(self) -> None:
        if _ACCOUNT_ID.fullmatch(self.account_id) is None:
            raise ValueError("account pianificazione non valido")
        if not self.settings_path.is_absolute():
            raise ValueError("il percorso impostazioni deve essere assoluto")
        if not self.python_executable.is_absolute():
            raise ValueError("il percorso Python deve essere assoluto")
        if not self.schedule.enabled:
            raise ValueError("la pianificazione deve essere abilitata prima di installarla")
        if not isinstance(self.packaged_worker, bool):
            raise ValueError("modalità worker pianificato non valida")
        if self.source_root is not None and not self.source_root.is_absolute():
            raise ValueError("il percorso dei sorgenti deve essere assoluto")

    @property
    def environment(self) -> dict[str, str]:
        """Environment the scheduled job needs to start on its own.

        A source checkout is reachable through a .pth file that a syncing
        folder can mark hidden, and Python then silently ignores it. Naming the
        source root here keeps the job independent of that file. A packaged
        worker carries its own modules and must not receive it.
        """

        environment = {"HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1"}
        if self.source_root is not None and not self.packaged_worker:
            environment["PYTHONPATH"] = str(self.source_root)
        return environment

    @property
    def log_path(self) -> Path:
        """Where a scheduled failure can be read afterwards.

        The scheduled run prints aggregate JSON only, so this never receives
        message text; without it a failure before that point leaves no trace.
        """

        return (
            self.settings_path.parent
            / "logs"
            / f"schedule-{self.account_id}.log"
        )

    @property
    def program_arguments(self) -> tuple[str, ...]:
        if self.packaged_worker:
            return (
                str(self.python_executable),
                "scheduled-run",
                "--account",
                self.account_id,
                "--settings",
                str(self.settings_path),
            )
        return (
            str(self.python_executable),
            "-m",
            "inboxlume.scheduled_run",
            "--account",
            self.account_id,
            "--settings",
            str(self.settings_path),
        )


@dataclass(frozen=True, slots=True)
class ScheduleStatus:
    backend: str
    installed: bool
    detail: str


class NativeScheduleBackend(Protocol):
    name: str

    def status(self, account_id: str) -> ScheduleStatus: ...

    def install(self, request: ScheduleRequest) -> ScheduleStatus: ...

    def remove(self, account_id: str) -> ScheduleStatus: ...


def _validate_account_id(account_id: str) -> None:
    if _ACCOUNT_ID.fullmatch(account_id) is None:
        raise ValueError("account pianificazione non valido")


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise SchedulerError("il file di pianificazione non può essere un collegamento")
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        if os.name == "posix":
            temporary_path.chmod(0o600)
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _require(result: CommandResult, action: str) -> None:
    if result.returncode != 0:
        raise SchedulerError(f"{action} non riuscita (codice {result.returncode})")


def _launchd_calendar(schedule: ScheduleSettings) -> dict | list[dict]:
    base = {"Hour": schedule.hour, "Minute": schedule.minute}
    if schedule.frequency is ScheduleFrequency.DAILY:
        return base
    iso_days = (
        range(1, 6)
        if schedule.frequency is ScheduleFrequency.WEEKDAYS
        else (schedule.weekday,)
    )
    # launchd: 1=domingo, 2=lunedi ... 7=sabato.
    return [
        {**base, "Weekday": 1 if iso_day == 7 else iso_day + 1}
        for iso_day in iso_days
    ]


class MacOSLaunchdScheduler:
    name = "launchd"

    def __init__(
        self,
        directory: Path,
        runner: CommandRunner | None = None,
        *,
        uid: int | None = None,
    ) -> None:
        self.directory = directory
        self.runner = runner or SubprocessCommandRunner()
        self.uid = os.getuid() if uid is None else uid

    @staticmethod
    def _label(account_id: str) -> str:
        _validate_account_id(account_id)
        return f"local.inboxlume.schedule.{account_id}"

    def _path(self, account_id: str) -> Path:
        return self.directory / f"{self._label(account_id)}.plist"

    def status(self, account_id: str) -> ScheduleStatus:
        label = self._label(account_id)
        path = self._path(account_id)
        result = self.runner.run(
            ("launchctl", "print", f"gui/{self.uid}/{label}")
        )
        installed = path.is_file() and result.returncode == 0
        detail = (
            "Pianificazione launchd attiva"
            if installed
            else "Pianificazione launchd non installata"
        )
        if result.returncode == 127:
            detail = "launchd non disponibile su questo sistema"
        return ScheduleStatus(self.name, installed, detail)

    def install(self, request: ScheduleRequest) -> ScheduleStatus:
        label = self._label(request.account_id)
        path = self._path(request.account_id)
        document = {
            "Label": label,
            "ProgramArguments": list(request.program_arguments),
            "StartCalendarInterval": _launchd_calendar(request.schedule),
            "RunAtLoad": False,
            "KeepAlive": False,
            "ProcessType": "Background",
            "LowPriorityIO": True,
            "Nice": 10,
            "StandardOutPath": str(request.log_path),
            "StandardErrorPath": str(request.log_path),
            "EnvironmentVariables": request.environment,
        }
        request.log_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _atomic_write(path, plistlib.dumps(document, sort_keys=True))
        domain = f"gui/{self.uid}"
        self.runner.run(("launchctl", "bootout", domain, str(path)))
        try:
            _require(
                self.runner.run(("launchctl", "bootstrap", domain, str(path))),
                "installazione launchd",
            )
            _require(
                self.runner.run(("launchctl", "enable", f"{domain}/{label}")),
                "attivazione launchd",
            )
            _require(
                self.runner.run(("launchctl", "print", f"{domain}/{label}")),
                "verifica launchd",
            )
        except SchedulerError:
            self.runner.run(("launchctl", "bootout", domain, str(path)))
            path.unlink(missing_ok=True)
            raise
        return ScheduleStatus(self.name, True, "Pianificazione launchd attiva")

    def remove(self, account_id: str) -> ScheduleStatus:
        path = self._path(account_id)
        if path.is_symlink():
            raise SchedulerError("file launchd inatteso: rimozione interrotta")
        label = self._label(account_id)
        domain = f"gui/{self.uid}"
        self.runner.run(("launchctl", "bootout", domain, str(path)))
        verification = self.runner.run(
            ("launchctl", "print", f"{domain}/{label}")
        )
        if verification.returncode == 0:
            raise SchedulerError("launchd non ha confermato la rimozione")
        path.unlink(missing_ok=True)
        return ScheduleStatus(self.name, False, "Pianificazione launchd rimossa")


def _windows_days(schedule: ScheduleSettings) -> str:
    if schedule.frequency is ScheduleFrequency.WEEKDAYS:
        return "".join(
            f"<{name} />" for name in ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday")
        )
    day = {
        1: "Monday",
        2: "Tuesday",
        3: "Wednesday",
        4: "Thursday",
        5: "Friday",
        6: "Saturday",
        7: "Sunday",
    }[schedule.weekday]
    return f"<{day} />"


def _windows_task_xml(request: ScheduleRequest, user_name: str) -> bytes:
    time = f"{request.schedule.hour:02d}:{request.schedule.minute:02d}:00"
    if request.schedule.frequency is ScheduleFrequency.DAILY:
        trigger = (
            "<CalendarTrigger><StartBoundary>2000-01-01T"
            f"{time}</StartBoundary><Enabled>true</Enabled>"
            "<ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>"
            "</CalendarTrigger>"
        )
    else:
        trigger = (
            "<CalendarTrigger><StartBoundary>2000-01-03T"
            f"{time}</StartBoundary><Enabled>true</Enabled>"
            "<ScheduleByWeek><DaysOfWeek>"
            f"{_windows_days(request.schedule)}</DaysOfWeek>"
            "<WeeksInterval>1</WeeksInterval></ScheduleByWeek>"
            "</CalendarTrigger>"
        )
    arguments = subprocess.list2cmdline(list(request.program_arguments[1:]))
    command = escape(str(request.python_executable))
    arguments_xml = escape(arguments)
    xml = (
        '<?xml version="1.0" encoding="UTF-16"?>'
        '<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
        "<RegistrationInfo><Author>InboxLume</Author></RegistrationInfo>"
        f"<Triggers>{trigger}</Triggers>"
        "<Principals><Principal id=\"Author\">"
        f"<UserId>{escape(user_name)}</UserId><LogonType>InteractiveToken</LogonType>"
        "<RunLevel>LeastPrivilege</RunLevel></Principal></Principals>"
        "<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
        "<StartWhenAvailable>true</StartWhenAvailable><WakeToRun>false</WakeToRun>"
        "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Enabled>true</Enabled></Settings>"
        f"<Actions Context=\"Author\"><Exec><Command>{command}</Command>"
        f"<Arguments>{arguments_xml}</Arguments></Exec></Actions></Task>"
    )
    return xml.encode("utf-16")


class WindowsTaskScheduler:
    name = "Windows Task Scheduler"

    def __init__(
        self,
        directory: Path,
        runner: CommandRunner | None = None,
        *,
        user_name: str | None = None,
    ) -> None:
        self.directory = directory
        self.runner = runner or SubprocessCommandRunner()
        self.user_name = user_name or getpass.getuser()

    @staticmethod
    def _task_name(account_id: str) -> str:
        _validate_account_id(account_id)
        return f"InboxLume-{account_id}"

    def _path(self, account_id: str) -> Path:
        return self.directory / f"{self._task_name(account_id)}.xml"

    def status(self, account_id: str) -> ScheduleStatus:
        name = self._task_name(account_id)
        result = self.runner.run(("schtasks.exe", "/Query", "/TN", name))
        installed = result.returncode == 0
        detail = (
            "Attività Windows attiva"
            if installed
            else "Attività Windows non installata"
        )
        if result.returncode == 127:
            detail = "Utilità di pianificazione Windows non disponibile"
        return ScheduleStatus(self.name, installed, detail)

    def install(self, request: ScheduleRequest) -> ScheduleStatus:
        name = self._task_name(request.account_id)
        path = self._path(request.account_id)
        _atomic_write(path, _windows_task_xml(request, self.user_name))
        try:
            _require(
                self.runner.run(
                    (
                        "schtasks.exe",
                        "/Create",
                        "/TN",
                        name,
                        "/XML",
                        str(path),
                        "/F",
                    )
                ),
                "installazione attività Windows",
            )
            _require(
                self.runner.run(("schtasks.exe", "/Query", "/TN", name)),
                "verifica attività Windows",
            )
        except SchedulerError:
            path.unlink(missing_ok=True)
            raise
        return ScheduleStatus(self.name, True, "Attività Windows attiva")

    def remove(self, account_id: str) -> ScheduleStatus:
        name = self._task_name(account_id)
        if self.status(account_id).installed:
            _require(
                self.runner.run(("schtasks.exe", "/Delete", "/TN", name, "/F")),
                "rimozione attività Windows",
            )
            if self.status(account_id).installed:
                raise SchedulerError("Windows non ha confermato la rimozione")
        path = self._path(account_id)
        if path.is_symlink():
            raise SchedulerError("file attività Windows inatteso: rimozione interrotta")
        path.unlink(missing_ok=True)
        return ScheduleStatus(self.name, False, "Attività Windows rimossa")


def _systemd_quote(value: str) -> str:
    escaped = value.replace("%", "%%").replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _systemd_calendar(schedule: ScheduleSettings) -> str:
    time = f"{schedule.hour:02d}:{schedule.minute:02d}:00"
    if schedule.frequency is ScheduleFrequency.DAILY:
        return f"*-*-* {time}"
    if schedule.frequency is ScheduleFrequency.WEEKDAYS:
        return f"Mon..Fri *-*-* {time}"
    return f"{_WEEKDAY_NAMES[schedule.weekday]} *-*-* {time}"


class LinuxSystemdScheduler:
    name = "systemd --user"

    def __init__(self, directory: Path, runner: CommandRunner | None = None) -> None:
        self.directory = directory
        self.runner = runner or SubprocessCommandRunner()

    @staticmethod
    def _unit_stem(account_id: str) -> str:
        _validate_account_id(account_id)
        return f"inboxlume-{account_id}"

    def _paths(self, account_id: str) -> tuple[Path, Path]:
        stem = self._unit_stem(account_id)
        return self.directory / f"{stem}.service", self.directory / f"{stem}.timer"

    def status(self, account_id: str) -> ScheduleStatus:
        _, timer = self._paths(account_id)
        result = self.runner.run(
            ("systemctl", "--user", "is-enabled", timer.name)
        )
        installed = timer.is_file() and result.returncode == 0
        detail = (
            "Timer systemd utente attivo"
            if installed
            else "Timer systemd utente non installato"
        )
        if result.returncode == 127:
            detail = "systemd utente non disponibile su questo sistema"
        return ScheduleStatus(self.name, installed, detail)

    def install(self, request: ScheduleRequest) -> ScheduleStatus:
        service, timer = self._paths(request.account_id)
        command = " ".join(_systemd_quote(item) for item in request.program_arguments)
        service_text = (
            "[Unit]\n"
            f"Description=InboxLume one-shot scan for {request.account_id}\n\n"
            "[Service]\nType=oneshot\n"
            f"ExecStart={command}\n"
            + "".join(
                f"Environment={name}={_systemd_quote(value)}\n"
                for name, value in sorted(request.environment.items())
            )
            + 
            "NoNewPrivileges=true\nPrivateTmp=true\nPrivateDevices=true\n"
            "ProtectSystem=full\nRestrictSUIDSGID=true\nLockPersonality=true\n"
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n"
        )
        timer_text = (
            "[Unit]\n"
            f"Description=InboxLume schedule for {request.account_id}\n\n"
            "[Timer]\n"
            f"OnCalendar={_systemd_calendar(request.schedule)}\n"
            "Persistent=true\nAccuracySec=1min\nRandomizedDelaySec=0\n\n"
            "[Install]\nWantedBy=timers.target\n"
        )
        _atomic_write(service, service_text.encode("utf-8"))
        _atomic_write(timer, timer_text.encode("utf-8"))
        try:
            _require(
                self.runner.run(("systemctl", "--user", "daemon-reload")),
                "ricaricamento systemd utente",
            )
            _require(
                self.runner.run(
                    ("systemctl", "--user", "enable", "--now", timer.name)
                ),
                "attivazione timer systemd utente",
            )
            _require(
                self.runner.run(("systemctl", "--user", "is-enabled", timer.name)),
                "verifica timer systemd utente",
            )
        except SchedulerError:
            self.runner.run(("systemctl", "--user", "disable", "--now", timer.name))
            service.unlink(missing_ok=True)
            timer.unlink(missing_ok=True)
            self.runner.run(("systemctl", "--user", "daemon-reload"))
            raise
        return ScheduleStatus(self.name, True, "Timer systemd utente attivo")

    def remove(self, account_id: str) -> ScheduleStatus:
        service, timer = self._paths(account_id)
        self.runner.run(("systemctl", "--user", "disable", "--now", timer.name))
        verification = self.runner.run(
            ("systemctl", "--user", "is-enabled", timer.name)
        )
        if verification.returncode == 0:
            raise SchedulerError("systemd non ha confermato la rimozione")
        for path in (service, timer):
            if path.is_symlink():
                raise SchedulerError("unità systemd inattesa: rimozione interrotta")
            path.unlink(missing_ok=True)
        _require(
            self.runner.run(("systemctl", "--user", "daemon-reload")),
            "ricaricamento systemd utente",
        )
        return ScheduleStatus(self.name, False, "Timer systemd utente rimosso")


def native_scheduler(
    settings_path: Path,
    *,
    system_name: str | None = None,
    home: Path | None = None,
    runner: CommandRunner | None = None,
    uid: int | None = None,
) -> NativeScheduleBackend:
    current_system = system_name or platform.system()
    user_home = home or Path.home()
    if current_system == "Darwin":
        return MacOSLaunchdScheduler(
            user_home / "Library" / "LaunchAgents",
            runner,
            uid=uid,
        )
    if current_system == "Windows":
        return WindowsTaskScheduler(
            settings_path.parent / "schedules" / "windows",
            runner,
        )
    if current_system == "Linux":
        return LinuxSystemdScheduler(
            user_home / ".config" / "systemd" / "user",
            runner,
        )
    raise SchedulerError(f"pianificazione non supportata su {current_system}")
