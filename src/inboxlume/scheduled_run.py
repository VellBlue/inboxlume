from __future__ import annotations

import argparse
import io
import json
import sys
import time
from argparse import Namespace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, TextIO

from .credential_store import SystemCredentialStore
from .desktop_worker import execute_scan, terminal_scan_receipt
from .diagnostics import (
    append_diagnostic,
    diagnostic_for_terminal_status,
    diagnostic_path,
)
from .local_models import model_spec, scan_profile_for_model
from .operation_lock import (
    AccountOperationLock,
    account_operation_lock_path,
    account_progress_path,
)
from .runtime import (
    calibration_answer_counts,
    default_runtime_config_path,
    state_database_path,
)
from .settings import (
    RECOMMENDED_INITIAL_DONT_KEEP_ANSWERS,
    RECOMMENDED_INITIAL_KEEP_ANSWERS,
    RECOMMENDED_INITIAL_QUIZ_ANSWERS,
    SettingsStore,
)


ScheduledRunLock = AccountOperationLock


class ProgressJournal(io.StringIO):
    """Publish a scheduled run's aggregate progress for the window to read.

    A scan started from the window streams its events to the window, which is
    how the interactive counter is drawn. A scheduled run had nowhere to stream
    to, so the app showed cumulative totals under the word "completed" while a
    run had been going for hours, and there was no way to tell one state from
    the other. Only counts and the phase name are published: the same aggregate
    the diagnostics already keep, never a subject, sender or message id.
    """

    MINIMUM_INTERVAL_SECONDS = 1.0

    def __init__(self, path: Path, *, clock: Callable[[], float] = time.monotonic):
        super().__init__()
        self.path = path
        self._clock = clock
        self._published_at: float | None = None
        self._state: dict[str, Any] = {"phase": "startup", "processed": 0, "limit": 0}

    def write(self, text: str) -> int:
        for line in text.splitlines():
            self._absorb(line)
        return super().write(text)

    def _absorb(self, line: str) -> None:
        try:
            event = json.loads(line)
        except (TypeError, ValueError):
            return
        if not isinstance(event, Mapping):
            return
        kind = event.get("type")
        if kind == "phase":
            self._state["phase"] = str(event.get("phase", "unspecified"))
        elif kind == "progress":
            self._state["processed"] = int(event.get("processed", 0))
            self._state["limit"] = int(event.get("limit", 0))
        else:
            return
        self._publish(final=kind == "phase")

    def _publish(self, *, final: bool) -> None:
        now = self._clock()
        if (
            not final
            and self._published_at is not None
            and now - self._published_at < self.MINIMUM_INTERVAL_SECONDS
        ):
            # One file write per message would cost more than the work it
            # reports on; a phase change is rare enough to always go out.
            return
        self._published_at = now
        record = dict(self._state)
        record["updated_at"] = datetime.now(timezone.utc).isoformat()
        record["stored_plaintext"] = False
        temporary = self.path.with_name(f"{self.path.name}.partial")
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            temporary.write_text(
                json.dumps(record, ensure_ascii=False, separators=(",", ":")),
                encoding="utf-8",
            )
            # A reader must never catch a half-written file.
            temporary.replace(self.path)
        except OSError:
            # Progress reporting must never be able to fail a run.
            pass

    def clear(self) -> None:
        try:
            self.path.unlink()
        except OSError:
            pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="inboxlume-scheduled",
        description="Esecuzione one-shot sicura creata dalla pianificazione nativa.",
    )
    parser.add_argument("--account", required=True)
    parser.add_argument("--settings", type=Path, required=True)
    return parser


def run_scheduled_scan(
    account_id: str,
    settings_path: Path,
    output_stream: TextIO,
    *,
    executor: Callable[..., dict[str, Any]] = execute_scan,
    calibration_reader: Callable[[Path, str], Mapping[str, int]] | None = None,
    arguments_sink: Callable[[Namespace], None] | None = None,
) -> dict[str, Any]:
    if not settings_path.is_absolute():
        raise ValueError("il percorso impostazioni pianificate deve essere assoluto")
    store = SettingsStore(settings_path)
    settings = store.load()
    account = settings.account(account_id)
    if not account.schedule.enabled:
        raise RuntimeError("la pianificazione di questo account è disattivata")

    project_root = Path(__file__).resolve().parents[2]
    config_path = default_runtime_config_path(project_root)
    state_db = state_database_path(settings_path, project_root, account)
    if calibration_reader is None:
        credential_store = SystemCredentialStore()

        def calibration_reader(path: Path, selected_account: str) -> Mapping[str, int]:
            return calibration_answer_counts(
                path,
                selected_account,
                credential_store,
            )

    calibration = calibration_reader(state_db, account.account_id)
    total = sum(calibration.values())
    if not (
        total >= RECOMMENDED_INITIAL_QUIZ_ANSWERS
        and calibration.get("keep", 0) >= RECOMMENDED_INITIAL_KEEP_ANSWERS
        and calibration.get("dont_keep", 0)
        >= RECOMMENDED_INITIAL_DONT_KEEP_ANSWERS
    ):
        raise RuntimeError(
            "un controllo pianificato richiede la calibrazione iniziale completa"
        )
    lock_path = account_operation_lock_path(state_db, account.account_id)
    selected_model = model_spec(account.model_profile)
    arguments = Namespace(
        command="scan",
        config=config_path,
        account=account.account_id,
        provider=account.provider.value,
        state_db=state_db,
        unread_days=account.unread_age_days,
        otp_days=account.read_one_time_code_age_days,
        confirm_read_bodies=True,
        backend=selected_model.backend,
        ollama_model=selected_model.ollama_model,
        limit=account.batch_size,
        search_limit=0,
        scan_order=account.scan_order.value,
        destination=account.destination.value,
        apply_safe_actions=True,
        enforce_safety_governor=account.safety_governor_enforced,
        skip_threat_protection=not account.threat_protection_enabled,
        threat_semantic_mode=account.threat_semantic_mode.value,
        skip_lumegraph=not account.lumegraph_enabled,
        skip_obsolescence_proof=not account.obsolescence_proof_enabled,
        trigger="scheduled",
        operation_lock_held=True,
    )
    # The scan annotates this namespace as it advances, so handing it to the
    # caller before the run starts lets a later failure record the phase and
    # mailbox outcome actually reached instead of a default.
    if arguments_sink is not None:
        arguments_sink(arguments)
    journal = ProgressJournal(account_progress_path(state_db, account.account_id))
    with ScheduledRunLock(lock_path):
        # Per-message detail still never reaches journald or a task log. The
        # journal publishes only counts and the phase name, for the window to
        # show while the run it did not start is going on.
        try:
            summary = executor(arguments, journal)
        finally:
            journal.clear()
    automatic = summary.get("automatic_quarantine")
    actions = automatic if isinstance(automatic, Mapping) else {}
    output_stream.write(
        json.dumps(
            {
                "type": "scheduled_run_complete",
                "processed": int(summary.get("newly_processed", 0)),
                "applied": int(actions.get("applied", 0)),
                "changes_mailbox": bool(summary.get("changes_mailbox", False)),
                "stored_plaintext": False,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
        + "\n"
    )
    output_stream.flush()
    return summary


def _write_started(stream: TextIO) -> None:
    # Without this the log holds a single line written when the run ends, and
    # its timestamp reads like a start time. A run that worked for over an hour
    # and then failed is indistinguishable from one that began late, which sent
    # a real investigation looking at the wrong thing.
    stream.write(
        json.dumps(
            {
                "type": "scheduled_run_started",
                "started_at": datetime.now(timezone.utc).isoformat(),
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
        + "\n"
    )
    stream.flush()


def _write_error(stream: TextIO, code: str, failure: str) -> None:
    stream.write(
        json.dumps(
            {
                "type": "scheduled_run_error",
                "code": code,
                # An exception class name is a code identifier: it cannot carry
                # a subject line, an address or any other message content, so it
                # is safe to log where the exception text is not. Without it the
                # log cannot separate a setting the worker refuses from a
                # mailbox it could not reach, and a scheduled failure has no
                # operator watching it to tell the difference.
                "failure": failure,
                "message": "controllo pianificato non completato; apri InboxLume",
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
        + "\n"
    )
    stream.flush()


def _record_scheduled_failure(
    account_id: str,
    settings_path: Path,
    worker_arguments: Namespace | None = None,
) -> None:
    try:
        settings = SettingsStore(settings_path).load()
        account = settings.account(account_id)
        project_root = Path(__file__).resolve().parents[2]
        state_db = state_database_path(settings_path, project_root, account)
        # A failure raised before the scan namespace exists cannot have touched
        # the mailbox: the run never got past its own startup.
        phase, processed, mailbox_outcome = (
            ("startup", 0, "unchanged")
            if worker_arguments is None
            else terminal_scan_receipt(worker_arguments)
        )
        append_diagnostic(
            diagnostic_path(state_db),
            diagnostic_for_terminal_status(
                status="failed",
                trigger="scheduled",
                provider=account.provider.value,
                destination=account.destination.value,
                scan_profile=scan_profile_for_model(account.model_profile),
                phase=phase,
                processed=processed,
                mailbox_outcome=mailbox_outcome,
                governor_requested=account.safety_governor_enforced,
            ),
        )
    except Exception:  # noqa: BLE001 - best-effort aggregate failure record
        pass


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _write_started(sys.stdout)
    started: list[Namespace] = []
    try:
        run_scheduled_scan(
            args.account,
            args.settings,
            sys.stdout,
            arguments_sink=started.append,
        )
    except Exception as error:  # noqa: BLE001 - final privacy-safe boundary
        _record_scheduled_failure(
            args.account,
            args.settings,
            started[-1] if started else None,
        )
        _write_error(sys.stdout, "scheduled_run_failed", type(error).__name__)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
