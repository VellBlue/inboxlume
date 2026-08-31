from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from .operation_lock import AccountOperationLock


DIAGNOSTIC_SCHEMA_VERSION = "run-diagnostic-v1"
MAX_DIAGNOSTIC_RECORDS = 200

# Stage codes emitted by the desktop worker, plus the two values that only a
# record can carry: "completed" for a run that reached its final receipt and
# "unspecified" for records written before the phase was persisted.
DIAGNOSTIC_PHASES = frozenset(
    {
        "unspecified",
        "startup",
        "classification",
        "threat_protection",
        "lumegraph",
        "obsolescence_proof",
        "mailbox_actions",
        "post_scan",
        "completed",
    }
)
DIAGNOSTIC_MAILBOX_OUTCOMES = frozenset({"unchanged", "changed", "unknown"})

# Records written before this schema gained the two fields stay readable: the
# phase they stopped in was never stored, and their mailbox outcome therefore
# cannot be proven from the record alone.
LEGACY_DIAGNOSTIC_DEFAULTS: Mapping[str, str] = {
    "phase": "unspecified",
    "mailbox_outcome": "unknown",
}


@dataclass(frozen=True, slots=True)
class RunDiagnostic:
    recorded_at: datetime
    trigger: str
    status: str
    provider: str
    destination: str
    scan_profile: str
    phase: str
    processed: int
    applied: int
    mailbox_outcome: str
    governor_requested: bool
    governor_enforced: bool
    governor_blocked: int
    lumegraph_available: bool
    lumegraph_nodes: int
    lumegraph_transitions: int
    lumegraph_model_failures: int

    def __post_init__(self) -> None:
        if self.recorded_at.tzinfo is None:
            raise ValueError("diagnostic timestamp must include a timezone")
        if self.trigger not in {"manual", "scheduled"}:
            raise ValueError("invalid diagnostic trigger")
        if self.status not in {"completed", "failed", "cancelled"}:
            raise ValueError("invalid diagnostic status")
        if self.provider not in {"gmail", "yahoo"}:
            raise ValueError("invalid diagnostic provider")
        if self.destination not in {"quarantine", "trash"}:
            raise ValueError("invalid diagnostic destination")
        if not self.scan_profile.strip() or len(self.scan_profile) > 100:
            raise ValueError("invalid diagnostic scan profile")
        if self.phase not in DIAGNOSTIC_PHASES:
            raise ValueError("invalid diagnostic phase")
        if self.mailbox_outcome not in DIAGNOSTIC_MAILBOX_OUTCOMES:
            raise ValueError("invalid diagnostic mailbox outcome")
        if (self.status == "completed") != (self.phase == "completed"):
            raise ValueError("diagnostic phase contradicts diagnostic status")
        counts = (
            self.processed,
            self.applied,
            self.governor_blocked,
            self.lumegraph_nodes,
            self.lumegraph_transitions,
            self.lumegraph_model_failures,
        )
        if any(isinstance(value, bool) or value < 0 for value in counts):
            raise ValueError("invalid diagnostic count")

    def as_dict(self) -> dict[str, object]:
        return {
            "schema": DIAGNOSTIC_SCHEMA_VERSION,
            "recorded_at": self.recorded_at.astimezone(timezone.utc).isoformat(),
            "trigger": self.trigger,
            "status": self.status,
            "provider": self.provider,
            "destination": self.destination,
            "scan_profile": self.scan_profile,
            "phase": self.phase,
            "processed": self.processed,
            "applied": self.applied,
            "mailbox_outcome": self.mailbox_outcome,
            "governor_requested": self.governor_requested,
            "governor_enforced": self.governor_enforced,
            "governor_blocked": self.governor_blocked,
            "lumegraph_available": self.lumegraph_available,
            "lumegraph_nodes": self.lumegraph_nodes,
            "lumegraph_transitions": self.lumegraph_transitions,
            "lumegraph_model_failures": self.lumegraph_model_failures,
            "stored_plaintext": False,
        }


def diagnostic_path(state_db: Path) -> Path:
    return state_db.with_suffix(".diagnostics.jsonl")


def diagnostic_from_summary(
    summary: Mapping[str, object],
    *,
    trigger: str,
    provider: str,
    destination: str,
    governor_requested: bool,
    recorded_at: datetime | None = None,
) -> RunDiagnostic:
    automatic = summary.get("automatic_quarantine")
    actions = automatic if isinstance(automatic, Mapping) else {}
    governor_raw = summary.get("safety_governor")
    governor = governor_raw if isinstance(governor_raw, Mapping) else {}
    graph_raw = summary.get("lumegraph")
    graph = graph_raw if isinstance(graph_raw, Mapping) else {}
    applied = int(actions.get("applied", 0))
    # A completed run carries its own proof: the mailbox changed only when the
    # summary reports an applied action, so the record never has to guess.
    mailbox_outcome = (
        "changed"
        if summary.get("changes_mailbox") is True or applied > 0
        else "unchanged"
    )
    return RunDiagnostic(
        recorded_at=recorded_at or datetime.now(timezone.utc),
        trigger=trigger,
        status="completed",
        provider=provider,
        destination=destination,
        scan_profile=str(summary.get("scan_profile", "")),
        phase="completed",
        processed=int(summary.get("newly_processed", 0)),
        applied=applied,
        mailbox_outcome=mailbox_outcome,
        governor_requested=governor_requested,
        governor_enforced=bool(governor.get("enforced", False)),
        governor_blocked=int(governor.get("blocked_current_batch", 0)),
        lumegraph_available=graph.get("available") is not False,
        lumegraph_nodes=int(graph.get("run_nodes", 0)),
        lumegraph_transitions=int(graph.get("run_transitions", 0)),
        lumegraph_model_failures=int(graph.get("model_failures", 0)),
    )


def diagnostic_for_terminal_status(
    *,
    status: str,
    trigger: str,
    provider: str,
    destination: str,
    scan_profile: str,
    phase: str,
    processed: int,
    mailbox_outcome: str,
    governor_requested: bool,
    recorded_at: datetime | None = None,
) -> RunDiagnostic:
    """Create an aggregate failure/cancellation record without exception text.

    The caller must supply the phase actually reached, the count actually
    processed and whether a mailbox mutation had already begun.  Recording
    defaults here would make an interrupted run indistinguishable from one that
    never touched the mailbox, which is precisely what the record has to prove.
    """

    return RunDiagnostic(
        recorded_at=recorded_at or datetime.now(timezone.utc),
        trigger=trigger,
        status=status,
        provider=provider,
        destination=destination,
        scan_profile=scan_profile,
        phase=phase,
        processed=processed,
        applied=0,
        mailbox_outcome=mailbox_outcome,
        governor_requested=governor_requested,
        governor_enforced=False,
        governor_blocked=0,
        lumegraph_available=False,
        lumegraph_nodes=0,
        lumegraph_transitions=0,
        lumegraph_model_failures=0,
    )


def append_diagnostic(path: Path, record: RunDiagnostic) -> None:
    lock_path = path.with_name(f".{path.name}.lock")
    with AccountOperationLock(lock_path, wait=True):
        _append_diagnostic_unlocked(path, record)


def _append_diagnostic_unlocked(path: Path, record: RunDiagnostic) -> None:
    """Atomically retain a bounded, aggregate-only local JSONL history."""

    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink():
        raise OSError("diagnostic path must not be a symbolic link")
    prior: list[str] = []
    if path.is_file():
        prior = path.read_text(encoding="utf-8").splitlines()
    lines = [*prior[-(MAX_DIAGNOSTIC_RECORDS - 1):], json.dumps(
        record.as_dict(),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )]
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary.write("\n".join(lines) + "\n")
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


def latest_diagnostic(path: Path) -> dict[str, object] | None:
    if not path.is_file() or path.is_symlink():
        return None
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines:
        return None
    try:
        value = json.loads(lines[-1])
    except json.JSONDecodeError as exc:
        raise ValueError("invalid local diagnostic record") from exc
    if not isinstance(value, dict) or value.get("schema") != DIAGNOSTIC_SCHEMA_VERSION:
        raise ValueError("invalid local diagnostic record")
    allowed = set(RunDiagnostic.__dataclass_fields__) | {"schema", "stored_plaintext"}
    required = allowed - set(LEGACY_DIAGNOSTIC_DEFAULTS)
    present = set(value)
    if not required <= present <= allowed:
        raise ValueError("invalid local diagnostic fields")
    if value.get("stored_plaintext") is not False:
        raise ValueError("invalid local diagnostic fields")
    record = {**LEGACY_DIAGNOSTIC_DEFAULTS, **value}
    if (
        record["phase"] not in DIAGNOSTIC_PHASES
        or record["mailbox_outcome"] not in DIAGNOSTIC_MAILBOX_OUTCOMES
    ):
        raise ValueError("invalid local diagnostic fields")
    return record
