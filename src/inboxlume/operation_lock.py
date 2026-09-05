from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path


def account_operation_lock_path(state_db: Path, account_id: str) -> Path:
    if not account_id.strip() or "\0" in account_id:
        raise ValueError("account_id lock non valido")
    identity = hashlib.sha256(account_id.encode("utf-8")).hexdigest()[:20]
    return state_db.parent / f".inboxlume-{identity}.operation.lock"


def account_progress_path(state_db: Path, account_id: str) -> Path:
    """Name the aggregate progress file beside this account's operation lock."""

    lock = account_operation_lock_path(state_db, account_id)
    return lock.with_suffix(".progress.json")


def operation_lock_holder(path: Path) -> int | None:
    """Name the live process holding this lock, reading nothing but the file.

    The holder writes its pid into the lock, so a reader can answer "is a run
    happening right now" without touching the lock itself. Probing the lock
    instead would mean asking for it, and a scheduled run starting inside that
    window would be told a run was already going and fail for nothing.

    A pid can be reused after the owner dies, so this is a status signal and
    never an authority: only the lock decides who may run.
    """

    try:
        recorded = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError):
        return None
    if not recorded.isdigit():
        return None
    holder = int(recorded)
    if holder <= 0:
        return None
    try:
        os.kill(holder, 0)
    except ProcessLookupError:
        return None
    except PermissionError:
        # Alive and owned by somebody else; not ours to report on.
        return None
    except OSError:
        return None
    return holder


class AccountOperationLock:
    """Cross-process, crash-safe exclusive lock for one account operation."""

    def __init__(self, path: Path, *, wait: bool = False) -> None:
        self.path = path
        self.wait = wait
        self._descriptor: int | None = None

    def __enter__(self) -> AccountOperationLock:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.path.is_symlink():
            raise RuntimeError("lock operazione non valido")
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.path, flags, 0o600)
        try:
            mode = os.fstat(descriptor).st_mode
            if not stat.S_ISREG(mode):
                raise RuntimeError("lock operazione non valido")
            if os.name != "nt":
                import fcntl

                try:
                    flags = fcntl.LOCK_EX
                    if not self.wait:
                        flags |= fcntl.LOCK_NB
                    fcntl.flock(descriptor, flags)
                except BlockingIOError as exc:
                    raise RuntimeError(
                        "un controllo InboxLume è già in esecuzione"
                    ) from exc
                os.fchmod(descriptor, 0o600)
            else:  # pragma: no cover - exercised by Windows package smoke tests
                import msvcrt

                if os.fstat(descriptor).st_size == 0:
                    try:
                        os.write(descriptor, b"\0")
                    except PermissionError:
                        # Another opener can acquire the one-byte Windows lock
                        # between fstat() and this initialization write.  The
                        # blocking lock below will wait for that owner, which
                        # also restores the byte before releasing the handle.
                        pass
                os.lseek(descriptor, 0, os.SEEK_SET)
                try:
                    mode = msvcrt.LK_LOCK if self.wait else msvcrt.LK_NBLCK
                    msvcrt.locking(descriptor, mode, 1)
                except OSError as exc:
                    raise RuntimeError(
                        "un controllo InboxLume è già in esecuzione"
                    ) from exc
            os.ftruncate(descriptor, 0)
            os.write(descriptor, f"{os.getpid()}\n".encode("ascii"))
            os.fsync(descriptor)
        except Exception:
            os.close(descriptor)
            raise
        self._descriptor = descriptor
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:  # noqa: ANN001
        descriptor = self._descriptor
        if descriptor is None:
            return
        try:
            # Keep the inode in place. Unlinking a locked file lets a third
            # process create and lock a different inode while an existing
            # waiter is still queued on the old one.
            if os.name != "nt":
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
            else:  # pragma: no cover - exercised by Windows package smoke tests
                import msvcrt

                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        finally:
            os.close(descriptor)
            self._descriptor = None
