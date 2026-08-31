from __future__ import annotations

import os
import sys


def _isolate_process_tree() -> None:
    if os.name != "posix":
        return
    try:
        os.setsid()
    except OSError:
        # A native scheduler may already have made this process a session leader.
        pass


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        raise SystemExit("worker InboxLume: comando mancante")
    command, remaining = arguments[0], arguments[1:]
    _isolate_process_tree()
    if command == "desktop-worker":
        from .desktop_worker import main as worker_main

        return worker_main(remaining)
    if command == "scheduled-run":
        from .scheduled_run import main as scheduled_main

        return scheduled_main(remaining)
    raise SystemExit("worker InboxLume: comando non valido")


if __name__ == "__main__":
    raise SystemExit(main())
