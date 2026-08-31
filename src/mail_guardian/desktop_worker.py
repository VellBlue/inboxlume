"""Worker legacy; inoltra al worker InboxLume con gli stessi guardrail."""

from inboxlume.desktop_worker import *  # noqa: F403
from inboxlume.desktop_worker import main


if __name__ == "__main__":
    raise SystemExit(main())
