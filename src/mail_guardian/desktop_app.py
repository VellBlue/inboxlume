"""Entry point desktop legacy; la nuova applicazione si chiama InboxLume."""

from inboxlume.desktop_app import *  # noqa: F403
from inboxlume.desktop_app import main


if __name__ == "__main__":
    raise SystemExit(main())
