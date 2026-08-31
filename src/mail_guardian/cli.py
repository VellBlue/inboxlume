"""Entry point legacy; i nuovi comandi usano :mod:`inboxlume.cli`."""

from inboxlume.cli import *  # noqa: F403
from inboxlume.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
