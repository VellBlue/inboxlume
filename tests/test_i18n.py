from __future__ import annotations

import ast
import unittest
from pathlib import Path

from inboxlume.desktop_worker import WORKER_FAILURE_MESSAGES
from inboxlume.i18n import ITALIAN_UI


ROOT = Path(__file__).resolve().parents[1]


class I18nTests(unittest.TestCase):
    def test_every_static_desktop_message_has_an_italian_translation(self) -> None:
        source = (ROOT / "src/inboxlume/desktop_app.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        canonical_messages = {
            node.args[0].value
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "_"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        }

        self.assertEqual(canonical_messages - set(ITALIAN_UI), set())

    def test_every_worker_failure_message_has_an_italian_translation(self) -> None:
        # These reach the user through the GUI event payload rather than a
        # literal call, so the scan above cannot see them.
        untranslated = {
            code
            for code, message in WORKER_FAILURE_MESSAGES.items()
            if message not in ITALIAN_UI
        }

        self.assertEqual(untranslated, set())


if __name__ == "__main__":
    unittest.main()
