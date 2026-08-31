from __future__ import annotations

import unittest

from scripts.smoke_packaged_worker import validate_synthetic_receipt


class PackageSmokeTests(unittest.TestCase):
    @staticmethod
    def _valid_receipt() -> dict[str, object]:
        return {
            "type": "local_threat_backtest",
            "synthetic_corpus_only": True,
            "reads_mailbox": False,
            "uses_network": False,
            "changes_mailbox": False,
            "authorizes_actions": False,
            "stored_plaintext": False,
            "cases": {"total": 24, "malicious": 12, "benign": 12},
        }

    def test_accepts_a_strictly_offline_synthetic_receipt(self) -> None:
        validate_synthetic_receipt(self._valid_receipt())

    def test_rejects_any_mailbox_access_or_mutation_claim(self) -> None:
        for field in ("reads_mailbox", "changes_mailbox"):
            with self.subTest(field=field):
                receipt = self._valid_receipt()
                receipt[field] = True
                with self.assertRaisesRegex(ValueError, field):
                    validate_synthetic_receipt(receipt)

    def test_rejects_network_or_non_synthetic_execution(self) -> None:
        for field, value in (
            ("uses_network", True),
            ("synthetic_corpus_only", False),
            ("authorizes_actions", True),
            ("stored_plaintext", True),
        ):
            with self.subTest(field=field):
                receipt = self._valid_receipt()
                receipt[field] = value
                with self.assertRaisesRegex(ValueError, field):
                    validate_synthetic_receipt(receipt)


if __name__ == "__main__":
    unittest.main()
