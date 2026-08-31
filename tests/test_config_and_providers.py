from __future__ import annotations

import unittest
from pathlib import Path

from inboxlume.config import AccountPolicy, account_policy_from_dict, load_policies
from inboxlume.models import PreferenceSnapshot, ProviderKind
from inboxlume.providers.contracts import (
    INBOX_FOLDER,
    READ_ONLY_CAPABILITIES,
    ReadOnlyMailbox,
)


ROOT = Path(__file__).resolve().parents[1]


class ConfigurationTests(unittest.TestCase):
    def test_example_has_separate_gmail_and_yahoo_policies(self) -> None:
        policies = load_policies(ROOT / "config" / "accounts.example.json")
        self.assertEqual(policies["gmail_personale"].provider, ProviderKind.GMAIL)
        self.assertEqual(policies["yahoo_personale"].provider, ProviderKind.YAHOO)
        self.assertIsNot(policies["gmail_personale"], policies["yahoo_personale"])

    def test_only_shadow_mode_is_accepted(self) -> None:
        with self.assertRaises(ValueError):
            AccountPolicy(
                account_id="x",
                provider=ProviderKind.GMAIL,
                unread_age_days=90,
                mode="automatic",  # type: ignore[arg-type]
            )

    def test_configuration_rejects_coercible_and_non_finite_values(self) -> None:
        base = {"id": "x", "provider": "gmail", "unread_age_days": 30}
        invalid_variants = (
            {**base, "unread_age_days": True},
            {**base, "protect_attachments": "false"},
            {**base, "review_confidence": float("nan")},
            {**base, "learning": {"enabled": "false"}},
        )
        for raw in invalid_variants:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                account_policy_from_dict(raw)

    def test_preference_snapshot_rejects_non_finite_and_boolean_numbers(self) -> None:
        for field, value in (
            ("score", float("nan")),
            ("keep_similarity", float("inf")),
            ("observations", True),
            ("recent_content_evidence", float("nan")),
        ):
            values = {"score": 0.5, "observations": 1, field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                PreferenceSnapshot(**values)


class ProviderContractTests(unittest.TestCase):
    def test_contract_mentions_only_inbox(self) -> None:
        self.assertEqual(INBOX_FOLDER, "INBOX")
        self.assertIn("iter_inbox_unread_before", ReadOnlyMailbox.__dict__)
        self.assertIn(
            "iter_inbox_read_one_time_code_candidates_before",
            ReadOnlyMailbox.__dict__,
        )
        self.assertIn("iter_inbox_quiz_sample", ReadOnlyMailbox.__dict__)
        names = " ".join(ReadOnlyMailbox.__dict__).casefold()
        for forbidden in ("sent", "trash", "spam", "draft", "delete", "expunge"):
            self.assertNotIn(forbidden, names)

    def test_capabilities_are_read_only(self) -> None:
        values = {capability.value for capability in READ_ONLY_CAPABILITIES}
        self.assertEqual(values, {"list_unread", "fetch_metadata", "fetch_body"})


if __name__ == "__main__":
    unittest.main()
