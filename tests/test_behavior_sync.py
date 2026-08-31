from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from inboxlume.cli import (
    _collect_gmail_behavior_feedback,
    _collect_yahoo_restored_feedback,
)
from inboxlume.config import load_policies
from inboxlume.learning import PreferenceStore
from inboxlume.models import Classification, EmailCategory, PolicyAction, PolicyDecision
from inboxlume.providers.gmail import (
    GmailHistoryExpired,
    GmailHistorySync,
    GmailLabelChange,
)
from inboxlume.providers.yahoo import YahooInboxIdentitySync

from tests.helpers import make_message


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 8, 30, tzinfo=timezone.utc)


class FakeHistoryMailbox:
    def __init__(
        self,
        current: str,
        sync: GmailHistorySync | None = None,
        expired: bool = False,
    ) -> None:
        self.current = current
        self.sync = sync
        self.expired = expired
        self.starts: list[str] = []

    def current_history_id(self) -> str:
        return self.current

    def inbox_label_changes_since(self, start_history_id: str) -> GmailHistorySync:
        self.starts.append(start_history_id)
        if self.expired:
            raise GmailHistoryExpired("scaduta")
        if self.sync is None:
            raise AssertionError("sync inattesa")
        return self.sync


class FakeYahooRestoreMailbox:
    class _Transport:
        uid_validity = "777"

    transport = _Transport()

    def __init__(self, identities: tuple[str, ...], latest_uid: str = "11") -> None:
        self.identities = identities
        self.latest_uid = latest_uid

    def inbox_identities_after(
        self,
        uid_validity: str,
        last_uid: str,
        limit: int,
    ) -> YahooInboxIdentitySync:
        if (uid_validity, last_uid, limit) != ("777", "10", 500):
            raise AssertionError("cursore Yahoo inatteso")
        return YahooInboxIdentitySync("777", self.identities, self.latest_uid, False)


class BehaviorSyncTests(unittest.TestCase):
    def setUp(self) -> None:
        policies = load_policies(ROOT / "config/accounts.example.json")
        self.policy = policies["gmail_personale"]
        self.yahoo_policy = policies["yahoo_personale"]

    def test_first_run_only_initializes_cursor_without_inference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "state.sqlite3", b"c" * 32)
            mailbox = FakeHistoryMailbox("150")
            result = _collect_gmail_behavior_feedback(
                mailbox,  # type: ignore[arg-type]
                store,
                self.policy,
                NOW,
            )
            cursor = store.gmail_history_cursor(self.policy.account_id)
        self.assertEqual(result["status"], "initialized")
        self.assertEqual(result["new_signals"], {})
        self.assertEqual(cursor, "150")
        self.assertEqual(mailbox.starts, [])

    def test_known_label_changes_become_idempotent_local_signals(self) -> None:
        classification = Classification(
            EmailCategory.ADVERTISING,
            0.99,
            ("test",),
            "test",
        )
        message = make_message(
            message_id="private-known",
            subject="Newsletter fotografia settimanale",
            body_text="Nuova lezione e programma del corso di fotografia.",
        )
        sync = GmailHistorySync(
            (
                GmailLabelChange(
                    "private-known",
                    frozenset({"STARRED"}),
                    frozenset({"UNREAD"}),
                ),
                GmailLabelChange(
                    "unknown-id",
                    frozenset({"IMPORTANT"}),
                    frozenset(),
                ),
            ),
            "200",
        )
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "state.sqlite3"
            store = PreferenceStore(database, b"d" * 32)
            store.record_shadow_scan(
                message,
                classification,
                PolicyDecision(PolicyAction.REVIEW, ("test",)),
                "gemma26-policy-v2",
                NOW,
            )
            store.set_gmail_history_cursor(self.policy.account_id, "100", NOW)
            mailbox = FakeHistoryMailbox("210", sync=sync)
            first = _collect_gmail_behavior_feedback(
                mailbox,  # type: ignore[arg-type]
                store,
                self.policy,
                NOW,
            )
            second = _collect_gmail_behavior_feedback(
                FakeHistoryMailbox("210", sync=GmailHistorySync(sync.changes, "210")),  # type: ignore[arg-type]
                store,
                self.policy,
                NOW,
            )
            summary = store.behavior_event_summary(self.policy.account_id)
            database_bytes = database.read_bytes()

        self.assertEqual(first["new_signals"], {"opened": 1, "starred": 1})
        self.assertEqual(second["new_signals"], {})
        self.assertEqual(
            summary,
            {"left_unread": 1, "opened": 1, "starred": 1},
        )
        self.assertNotIn(b"private-known", database_bytes)
        self.assertNotIn(b"fotografia", database_bytes)

    def test_expired_history_resets_cursor_without_guessing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "state.sqlite3", b"e" * 32)
            store.set_gmail_history_cursor(self.policy.account_id, "100", NOW)
            result = _collect_gmail_behavior_feedback(
                FakeHistoryMailbox("500", expired=True),  # type: ignore[arg-type]
                store,
                self.policy,
                NOW,
            )
            cursor = store.gmail_history_cursor(self.policy.account_id)
            summary = store.behavior_event_summary(self.policy.account_id)
        self.assertEqual(result["status"], "history_reset_without_inference")
        self.assertEqual(cursor, "500")
        self.assertEqual(summary, {})

    def test_gmail_restore_is_strong_idempotent_governor_feedback(self) -> None:
        message = make_message(message_id="restored-gmail")
        classification = Classification(
            EmailCategory.ADVERTISING, 0.99, ("test",), "test"
        )
        profile = "gemma26-policy-v2"
        sync = GmailHistorySync(
            (
                GmailLabelChange(
                    "restored-gmail",
                    frozenset({"INBOX"}),
                    frozenset({"TRASH"}),
                ),
            ),
            "200",
        )
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "state.sqlite3", b"f" * 32)
            store.record_shadow_scan(
                message,
                classification,
                PolicyDecision(PolicyAction.QUARANTINE, ("test",)),
                profile,
                NOW,
            )
            store.record_quarantine_pilot_execution(
                self.policy.account_id,
                self.policy.provider,
                message.message_id,
                profile,
                NOW,
                "moved_to_trash",
            )
            store.set_gmail_history_cursor(self.policy.account_id, "100", NOW)
            first = _collect_gmail_behavior_feedback(
                FakeHistoryMailbox("200", sync=sync),  # type: ignore[arg-type]
                store,
                self.policy,
                NOW,
            )
            second = _collect_gmail_behavior_feedback(
                FakeHistoryMailbox("200", sync=sync),  # type: ignore[arg-type]
                store,
                self.policy,
                NOW,
            )
            evidence = store.shadow_quarantine_evidence_by_category(
                self.policy.account_id, profile
            )

        self.assertEqual(first["new_signals"], {"restored": 1})
        self.assertEqual(second["new_signals"], {})
        self.assertEqual(evidence["advertising"]["keep"], 1)

    def test_yahoo_restore_uses_hmac_identity_without_plaintext(self) -> None:
        private_identity = "<private-yahoo-message@example.invalid>"
        message = make_message(
            account_id=self.yahoo_policy.account_id,
            provider=self.yahoo_policy.provider,
            message_id="777:5",
            headers={"Message-ID": private_identity},
        )
        classification = Classification(
            EmailCategory.ADVERTISING, 0.99, ("test",), "test"
        )
        profile = "gemma26-policy-v2"
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "state.sqlite3"
            store = PreferenceStore(database, b"g" * 32)
            store.record_shadow_scan(
                message,
                classification,
                PolicyDecision(PolicyAction.QUARANTINE, ("test",)),
                profile,
                NOW,
            )
            store.record_quarantine_pilot_execution(
                self.yahoo_policy.account_id,
                self.yahoo_policy.provider,
                message.message_id,
                profile,
                NOW,
                "applied",
            )
            store.set_yahoo_uid_cursor(self.yahoo_policy.account_id, "777", "10", NOW)
            result = _collect_yahoo_restored_feedback(
                FakeYahooRestoreMailbox((private_identity,)),  # type: ignore[arg-type]
                store,
                self.yahoo_policy,
                NOW,
            )
            evidence = store.shadow_quarantine_evidence_by_category(
                self.yahoo_policy.account_id, profile
            )
            database_bytes = database.read_bytes()

        self.assertEqual(result["new_signals"], {"restored": 1})
        self.assertEqual(evidence["advertising"]["keep"], 1)
        self.assertNotIn(private_identity.encode(), database_bytes)


if __name__ == "__main__":
    unittest.main()
