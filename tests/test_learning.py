from __future__ import annotations

import tempfile
import unittest
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from inboxlume.learning import (
    PREFERENCE_HMAC_KEYCHAIN_SERVICE,
    FeedbackSignal,
    PreferenceStore,
    load_or_create_hmac_key,
)
from inboxlume.models import (
    Classification,
    EmailCategory,
    PolicyAction,
    PolicyDecision,
    ProviderKind,
)

from tests.helpers import make_message


CLASSIFICATION = Classification(EmailCategory.ADVERTISING, 0.95, ("test",), "test")


class FakeSecretStore:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get(self, service: str, account: str) -> str | None:
        return self.values.get((service, account))

    def set(self, service: str, account: str, secret: str) -> None:
        self.values[(service, account)] = secret


class PreferenceStoreTests(unittest.TestCase):
    def test_hmac_key_is_generated_once_and_kept_in_secret_store(self) -> None:
        secret_store = FakeSecretStore()
        first = load_or_create_hmac_key(secret_store, "gmail_personale")
        second = load_or_create_hmac_key(secret_store, "gmail_personale")
        self.assertEqual(first, second)
        self.assertEqual(len(first), 32)
        self.assertIn(
            (PREFERENCE_HMAC_KEYCHAIN_SERVICE, "gmail_personale"),
            secret_store.values,
        )

    def test_hmac_creation_is_serialized_for_one_database(self) -> None:
        secret_store = FakeSecretStore()
        with tempfile.TemporaryDirectory() as directory:
            state_db = Path(directory) / "race.sqlite3"
            with ThreadPoolExecutor(max_workers=8) as pool:
                keys = list(
                    pool.map(
                        lambda _: load_or_create_hmac_key(
                            secret_store, "gmail_race", state_db
                        ),
                        range(16),
                    )
                )
        self.assertEqual(len(set(keys)), 1)

    def test_hmac_creation_is_serialized_across_different_databases(self) -> None:
        secret_store = FakeSecretStore()
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / "one.sqlite3", Path(directory) / "two.sqlite3"]
            with ThreadPoolExecutor(max_workers=2) as pool:
                keys = list(
                    pool.map(
                        lambda path: load_or_create_hmac_key(
                            secret_store, "gmail_cross_database_race", path
                        ),
                        paths,
                    )
                )
        self.assertEqual(keys[0], keys[1])

    def test_missing_key_for_existing_database_fails_closed(self) -> None:
        secret_store = FakeSecretStore()
        with tempfile.TemporaryDirectory() as directory:
            state_db = Path(directory) / "existing.sqlite3"
            key = load_or_create_hmac_key(secret_store, "gmail_existing", state_db)
            PreferenceStore(state_db, key, "gmail_existing")
            secret_store.values.clear()

            with self.assertRaisesRegex(RuntimeError, "mancante"):
                load_or_create_hmac_key(secret_store, "gmail_existing", state_db)

    def test_shared_database_allows_a_genuinely_new_account_key(self) -> None:
        secret_store = FakeSecretStore()
        with tempfile.TemporaryDirectory() as directory:
            state_db = Path(directory) / "shared.sqlite3"
            first_key = load_or_create_hmac_key(secret_store, "gmail_one", state_db)
            PreferenceStore(state_db, first_key, "gmail_one")

            second_key = load_or_create_hmac_key(secret_store, "gmail_two", state_db)
            PreferenceStore(state_db, second_key, "gmail_two")

        self.assertNotEqual(first_key, second_key)

    def test_database_key_binding_rejects_a_different_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_db = Path(directory) / "bound.sqlite3"
            PreferenceStore(state_db, b"a" * 32, "gmail_bound")
            with self.assertRaisesRegex(RuntimeError, "non corrisponde"):
                PreferenceStore(state_db, b"b" * 32, "gmail_bound")

    @unittest.skipIf(os.name == "nt", "POSIX mode bits are not Windows ACLs")
    def test_database_and_wal_files_are_owner_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "public-parent"
            parent.mkdir(mode=0o755)
            parent.chmod(0o755)
            previous_umask = os.umask(0o022)
            try:
                state_db = parent / "private.sqlite3"
                store = PreferenceStore(state_db, b"p" * 32, "gmail_private")
                connection = store._connect()
                try:
                    connection.execute(
                        "UPDATE state_key_binding SET key_check = key_check"
                    )
                    connection.commit()
                    paths = [state_db, Path(f"{state_db}-wal"), Path(f"{state_db}-shm")]
                    self.assertTrue(all(path.exists() for path in paths))
                    for path in paths:
                        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                finally:
                    connection.close()
            finally:
                os.umask(previous_umask)

    def test_accounts_are_isolated_and_data_is_hashed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "preferences.sqlite3"
            store = PreferenceStore(path, b"k" * 32)
            gmail = make_message(sender="Persona <private@example.invalid>")
            yahoo = make_message(
                account_id="yahoo_personale",
                provider=ProviderKind.YAHOO,
                sender="Persona <private@example.invalid>",
            )
            store.observe(gmail, CLASSIFICATION, FeedbackSignal.OPENED)

            self.assertGreater(store.interest_for(gmail, CLASSIFICATION).observations, 0)
            self.assertEqual(store.interest_for(yahoo, CLASSIFICATION).observations, 0)
            self.assertNotIn(b"private@example.invalid", path.read_bytes())

    def test_unread_is_weak_and_explicit_keep_is_strong(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "p.sqlite3", b"z" * 32)
            message = make_message()
            for _ in range(5):
                store.observe(message, CLASSIFICATION, FeedbackSignal.LEFT_UNREAD)
            after_unread = store.interest_for(message, CLASSIFICATION)
            store.observe(message, CLASSIFICATION, FeedbackSignal.EXPLICIT_KEEP)
            after_keep = store.interest_for(message, CLASSIFICATION)
            self.assertGreater(after_keep.score, after_unread.score)

    def test_quiz_retry_does_not_count_the_same_answer_twice(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "p.sqlite3", b"r" * 32)
            message = make_message()
            store.record_quiz_answer(
                message,
                CLASSIFICATION,
                "keep",
                FeedbackSignal.EXPLICIT_KEEP,
            )
            first = store.interest_for(message, CLASSIFICATION)
            store.record_quiz_answer(
                message,
                CLASSIFICATION,
                "keep",
                FeedbackSignal.EXPLICIT_KEEP,
            )
            second = store.interest_for(message, CLASSIFICATION)
            self.assertEqual(first, second)

    def test_quiz_labels_can_be_recovered_only_through_hmac_lookup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "p.sqlite3"
            store = PreferenceStore(path, b"h" * 32)
            message = make_message(message_id="private-id")
            store.record_quiz_answer(
                message,
                CLASSIFICATION,
                "dont_keep",
                FeedbackSignal.EXPLICIT_NOT_INTERESTED,
            )
            answer = store.quiz_answer_for_message_id(
                message.account_id,
                message.provider,
                message.message_id,
            )
            self.assertEqual(answer, "dont_keep")
            self.assertEqual(
                store.quiz_answer_counts(message.account_id),
                {"keep": 0, "dont_keep": 1, "unsure": 0},
            )
            self.assertNotIn(b"private-id", path.read_bytes())

    def test_similar_content_reuses_an_explicit_answer_without_plaintext(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "p.sqlite3"
            store = PreferenceStore(path, b"s" * 32)
            example = make_message(
                message_id="example",
                subject="Offerta speciale: 20% sulle scarpe",
                body_text=(
                    "Solo oggi risparmia il 20 per cento sulle scarpe della nuova "
                    "collezione. Acquista ora e disiscriviti qui."
                ),
            )
            similar = make_message(
                message_id="similar",
                subject="Offerta speciale: 25% sulle scarpe",
                body_text=(
                    "Solo oggi risparmia il 25 per cento sulle scarpe della nuova "
                    "collezione. Acquista ora e disiscriviti qui."
                ),
            )
            store.record_quiz_answer(
                example,
                CLASSIFICATION,
                "dont_keep",
                FeedbackSignal.EXPLICIT_NOT_INTERESTED,
            )
            preference = store.interest_for(similar, CLASSIFICATION)
            database_bytes = path.read_bytes()

            self.assertGreaterEqual(preference.dont_keep_similarity, 0.82)
            self.assertEqual(preference.dont_keep_similar_examples, 1)
            self.assertNotIn(b"Offerta speciale", database_bytes)
            self.assertNotIn(b"scarpe", database_bytes)

    def test_every_event_on_one_message_still_counts_after_the_rewrite(self):
        """The content lookup narrows by feature first, then joins the events.

        Driving the join from behavior_event instead made SQLite look up every
        feature for every recorded event, which cost 43 seconds per message on
        a real archive. Narrowing first is the same aggregate only if a message
        with several events still contributes each of them.
        """

        now = datetime(2026, 8, 30, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "events.sqlite3", b"e" * 32)
            message = make_message(
                message_id="repeated-open",
                subject="Aggiornamento corso fotografia nuova lezione",
                body_text=(
                    "Nuova lezione del corso di fotografia disponibile. "
                    "Guarda il programma e il materiale della settimana."
                ),
            )
            store.record_shadow_scan(
                message,
                CLASSIFICATION,
                PolicyDecision(PolicyAction.REVIEW, ("test",)),
                "gemma26-policy-v2",
                now - timedelta(days=5),
            )
            # One message, several distinct events: the shape the rewritten
            # join has to preserve.
            for signal, offset in (
                (FeedbackSignal.OPENED, 5),
                (FeedbackSignal.STARRED, 4),
                (FeedbackSignal.MARKED_IMPORTANT, 3),
            ):
                self.assertTrue(
                    store.record_behavior_event_for_message_id(
                        message.account_id,
                        message.provider,
                        message.message_id,
                        signal,
                        now - timedelta(days=offset),
                    )
                )

            similar = make_message(
                message_id="new-similar-repeated",
                subject="Aggiornamento corso fotografia nuova lezione",
                body_text=(
                    "Nuova lezione del corso di fotografia disponibile. "
                    "Guarda il programma e il materiale della settimana."
                ),
            )
            found = store.interest_for(similar, CLASSIFICATION, now)

        # Three events on one message, each one still weighed.
        self.assertGreater(found.recent_content_evidence, 0.0)
        self.assertGreater(found.recent_content_score, 0.5)
        self.assertEqual(found.recent_content_examples, 1)

    def test_recent_opening_behavior_is_content_specific_and_decays(self) -> None:
        now = datetime(2026, 8, 30, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "behavior.sqlite3"
            store = PreferenceStore(path, b"b" * 32)
            for index in range(3):
                message = make_message(
                    message_id=f"private-open-{index}",
                    subject=f"Aggiornamento corso fotografia numero {index}",
                    body_text=(
                        "Nuova lezione del corso di fotografia disponibile. "
                        "Guarda il programma e il materiale della settimana."
                    ),
                )
                store.record_shadow_scan(
                    message,
                    CLASSIFICATION,
                    PolicyDecision(PolicyAction.REVIEW, ("test",)),
                    "gemma26-policy-v2",
                    now - timedelta(days=5),
                )
                self.assertTrue(
                    store.record_behavior_event_for_message_id(
                        message.account_id,
                        message.provider,
                        message.message_id,
                        FeedbackSignal.OPENED,
                        now,
                    )
                )
            similar = make_message(
                message_id="new-similar",
                subject="Aggiornamento corso fotografia nuova lezione",
                body_text=(
                    "Nuova lezione del corso di fotografia disponibile. "
                    "Guarda il programma e il materiale della settimana."
                ),
            )
            recent = store.interest_for(similar, CLASSIFICATION, now)
            expired = store.interest_for(
                similar,
                CLASSIFICATION,
                now + timedelta(days=270),
            )
            summary = store.behavior_event_summary("gmail_personale")
            database_bytes = path.read_bytes()

        self.assertGreaterEqual(recent.recent_content_evidence, 3.0)
        self.assertGreater(recent.recent_content_score, 0.72)
        self.assertLess(expired.recent_content_evidence, 0.2)
        self.assertEqual(summary, {"left_unread": 3, "opened": 3})
        self.assertNotIn(b"private-open", database_bytes)
        self.assertNotIn(b"fotografia", database_bytes)

    def test_behavior_event_is_idempotent_and_unknown_ids_are_ignored(self) -> None:
        now = datetime(2026, 8, 30, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "behavior.sqlite3", b"i" * 32)
            message = make_message(message_id="known")
            store.record_shadow_scan(
                message,
                CLASSIFICATION,
                PolicyDecision(PolicyAction.REVIEW, ("test",)),
                "gemma26-policy-v2",
                now,
            )
            first = store.record_behavior_event_for_message_id(
                message.account_id,
                message.provider,
                message.message_id,
                FeedbackSignal.STARRED,
                now,
            )
            duplicate = store.record_behavior_event_for_message_id(
                message.account_id,
                message.provider,
                message.message_id,
                FeedbackSignal.STARRED,
                now,
            )
            unknown = store.record_behavior_event_for_message_id(
                message.account_id,
                message.provider,
                "unknown",
                FeedbackSignal.OPENED,
                now,
            )
        self.assertTrue(first)
        self.assertFalse(duplicate)
        self.assertFalse(unknown)

    def test_threat_marker_audit_uses_hmac_identity_and_controlled_fields(self) -> None:
        now = datetime(2026, 8, 30, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "threat-marker.sqlite3"
            store = PreferenceStore(path, b"m" * 32)
            store.record_threat_marker_execution(
                "gmail_personale",
                ProviderKind.GMAIL,
                "private-provider-id",
                "gemma26-policy-v2",
                now,
                "gmail_label",
                "applied",
            )
            summary = store.threat_marker_summary(
                "gmail_personale", "gemma26-policy-v2"
            )
            database_bytes = path.read_bytes()

        self.assertEqual(summary["outcomes"], {"gmail_label:applied": 1})
        self.assertFalse(summary["stored_plaintext"])
        self.assertNotIn(b"private-provider-id", database_bytes)

    def test_failed_threat_marker_reopens_only_retryable_shadow_rows(self) -> None:
        now = datetime(2026, 8, 30, tzinfo=timezone.utc)
        profile = "gemma26-policy-v2"
        cases = (
            (ProviderKind.GMAIL, "gmail_personale", "gmail_label", "gmail-marker"),
            (ProviderKind.YAHOO, "yahoo_personale", "yahoo_star", "777:11"),
        )
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(
                Path(directory) / "marker-retry.sqlite3", b"r" * 32
            )
            for provider, account_id, marker_kind, message_id in cases:
                with self.subTest(provider=provider.value):
                    message = make_message(
                        account_id=account_id,
                        provider=provider,
                        message_id=message_id,
                    )
                    decision = PolicyDecision(
                        PolicyAction.REVIEW,
                        (
                            "threat_protective_review",
                            "threat_visible_marker_candidate",
                        ),
                    )
                    store.record_shadow_scan(
                        message,
                        CLASSIFICATION,
                        decision,
                        profile,
                        now,
                    )
                    was_scanned = store.shadow_scan_membership_checker(
                        account_id, provider, profile
                    )
                    self.assertTrue(was_scanned(message_id))

                    store.record_threat_marker_execution(
                        account_id,
                        provider,
                        message_id,
                        profile,
                        now,
                        marker_kind,
                        "failed",
                    )
                    was_scanned = store.shadow_scan_membership_checker(
                        account_id, provider, profile
                    )
                    self.assertFalse(was_scanned(message_id))

                    # Simulate the next shadow pass and its successful provider
                    # retry. Re-recording the same terminal result is idempotent.
                    store.record_shadow_scan(
                        message,
                        CLASSIFICATION,
                        decision,
                        profile,
                        now + timedelta(minutes=1),
                    )
                    store.record_threat_marker_execution(
                        account_id,
                        provider,
                        message_id,
                        profile,
                        now + timedelta(minutes=1),
                        marker_kind,
                        "applied",
                    )
                    store.record_threat_marker_execution(
                        account_id,
                        provider,
                        message_id,
                        profile,
                        now + timedelta(minutes=2),
                        marker_kind,
                        "applied",
                    )
                    was_scanned = store.shadow_scan_membership_checker(
                        account_id, provider, profile
                    )
                    self.assertTrue(was_scanned(message_id))

                    gone = make_message(
                        account_id=account_id,
                        provider=provider,
                        message_id=(
                            "gmail-gone"
                            if provider is ProviderKind.GMAIL
                            else "777:12"
                        ),
                    )
                    store.record_shadow_scan(
                        gone,
                        CLASSIFICATION,
                        decision,
                        profile,
                        now,
                    )
                    store.record_threat_marker_execution(
                        account_id,
                        provider,
                        gone.message_id,
                        profile,
                        now,
                        marker_kind,
                        "skipped_not_inbox",
                    )
                    was_scanned = store.shadow_scan_membership_checker(
                        account_id, provider, profile
                    )
                    self.assertTrue(was_scanned(gone.message_id))

            summary = store.threat_marker_summary("gmail_personale", profile)
            self.assertEqual(
                summary["outcomes"],
                {
                    "gmail_label:applied": 1,
                    "gmail_label:skipped_not_inbox": 1,
                },
            )
            yahoo_summary = store.threat_marker_summary("yahoo_personale", profile)
            self.assertEqual(
                yahoo_summary["outcomes"],
                {
                    "yahoo_star:applied": 1,
                    "yahoo_star:skipped_not_inbox": 1,
                },
            )


if __name__ == "__main__":
    unittest.main()
