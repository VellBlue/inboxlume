from __future__ import annotations

import imaplib
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from inboxlume.models import EmailRecord, ProviderKind
from inboxlume.providers.yahoo import (
    _ACCESS_TERMS,
    DirectYahooImapReadTransport,
    YahooImapCredentials,
    YahooReadOnlyMailbox,
    load_yahoo_credentials,
    save_yahoo_credentials,
    YahooImapError,
)
from inboxlume.providers.yahoo_quarantine import (
    YAHOO_QUARANTINE_FOLDER,
    YAHOO_TRASH_FOLDER,
    YahooDirectTrashExecutor,
    YahooQuarantineExecutor,
    YahooQuarantineOutcome,
    YahooThreatMarkerExecutor,
    YahooThreatMarkerOutcome,
    YahooTrashOutcome,
)


RAW_MESSAGE = (
    b"From: Negozio <promo@example.invalid>\r\n"
    b"To: Archivio <archive@example.invalid>\r\n"
    b"Subject: Offerta del giorno\r\n"
    b"Date: Sat, 29 Aug 2026 10:00:00 +0000\r\n"
    b"Message-ID: <synthetic-11@example.invalid>\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
    b"Sconto privato e promozione."
)


class FakeSecretStore:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get(self, service: str, account: str) -> str | None:
        return self.values.get((service, account))

    def set(self, service: str, account: str, secret: str) -> None:
        self.values[(service, account)] = secret


class FakeReadClient:
    capabilities = (b"IMAP4rev1", b"MOVE", b"UIDPLUS")

    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def login(self, address: str, password: str):  # noqa: ANN001
        self.calls.append(("login", address, password))
        return "OK", [b"logged in"]

    def select(self, folder: str, readonly: bool = False):  # noqa: ANN001
        self.calls.append(("select", folder, readonly))
        return "OK", [b"2"]

    def response(self, name: str):  # noqa: ANN001
        if name == "UIDVALIDITY":
            return "UIDVALIDITY", [b"777"]
        if name == "EXISTS":
            return "EXISTS", [b"2"]
        return None, None

    def uid(self, command: str, *args):  # noqa: ANN001
        self.calls.append(("uid", command, *args))
        if command == "SEARCH":
            return "OK", [b"10 11"]
        uid, query = args
        if query == "(UID FLAGS INTERNALDATE RFC822.SIZE)":
            return "OK", [
                f'{uid} (UID {uid} FLAGS () INTERNALDATE "29-Aug-2026 10:00:00 +0000" RFC822.SIZE {len(RAW_MESSAGE)})'.encode()
            ]
        if query == "(UID BODY.PEEK[])":
            return "OK", [(f"{uid} (UID {uid} BODY[] {{{len(RAW_MESSAGE)}}})".encode(), RAW_MESSAGE), b")"]
        if query == "(UID BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])":
            header = b"Message-ID: <synthetic-11@example.invalid>\r\n\r\n"
            return "OK", [(f"{uid} (UID {uid} BODY[] {{{len(header)}}})".encode(), header), b")"]
        raise AssertionError(query)

    def logout(self):  # noqa: ANN001
        self.calls.append(("logout",))
        return "BYE", [b"bye"]


class FakeMoveClient:
    capabilities = (b"IMAP4rev1", b"MOVE", b"UIDPLUS")

    def __init__(
        self,
        protected: bool = False,
        trash_available: bool = True,
        seen: bool = True,
    ) -> None:
        self.calls: list[tuple] = []
        self.protected = protected
        self.trash_available = trash_available
        self.seen = seen

    def login(self, address: str, password: str):  # noqa: ANN001
        self.calls.append(("login", address, password))
        return "OK", [b"logged in"]

    def select(self, folder: str, readonly: bool = False):  # noqa: ANN001
        self.calls.append(("select", folder, readonly))
        if folder == YAHOO_TRASH_FOLDER and not self.trash_available:
            return "NO", [b"missing"]
        if folder == YAHOO_QUARANTINE_FOLDER and not any(
            call[0] == "create" for call in self.calls
        ):
            return "NO", [b"missing"]
        return "OK", [b"1"]

    def create(self, folder: str):  # noqa: ANN001
        self.calls.append(("create", folder))
        return "OK", [b"created"]

    def response(self, name: str):  # noqa: ANN001
        if name == "UIDVALIDITY":
            return "UIDVALIDITY", [b"777"]
        return None, None

    def uid(self, command: str, *args):  # noqa: ANN001
        self.calls.append(("uid", command, *args))
        if command == "FETCH":
            flags = " ".join(
                flag
                for flag, enabled in (
                    ("\\Seen", self.seen),
                    ("\\Flagged", self.protected),
                )
                if enabled
            )
            return "OK", [f"1 (UID 11 FLAGS ({flags}))".encode()]
        if command == "MOVE":
            return "OK", [b"moved"]
        if command == "STORE":
            return "OK", [b"stored"]
        raise AssertionError(command)

    def logout(self):  # noqa: ANN001
        self.calls.append(("logout",))
        return "BYE", [b"bye"]


class OrderingTransport:
    """A read transport that answers with a whole Inbox, newest UID first."""

    uid_validity = "777"

    def __init__(self, uids: list[str]) -> None:
        # Yahoo hands back descending UIDs, so the newest message is first and
        # any window taken off the front is a window of the newest mail.
        self.uids = sorted(uids, key=int, reverse=True)

    def search(self, *criteria: str) -> list[str]:
        return list(self.uids) if "UNSEEN" in criteria else []

    def fetch_message(self, uid: str, account_id: str) -> EmailRecord:
        return EmailRecord(
            account_id=account_id,
            provider=ProviderKind.YAHOO,
            message_id=f"yahoo-777-{uid}",
            received_at=datetime(2020, 1, 1, tzinfo=timezone.utc)
            + timedelta(days=int(uid)),
            unread=True,
            sender="sender@example.com",
        )

    def fetch_message_identity(self, uid: str) -> str | None:
        return f"<{uid}@example.com>"

    def inbox_count(self) -> int:
        return len(self.uids)

    def close(self) -> None:
        return None


class ScanOrderTests(unittest.TestCase):
    """The processing order has to choose the messages, not just sort them."""

    CUTOFF = datetime(2030, 1, 1, tzinfo=timezone.utc)

    def _uids(self, *, oldest_first: bool, limit: int, search_limit: int) -> list[str]:
        mailbox = YahooReadOnlyMailbox(
            "yahoo_personale", OrderingTransport([str(n) for n in range(1, 21)])
        )
        return [
            record.message_id.rsplit("-", 1)[1]
            for record in mailbox.iter_inbox_unread_before(
                self.CUTOFF,
                limit,
                search_limit=search_limit,
                oldest_first=oldest_first,
            )
        ]

    def test_newest_first_takes_the_highest_uids(self) -> None:
        self.assertEqual(
            self._uids(oldest_first=False, limit=5, search_limit=0),
            ["20", "19", "18", "17", "16"],
        )

    def test_oldest_first_reaches_the_genuinely_oldest_mail(self) -> None:
        # The scan and the schedule both pass search_limit 0, so the window is
        # the whole Inbox and this is the order the option promises.
        self.assertEqual(
            self._uids(oldest_first=True, limit=5, search_limit=0),
            ["1", "2", "3", "4", "5"],
        )

    def test_a_finite_window_would_only_sort_the_newest_mail(self) -> None:
        # Documented, not endorsed: a caller that bounds the search window gets
        # the oldest of the newest, because the window is cut before the sort.
        # Every caller in the app passes 0; this records what the other choice
        # would mean before somebody makes it by accident.
        self.assertEqual(
            self._uids(oldest_first=True, limit=3, search_limit=5),
            ["16", "17", "18"],
        )


class YahooProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.credentials = YahooImapCredentials(
            "utente@example.invalid", "abcdefghijklmnop"
        )

    def test_credentials_are_stored_under_separate_yahoo_account(self) -> None:
        store = FakeSecretStore()
        save_yahoo_credentials(store, "yahoo_personale", self.credentials)
        loaded = load_yahoo_credentials(store, "yahoo_personale")
        self.assertEqual(loaded, self.credentials)
        self.assertEqual(len(store.values), 1)
        self.assertNotIn("gmail", next(iter(store.values))[0])

    def test_read_transport_selects_only_readonly_inbox_and_peeks_body(self) -> None:
        client = FakeReadClient()
        transport = DirectYahooImapReadTransport(self.credentials, client)  # type: ignore[arg-type]
        mailbox = YahooReadOnlyMailbox("yahoo_personale", transport)
        messages = list(
            mailbox.iter_inbox_unread_before(
                datetime(2026, 8, 30, tzinfo=timezone.utc), limit=1
            )
        )
        mailbox.close()

        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].provider, ProviderKind.YAHOO)
        self.assertEqual(messages[0].message_id, "777:11")
        self.assertIn("promozione", messages[0].body_text)
        self.assertEqual(messages[0].headers["To"], "Archivio <archive@example.invalid>")
        self.assertIn(("select", "INBOX", True), client.calls)
        self.assertTrue(
            any(
                call[:3] == ("uid", "FETCH", "11")
                and any("BODY.PEEK[]" in str(item) for item in call)
                for call in client.calls
            )
        )
        self.assertFalse(any(call[0] in {"store", "expunge"} for call in client.calls))

    def test_multi_word_subject_terms_reach_the_server_as_one_argument(self) -> None:
        client = FakeReadClient()
        transport = DirectYahooImapReadTransport(self.credentials, client)  # type: ignore[arg-type]
        transport.search("SEEN", "BEFORE", "30-Aug-2026", "SUBJECT", "new login")
        transport.close()

        search = next(
            call for call in client.calls if call[:2] == ("uid", "SEARCH")
        )
        # imaplib joins criteria with spaces, so an unquoted term would reach
        # the server as "SUBJECT new login" and be rejected with BAD.
        self.assertEqual(search[-1], '"new login"')
        self.assertEqual(search[-2], "SUBJECT")
        self.assertEqual(search[-3], "30-Aug-2026")

    def test_every_access_alert_term_is_sent_quoted(self) -> None:
        for term in _ACCESS_TERMS:
            if not term.isascii():
                continue
            with self.subTest(term=term):
                client = FakeReadClient()
                transport = DirectYahooImapReadTransport(self.credentials, client)  # type: ignore[arg-type]
                transport.search("SEEN", "SUBJECT", term)
                transport.close()
                search = next(
                    call for call in client.calls if call[:2] == ("uid", "SEARCH")
                )
                self.assertEqual(search[-1], f'"{term}"')

    def test_quoting_escapes_characters_that_would_end_the_string(self) -> None:
        client = FakeReadClient()
        transport = DirectYahooImapReadTransport(self.credentials, client)  # type: ignore[arg-type]
        transport.search("SEEN", "SUBJECT", 'con "virgolette" e \\ backslash')
        transport.close()

        search = next(
            call for call in client.calls if call[:2] == ("uid", "SEARCH")
        )
        self.assertEqual(search[-1], '"con \\"virgolette\\" e \\\\ backslash"')

    def test_keywords_and_dates_are_never_quoted(self) -> None:
        client = FakeReadClient()
        transport = DirectYahooImapReadTransport(self.credentials, client)  # type: ignore[arg-type]
        transport.search("SEEN", "BEFORE", "30-Aug-2026")
        transport.close()

        search = next(
            call for call in client.calls if call[:2] == ("uid", "SEARCH")
        )
        self.assertEqual(search[2:], (None, "SEEN", "BEFORE", "30-Aug-2026"))

    def test_restore_reconciliation_reads_only_message_id_header(self) -> None:
        client = FakeReadClient()
        transport = DirectYahooImapReadTransport(self.credentials, client)  # type: ignore[arg-type]
        mailbox = YahooReadOnlyMailbox("yahoo_personale", transport)
        sync = mailbox.inbox_identities_after("777", "9", limit=10)
        mailbox.close()

        self.assertEqual(
            sync.identities,
            ("<synthetic-11@example.invalid>", "<synthetic-11@example.invalid>"),
        )
        self.assertEqual(sync.latest_processed_uid, "11")
        self.assertFalse(sync.has_more)
        identity_fetches = [
            call for call in client.calls
            if call[:2] == ("uid", "FETCH")
            and "HEADER.FIELDS (MESSAGE-ID)" in str(call)
        ]
        self.assertEqual(len(identity_fetches), 2)
        self.assertFalse(
            any(
                call[:2] == ("uid", "FETCH") and "BODY.PEEK[]" in str(call)
                for call in client.calls
            )
        )

    def test_duration_count_uses_search_only_and_skips_recorded_uids(self) -> None:
        client = FakeReadClient()
        transport = DirectYahooImapReadTransport(self.credentials, client)  # type: ignore[arg-type]
        mailbox = YahooReadOnlyMailbox("yahoo_personale", transport)
        count, reached_limit = mailbox.count_inbox_unprocessed_candidate_ids(
            datetime(2026, 5, 1, tzinfo=timezone.utc),
            datetime(2026, 5, 2, tzinfo=timezone.utc),
            datetime(2026, 5, 3, tzinfo=timezone.utc),
            lambda message_id: message_id == "777:10",
        )
        mailbox.close()

        self.assertEqual(count, 1)
        self.assertFalse(reached_limit)
        self.assertTrue(any(call[:2] == ("uid", "SEARCH") for call in client.calls))
        self.assertFalse(any(call[:2] == ("uid", "FETCH") for call in client.calls))

    def test_imap_protocol_error_is_reported_as_recoverable_yahoo_error(self) -> None:
        class FailingFetchClient(FakeReadClient):
            def uid(self, command: str, *args):  # noqa: ANN001
                if command == "FETCH":
                    raise imaplib.IMAP4.error("private server detail")
                return super().uid(command, *args)

        transport = DirectYahooImapReadTransport(
            self.credentials,
            FailingFetchClient(),  # type: ignore[arg-type]
        )
        with self.assertRaisesRegex(YahooImapError, "lettura IMAP Yahoo") as error:
            transport.fetch_message("11", "yahoo_personale")
        transport.close()

        self.assertNotIn("private server detail", str(error.exception))

    def test_transport_fetch_failure_aborts_instead_of_reporting_empty_success(self) -> None:
        class OneUnreadableClient(FakeReadClient):
            def uid(self, command: str, *args):  # noqa: ANN001
                if command == "FETCH" and args[0] == "11":
                    raise imaplib.IMAP4.error("private server detail")
                return super().uid(command, *args)

        transport = DirectYahooImapReadTransport(
            self.credentials,
            OneUnreadableClient(),  # type: ignore[arg-type]
        )
        mailbox = YahooReadOnlyMailbox("yahoo_personale", transport)
        try:
            with self.assertRaisesRegex(YahooImapError, "lettura IMAP Yahoo"):
                list(
                    mailbox.iter_inbox_unread_before(
                        datetime(2026, 8, 30, tzinfo=timezone.utc), limit=2
                    )
                )
        finally:
            mailbox.close()

    def test_search_failure_aborts_instead_of_reporting_an_empty_inbox(self) -> None:
        class SearchUnavailableClient(FakeReadClient):
            def uid(self, command: str, *args):  # noqa: ANN001
                if command == "SEARCH":
                    return "NO", [b"private server detail"]
                return super().uid(command, *args)

        transport = DirectYahooImapReadTransport(
            self.credentials,
            SearchUnavailableClient(),  # type: ignore[arg-type]
        )
        mailbox = YahooReadOnlyMailbox("yahoo_personale", transport)
        try:
            with self.assertRaisesRegex(YahooImapError, "ricerca Inbox Yahoo") as error:
                list(
                    mailbox.iter_inbox_unread_before(
                        datetime(2026, 8, 30, tzinfo=timezone.utc), limit=2
                    )
                )
        finally:
            mailbox.close()
        self.assertNotIn("private server detail", str(error.exception))

    def test_access_search_never_sends_non_ascii_imap_criteria(self) -> None:
        class AsciiOnlySearchClient(FakeReadClient):
            def uid(self, command: str, *args):  # noqa: ANN001
                if command == "SEARCH" and any(
                    isinstance(value, str) and not value.isascii() for value in args
                ):
                    raise AssertionError("non-ASCII IMAP search criterion")
                return super().uid(command, *args)

        transport = DirectYahooImapReadTransport(
            self.credentials,
            AsciiOnlySearchClient(),  # type: ignore[arg-type]
        )
        mailbox = YahooReadOnlyMailbox("yahoo_personale", transport)
        messages = list(
            mailbox.iter_inbox_read_routine_access_alert_candidates_before(
                datetime(2026, 8, 30, tzinfo=timezone.utc), limit=1
            )
        )
        mailbox.close()

        # FakeReadClient exposes an unread message, so zero is expected; the
        # assertion that matters is that no UnicodeEncodeError escaped.
        self.assertEqual(len(messages), 0)

    def test_real_yahoo_session_reconnects_once_after_transient_fetch_error(self) -> None:
        class FailingOnceClient(FakeReadClient):
            def __init__(self) -> None:
                super().__init__()
                self.failed = False

            def uid(self, command: str, *args):  # noqa: ANN001
                if command == "FETCH" and not self.failed:
                    self.failed = True
                    raise imaplib.IMAP4.abort("transient private server detail")
                return super().uid(command, *args)

        first = FailingOnceClient()
        replacement = FakeReadClient()
        with patch(
            "inboxlume.providers.yahoo.imaplib.IMAP4_SSL",
            side_effect=(first, replacement),
        ):
            transport = DirectYahooImapReadTransport(self.credentials)
            mailbox = YahooReadOnlyMailbox("yahoo_personale", transport)
            messages = list(
                mailbox.iter_inbox_unread_before(
                    datetime(2026, 8, 30, tzinfo=timezone.utc), limit=1
                )
            )
            mailbox.close()

        self.assertEqual(len(messages), 1)
        self.assertTrue(first.failed)
        self.assertIn(("logout",), first.calls)
        self.assertIn(("login", self.credentials.email_address, self.credentials.app_password), replacement.calls)

    def test_quarantine_uses_exact_folder_and_move_without_expunge(self) -> None:
        client = FakeMoveClient()
        executor = YahooQuarantineExecutor(self.credentials, client)  # type: ignore[arg-type]
        result = executor.apply_quarantine("777:11", expected_unread=False)
        executor.close()

        self.assertEqual(result.outcome, YahooQuarantineOutcome.APPLIED)
        self.assertIn(("create", YAHOO_QUARANTINE_FOLDER), client.calls)
        self.assertIn(("select", "INBOX", False), client.calls)
        self.assertIn(("uid", "MOVE", "11", YAHOO_QUARANTINE_FOLDER), client.calls)
        self.assertFalse(any(call[0] in {"store", "expunge", "delete"} for call in client.calls))

    def test_quarantine_refuses_flagged_message(self) -> None:
        client = FakeMoveClient(protected=True)
        executor = YahooQuarantineExecutor(self.credentials, client)  # type: ignore[arg-type]
        result = executor.apply_quarantine("777:11", expected_unread=False)
        executor.close()
        self.assertEqual(result.outcome, YahooQuarantineOutcome.SKIPPED_PROTECTED)
        self.assertFalse(any(call[:2] == ("uid", "MOVE") for call in client.calls))

    def test_quarantine_moves_expected_unread_that_is_still_unread(self) -> None:
        client = FakeMoveClient(seen=False)
        executor = YahooQuarantineExecutor(self.credentials, client)  # type: ignore[arg-type]
        result = executor.apply_quarantine("777:11", expected_unread=True)
        executor.close()

        self.assertEqual(result.outcome, YahooQuarantineOutcome.APPLIED)
        self.assertIn(("uid", "MOVE", "11", YAHOO_QUARANTINE_FOLDER), client.calls)

    def test_quarantine_refuses_expected_read_that_became_unread(self) -> None:
        client = FakeMoveClient(seen=False)
        executor = YahooQuarantineExecutor(self.credentials, client)  # type: ignore[arg-type]
        result = executor.apply_quarantine("777:11", expected_unread=False)
        executor.close()

        self.assertEqual(result.outcome, YahooQuarantineOutcome.SKIPPED_PROTECTED)
        self.assertFalse(any(call[:2] == ("uid", "MOVE") for call in client.calls))

    def test_quarantine_refuses_expected_unread_that_became_read(self) -> None:
        client = FakeMoveClient(seen=True)
        executor = YahooQuarantineExecutor(self.credentials, client)  # type: ignore[arg-type]
        result = executor.apply_quarantine("777:11", expected_unread=True)
        executor.close()

        self.assertEqual(result.outcome, YahooQuarantineOutcome.SKIPPED_PROTECTED)
        self.assertFalse(any(call[:2] == ("uid", "MOVE") for call in client.calls))

    def test_quarantine_fails_closed_without_move_capability(self) -> None:
        client = FakeMoveClient()
        client.capabilities = (b"IMAP4rev1",)
        with self.assertRaises(YahooImapError):
            YahooQuarantineExecutor(self.credentials, client)  # type: ignore[arg-type]
        self.assertFalse(any(call[0] in {"store", "expunge"} for call in client.calls))

    def test_threat_marker_adds_flag_silently_without_move_or_folder(self) -> None:
        # The phishing marker is additive and remains valid for unread mail;
        # only MOVE executors treat missing \\Seen as a protection signal.
        client = FakeMoveClient(seen=False)
        executor = YahooThreatMarkerExecutor(self.credentials, client)  # type: ignore[arg-type]
        result = executor.apply("777:11")
        executor.close()

        self.assertEqual(result.outcome, YahooThreatMarkerOutcome.APPLIED)
        self.assertIn(
            ("uid", "STORE", "11", "+FLAGS.SILENT", "(\\Flagged)"), client.calls
        )
        self.assertFalse(any(call[:2] == ("uid", "MOVE") for call in client.calls))
        self.assertFalse(any(call[0] == "create" for call in client.calls))

    def test_threat_marker_existing_star_is_idempotent(self) -> None:
        client = FakeMoveClient(protected=True)
        executor = YahooThreatMarkerExecutor(self.credentials, client)  # type: ignore[arg-type]
        result = executor.apply("777:11")
        executor.close()

        self.assertEqual(result.outcome, YahooThreatMarkerOutcome.ALREADY_APPLIED)
        self.assertFalse(any(call[:2] == ("uid", "STORE") for call in client.calls))
        self.assertFalse(any(call[:2] == ("uid", "MOVE") for call in client.calls))

    def test_threat_marker_does_not_require_move_capability(self) -> None:
        client = FakeMoveClient()
        client.capabilities = (b"IMAP4rev1",)
        executor = YahooThreatMarkerExecutor(self.credentials, client)  # type: ignore[arg-type]
        result = executor.apply("777:11")
        executor.close()
        self.assertEqual(result.outcome, YahooThreatMarkerOutcome.APPLIED)
        self.assertFalse(any(call[:2] == ("uid", "MOVE") for call in client.calls))

    def test_direct_trash_uses_exact_existing_folder_and_never_expunge(self) -> None:
        client = FakeMoveClient()
        executor = YahooDirectTrashExecutor(self.credentials, client)  # type: ignore[arg-type]
        result = executor.apply("777:11", expected_unread=False)
        executor.close()

        self.assertEqual(result.outcome, YahooTrashOutcome.MOVED_TO_TRASH)
        self.assertIn(("select", YAHOO_TRASH_FOLDER, True), client.calls)
        self.assertIn(("select", "INBOX", False), client.calls)
        self.assertIn(("uid", "MOVE", "11", YAHOO_TRASH_FOLDER), client.calls)
        self.assertFalse(any(call[0] in {"create", "store", "expunge", "delete"} for call in client.calls))

    def test_direct_trash_refuses_flagged_message(self) -> None:
        client = FakeMoveClient(protected=True)
        executor = YahooDirectTrashExecutor(self.credentials, client)  # type: ignore[arg-type]
        result = executor.apply("777:11", expected_unread=False)
        executor.close()

        self.assertEqual(result.outcome, YahooTrashOutcome.SKIPPED_PROTECTED)
        self.assertFalse(any(call[:2] == ("uid", "MOVE") for call in client.calls))

    def test_direct_trash_moves_expected_unread_that_is_still_unread(self) -> None:
        client = FakeMoveClient(seen=False)
        executor = YahooDirectTrashExecutor(self.credentials, client)  # type: ignore[arg-type]
        result = executor.apply("777:11", expected_unread=True)
        executor.close()

        self.assertEqual(result.outcome, YahooTrashOutcome.MOVED_TO_TRASH)
        self.assertIn(("uid", "MOVE", "11", YAHOO_TRASH_FOLDER), client.calls)

    def test_direct_trash_refuses_expected_read_that_became_unread(self) -> None:
        client = FakeMoveClient(seen=False)
        executor = YahooDirectTrashExecutor(self.credentials, client)  # type: ignore[arg-type]
        result = executor.apply("777:11", expected_unread=False)
        executor.close()

        self.assertEqual(result.outcome, YahooTrashOutcome.SKIPPED_PROTECTED)
        self.assertFalse(any(call[:2] == ("uid", "MOVE") for call in client.calls))

    def test_direct_trash_refuses_expected_unread_that_became_read(self) -> None:
        client = FakeMoveClient(seen=True)
        executor = YahooDirectTrashExecutor(self.credentials, client)  # type: ignore[arg-type]
        result = executor.apply("777:11", expected_unread=True)
        executor.close()

        self.assertEqual(result.outcome, YahooTrashOutcome.SKIPPED_PROTECTED)
        self.assertFalse(any(call[:2] == ("uid", "MOVE") for call in client.calls))

    def test_direct_trash_fails_closed_if_exact_trash_folder_is_missing(self) -> None:
        client = FakeMoveClient(trash_available=False)
        with self.assertRaises(YahooImapError):
            YahooDirectTrashExecutor(self.credentials, client)  # type: ignore[arg-type]
        self.assertFalse(any(call[0] in {"create", "store", "expunge"} for call in client.calls))


if __name__ == "__main__":
    unittest.main()
