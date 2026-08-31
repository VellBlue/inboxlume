from __future__ import annotations

import base64
import unittest
import urllib.parse
from datetime import datetime, timezone
from typing import Any

from inboxlume.providers.contracts import GMAIL_READONLY_SCOPE
from inboxlume.providers.gmail import (
    DirectHttpsJsonTransport,
    GMAIL_API_ORIGIN,
    GMAIL_HISTORY_FIELDS,
    GMAIL_HISTORY_PATH,
    GMAIL_PROFILE_PATH,
    GmailReadError,
    GmailReadOnlyMailbox,
    _extract_inline_content,
)


def encoded(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")


class FakeTokenProvider:
    def __init__(self, scopes: frozenset[str] | None = None) -> None:
        self.scopes = scopes or frozenset({GMAIL_READONLY_SCOPE})

    def get_access_token(self) -> str:
        return "local-test-token"


class QueueTransport:
    def __init__(self, responses: list[dict[str, Any]]) -> None:
        self.responses = list(responses)
        self.urls: list[str] = []
        self.tokens: list[str] = []

    def get_json(self, url: str, access_token: str) -> dict[str, Any]:
        self.urls.append(url)
        self.tokens.append(access_token)
        if not self.responses:
            raise AssertionError("richiesta Gmail inattesa")
        return self.responses.pop(0)


def gmail_message(
    message_id: str = "abc123",
    labels: list[str] | None = None,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": message_id,
        "internalDate": "1767225600000",
        "labelIds": labels or ["INBOX", "UNREAD"],
        "snippet": "Anteprima",
        "payload": payload
        or {
            "mimeType": "text/plain",
            "headers": [
                {"name": "From", "value": "Scuola <school@example.invalid>"},
                {"name": "Subject", "value": "Comunicazione importante"},
                {"name": "Content-Type", "value": "text/plain; charset=utf-8"},
            ],
            "body": {"data": encoded("Messaggio della segreteria didattica")},
        },
    }


class GmailReadOnlyTests(unittest.TestCase):
    def test_requires_exactly_readonly_scope(self) -> None:
        with self.assertRaises(ValueError):
            GmailReadOnlyMailbox(
                "gmail_personale",
                FakeTokenProvider(frozenset({"https://mail.google.com/"})),
                QueueTransport([]),
            )

    def test_reads_only_old_unread_inbox_messages(self) -> None:
        transport = QueueTransport(
            [
                {"messages": [{"id": "abc123"}]},
                gmail_message(),
            ]
        )
        mailbox = GmailReadOnlyMailbox("gmail_personale", FakeTokenProvider(), transport)
        messages = list(
            mailbox.iter_inbox_unread_before(
                datetime(2026, 5, 1, tzinfo=timezone.utc),
                limit=10,
            )
        )
        self.assertEqual(len(messages), 1)
        self.assertIn("segreteria didattica", messages[0].body_text)
        query = urllib.parse.parse_qs(urllib.parse.urlparse(transport.urls[0]).query)
        self.assertEqual(query["labelIds"], ["INBOX"])
        self.assertEqual(query["includeSpamTrash"], ["false"])
        self.assertEqual(query["q"], ["is:unread before:2026/05/01"])
        self.assertTrue(all("/threads" not in url for url in transport.urls))

    def test_progressive_scan_skips_hmac_seen_ids_before_fetching_body(self) -> None:
        transport = QueueTransport(
            [
                {"messages": [{"id": "seen"}, {"id": "new"}]},
                gmail_message("new"),
            ]
        )
        mailbox = GmailReadOnlyMailbox("gmail_personale", FakeTokenProvider(), transport)
        messages = list(
            mailbox.iter_inbox_unread_before(
                datetime(2026, 5, 1, tzinfo=timezone.utc),
                limit=1,
                skip_message_id=lambda message_id: message_id == "seen",
                search_limit=2,
            )
        )
        self.assertEqual([message.message_id for message in messages], ["new"])
        self.assertEqual(len(transport.urls), 2)
        self.assertIn("/messages/new", transport.urls[1])
        self.assertNotIn("/messages/seen", " ".join(transport.urls))

    def test_progressive_scan_can_page_past_all_seen_ids_without_total_cap(self) -> None:
        transport = QueueTransport(
            [
                {
                    "messages": [{"id": "seen-one"}, {"id": "seen-two"}],
                    "nextPageToken": "next-page",
                },
                {"messages": [{"id": "new-deep"}]},
                gmail_message("new-deep"),
            ]
        )
        mailbox = GmailReadOnlyMailbox("gmail_personale", FakeTokenProvider(), transport)
        messages = list(
            mailbox.iter_inbox_unread_before(
                datetime(2026, 5, 1, tzinfo=timezone.utc),
                limit=1,
                skip_message_id=lambda message_id: message_id.startswith("seen-"),
                search_limit=0,
            )
        )
        self.assertEqual([message.message_id for message in messages], ["new-deep"])
        second_query = urllib.parse.parse_qs(
            urllib.parse.urlparse(transport.urls[1]).query
        )
        self.assertEqual(second_query["pageToken"], ["next-page"])
        self.assertNotIn("/messages/seen-", " ".join(transport.urls))

    def test_repeated_message_page_token_fails_closed(self) -> None:
        transport = QueueTransport(
            [
                {"messages": [], "nextPageToken": "repeat"},
                {"messages": [], "nextPageToken": "repeat"},
            ]
        )
        mailbox = GmailReadOnlyMailbox("gmail_personale", FakeTokenProvider(), transport)
        with self.assertRaisesRegex(GmailReadError, "paginazione.*ripetuta"):
            list(mailbox._list_ids(None, "is:unread"))
        self.assertEqual(len(transport.urls), 2)

    def test_deep_mime_tree_fails_with_controlled_error(self) -> None:
        payload: dict[str, Any] = {
            "mimeType": "text/plain",
            "body": {"data": encoded("safe")},
        }
        for _ in range(70):
            payload = {"mimeType": "multipart/mixed", "parts": [payload]}
        with self.assertRaisesRegex(GmailReadError, "MIME.*limite"):
            _extract_inline_content(payload)

    def test_duration_count_uses_only_unique_ids_and_skips_recorded_messages(self) -> None:
        transport = QueueTransport(
            [
                {"messages": [{"id": "seen"}, {"id": "otp-new"}]},
                {"messages": [{"id": "access-new"}, {"id": "otp-new"}]},
                {"messages": [{"id": "unread-new"}, {"id": "access-new"}]},
            ]
        )
        mailbox = GmailReadOnlyMailbox("gmail_personale", FakeTokenProvider(), transport)
        count, reached_limit = mailbox.count_inbox_unprocessed_candidate_ids(
            datetime(2026, 5, 1, tzinfo=timezone.utc),
            datetime(2026, 5, 2, tzinfo=timezone.utc),
            datetime(2026, 5, 3, tzinfo=timezone.utc),
            lambda message_id: message_id == "seen",
        )

        self.assertEqual(count, 3)
        self.assertFalse(reached_limit)
        self.assertEqual(len(transport.urls), 3)
        self.assertTrue(all("/messages/" not in url for url in transport.urls))

    def test_read_routine_access_prefilter_uses_inbox_and_age_cutoff(self) -> None:
        transport = QueueTransport(
            [
                {"messages": [{"id": "login-alert"}]},
                gmail_message(
                    "login-alert",
                    ["INBOX"],
                    payload={
                        "mimeType": "text/plain",
                        "headers": [
                            {"name": "From", "value": "Service <notice@example.invalid>"},
                            {"name": "Subject", "value": "New sign-in detected"},
                        ],
                        "body": {"data": encoded("A new device login was detected.")},
                    },
                ),
            ]
        )
        mailbox = GmailReadOnlyMailbox("gmail_personale", FakeTokenProvider(), transport)
        messages = list(
            mailbox.iter_inbox_read_routine_access_alert_candidates_before(
                datetime(2026, 5, 31, tzinfo=timezone.utc),
                limit=1,
            )
        )
        query = urllib.parse.parse_qs(urllib.parse.urlparse(transport.urls[0]).query)

        self.assertEqual([message.message_id for message in messages], ["login-alert"])
        self.assertEqual(query["labelIds"], ["INBOX"])
        self.assertIn("is:read before:2026/05/31", query["q"][0])
        self.assertIn('subject:"new sign-in"', query["q"][0])

    def test_history_sync_reads_only_relevant_inbox_label_changes(self) -> None:
        transport = QueueTransport(
            [
                {
                    "history": [
                        {
                            "labelsAdded": [
                                {
                                    "message": {"id": "known-one"},
                                    "labelIds": ["STARRED", "SPAM"],
                                }
                            ],
                            "labelsRemoved": [
                                {
                                    "message": {"id": "known-one"},
                                    "labelIds": ["UNREAD"],
                                }
                            ],
                        }
                    ],
                    "nextPageToken": "next-page",
                    "historyId": "150",
                },
                {
                    "history": [
                        {
                            "labelsAdded": [
                                {
                                    "message": {"id": "known-two"},
                                    "labelIds": ["IMPORTANT"],
                                }
                            ]
                        }
                    ],
                    "historyId": "200",
                },
            ]
        )
        mailbox = GmailReadOnlyMailbox("gmail_personale", FakeTokenProvider(), transport)
        sync = mailbox.inbox_label_changes_since("100")

        self.assertEqual(sync.latest_history_id, "200")
        self.assertEqual(len(sync.changes), 2)
        self.assertEqual(sync.changes[0].added_labels, frozenset({"STARRED"}))
        self.assertEqual(sync.changes[0].removed_labels, frozenset({"UNREAD"}))
        self.assertEqual(sync.changes[1].added_labels, frozenset({"IMPORTANT"}))
        for url in transport.urls:
            query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            self.assertEqual(query["labelId"], ["INBOX"])
            self.assertEqual(
                sorted(query["historyTypes"]),
                ["labelAdded", "labelRemoved"],
            )
            self.assertNotIn("messagesAdded", query["fields"][0])
        self.assertEqual(
            urllib.parse.parse_qs(urllib.parse.urlparse(transport.urls[1]).query)[
                "pageToken"
            ],
            ["next-page"],
        )

    def test_behavior_history_includes_only_inboxlume_quarantine_labels(self) -> None:
        transport = QueueTransport(
            [
                {
                    "history": [
                        {
                            "labelsAdded": [
                                {
                                    "message": {"id": "from-trash"},
                                    "labelIds": ["INBOX"],
                                }
                            ],
                            "labelsRemoved": [
                                {
                                    "message": {"id": "from-trash"},
                                    "labelIds": ["TRASH"],
                                }
                            ],
                        }
                    ],
                    "historyId": "200",
                },
                {
                    "labels": [
                        {
                            "id": "Label_42",
                            "name": "InboxLume/Quarantena",
                            "type": "user",
                        },
                        {"id": "Label_99", "name": "Private", "type": "user"},
                    ]
                },
                {
                    "history": [
                        {
                            "labelsRemoved": [
                                {
                                    "message": {"id": "from-quarantine"},
                                    "labelIds": ["Label_42"],
                                }
                            ]
                        }
                    ],
                    "historyId": "210",
                },
            ]
        )
        mailbox = GmailReadOnlyMailbox("gmail_personale", FakeTokenProvider(), transport)
        sync = mailbox.behavior_label_changes_since("100")

        self.assertEqual(sync.latest_history_id, "210")
        by_id = {change.message_id: change for change in sync.changes}
        self.assertEqual(by_id["from-trash"].added_labels, frozenset({"INBOX"}))
        self.assertEqual(by_id["from-trash"].removed_labels, frozenset({"TRASH"}))
        self.assertEqual(
            by_id["from-quarantine"].removed_labels,
            frozenset({"Label_42"}),
        )
        history_label_ids = [
            urllib.parse.parse_qs(urllib.parse.urlparse(url).query).get("labelId")
            for url in transport.urls
            if urllib.parse.urlparse(url).path == GMAIL_HISTORY_PATH
        ]
        self.assertEqual(history_label_ids, [["INBOX"], ["Label_42"]])
        self.assertNotIn("Label_99", " ".join(transport.urls))

    def test_profile_returns_only_history_cursor(self) -> None:
        transport = QueueTransport([{"historyId": "123456"}])
        mailbox = GmailReadOnlyMailbox("gmail_personale", FakeTokenProvider(), transport)
        self.assertEqual(mailbox.current_history_id(), "123456")
        self.assertEqual(
            transport.urls,
            [f"{GMAIL_API_ORIGIN}{GMAIL_PROFILE_PATH}?fields=historyId"],
        )

    def test_history_transport_rejects_broad_mailbox_history_requests(self) -> None:
        allowed_query = urllib.parse.urlencode(
            [
                ("startHistoryId", "100"),
                ("labelId", "INBOX"),
                ("historyTypes", "labelAdded"),
                ("historyTypes", "labelRemoved"),
                ("maxResults", "500"),
                ("fields", GMAIL_HISTORY_FIELDS),
            ]
        )
        DirectHttpsJsonTransport._validate_url(
            f"{GMAIL_API_ORIGIN}{GMAIL_HISTORY_PATH}?{allowed_query}"
        )
        forbidden = (
            f"{GMAIL_API_ORIGIN}{GMAIL_PROFILE_PATH}",
            f"{GMAIL_API_ORIGIN}{GMAIL_HISTORY_PATH}?startHistoryId=100",
            (
                f"{GMAIL_API_ORIGIN}{GMAIL_HISTORY_PATH}?"
                "startHistoryId=100&labelId=SENT&historyTypes=labelRemoved&"
                "maxResults=500&fields=historyId"
            ),
        )
        for url in forbidden:
            with self.subTest(url=url), self.assertRaises(GmailReadError):
                DirectHttpsJsonTransport._validate_url(url)

    def test_sent_label_is_rejected_even_when_in_inbox(self) -> None:
        transport = QueueTransport(
            [
                {"messages": [{"id": "sent123"}]},
                gmail_message("sent123", ["INBOX", "UNREAD", "SENT"]),
            ]
        )
        mailbox = GmailReadOnlyMailbox("gmail_personale", FakeTokenProvider(), transport)
        messages = list(
            mailbox.iter_inbox_unread_before(
                datetime(2026, 5, 1, tzinfo=timezone.utc),
                limit=10,
            )
        )
        self.assertEqual(messages, [])

    def test_attachment_is_not_downloaded_and_html_is_sanitized(self) -> None:
        payload = {
            "mimeType": "multipart/mixed",
            "headers": [
                {"name": "From", "value": "Sender <s@example.invalid>"},
                {"name": "Subject", "value": "HTML"},
            ],
            "body": {},
            "parts": [
                {
                    "mimeType": "text/html",
                    "filename": "",
                    "headers": [{"name": "Content-Type", "value": "text/html; charset=utf-8"}],
                    "body": {
                        "data": encoded(
                            '<p>Testo visibile</p><script>bad()</script>'
                            '<img src="https://tracker.invalid/pixel">'
                        )
                    },
                },
                {
                    "mimeType": "application/pdf",
                    "filename": "documento.pdf",
                    "body": {"attachmentId": "attachment-secret", "size": 1000},
                },
            ],
        }
        transport = QueueTransport(
            [
                {"messages": [{"id": "html123"}]},
                gmail_message("html123", payload=payload),
            ]
        )
        mailbox = GmailReadOnlyMailbox("gmail_personale", FakeTokenProvider(), transport)
        message = list(mailbox.iter_inbox_quiz_sample(limit=1))[0]
        self.assertEqual(message.body_text, "Testo visibile")
        self.assertTrue(message.has_attachment)
        self.assertNotIn("tracker.invalid", message.body_text)
        self.assertEqual(len(transport.urls), 2)
        self.assertTrue(all("attachments" not in url for url in transport.urls))

    def test_quiz_may_read_a_read_message_but_still_only_inbox(self) -> None:
        transport = QueueTransport(
            [
                {"messages": [{"id": "read123"}]},
                gmail_message("read123", ["INBOX"]),
            ]
        )
        mailbox = GmailReadOnlyMailbox("gmail_personale", FakeTokenProvider(), transport)
        message = list(mailbox.iter_inbox_quiz_sample(limit=1))[0]
        self.assertFalse(message.unread)

    def test_quiz_combines_old_unread_and_general_inbox(self) -> None:
        transport = QueueTransport(
            [
                {"messages": [{"id": "old1"}]},
                gmail_message("old1", ["INBOX", "UNREAD"]),
                {"messages": [{"id": "general1"}]},
                gmail_message("general1", ["INBOX"]),
            ]
        )
        mailbox = GmailReadOnlyMailbox("gmail_personale", FakeTokenProvider(), transport)
        messages = list(
            mailbox.iter_inbox_quiz_sample(
                limit=2,
                old_unread_before=datetime(2026, 5, 1, tzinfo=timezone.utc),
            )
        )
        self.assertEqual([message.message_id for message in messages], ["old1", "general1"])
        old_query = urllib.parse.parse_qs(urllib.parse.urlparse(transport.urls[0]).query)
        general_query = urllib.parse.parse_qs(urllib.parse.urlparse(transport.urls[2]).query)
        self.assertEqual(old_query["q"], ["is:unread before:2026/05/01"])
        self.assertNotIn("q", general_query)

    def test_answered_quiz_scan_fetches_only_hmac_matches(self) -> None:
        transport = QueueTransport(
            [
                {"messages": [{"id": "not-answered"}]},
                {"messages": [{"id": "answered"}]},
                gmail_message("answered", ["INBOX"]),
            ]
        )
        mailbox = GmailReadOnlyMailbox("gmail_personale", FakeTokenProvider(), transport)
        matched = list(
            mailbox.iter_inbox_answered_quiz_sample(
                limit=2,
                old_unread_before=datetime(2026, 5, 1, tzinfo=timezone.utc),
                answer_for_id=lambda message_id: (
                    "dont_keep" if message_id == "answered" else None
                ),
            )
        )
        self.assertEqual([(item.message_id, answer) for item, answer in matched], [("answered", "dont_keep")])
        self.assertEqual(len(transport.urls), 3)
        self.assertIn("/messages/answered", transport.urls[2])
        self.assertNotIn("not-answered?", transport.urls[2])

    def test_shadow_review_fetches_only_registered_inbox_candidate(self) -> None:
        transport = QueueTransport(
            [
                {},
                {},
                {"messages": [{"id": "review-me"}]},
                gmail_message("review-me", ["INBOX", "UNREAD"]),
            ]
        )
        mailbox = GmailReadOnlyMailbox("gmail_personale", FakeTokenProvider(), transport)
        matched = list(
            mailbox.iter_inbox_shadow_review_sample(
                unread_before=datetime(2026, 5, 1, tzinfo=timezone.utc),
                read_otp_before=datetime(2026, 8, 1, tzinfo=timezone.utc),
                read_access_before=datetime(2026, 5, 31, tzinfo=timezone.utc),
                limit=1,
                search_limit=10,
                record_for_id=lambda message_id: (
                    ("advertising", "quarantine")
                    if message_id == "review-me"
                    else None
                ),
            )
        )
        self.assertEqual(
            [(message.message_id, category, action) for message, category, action in matched],
            [("review-me", "advertising", "quarantine")],
        )
        self.assertEqual(len(transport.urls), 4)

    def test_verified_candidate_id_selection_reads_no_body(self) -> None:
        transport = QueueTransport(
            [{"messages": [{"id": "skip"}, {"id": "verified"}]}]
        )
        mailbox = GmailReadOnlyMailbox("gmail_personale", FakeTokenProvider(), transport)
        ids = list(
            mailbox.iter_inbox_matching_candidate_ids(
                unread_before=datetime(2026, 5, 1, tzinfo=timezone.utc),
                read_otp_before=datetime(2026, 5, 2, tzinfo=timezone.utc),
                read_access_before=datetime(2026, 3, 1, tzinfo=timezone.utc),
                limit=1,
                search_limit=10,
                include_message_id=lambda message_id, unread: message_id == "verified",
            )
        )
        self.assertEqual(ids, ["verified"])
        self.assertEqual(len(transport.urls), 1)
        self.assertTrue(all("format=full" not in url for url in transport.urls))
        self.assertTrue(all("/messages/verified?" not in url for url in transport.urls))

    def test_candidate_count_reads_no_message_body(self) -> None:
        transport = QueueTransport([{"resultSizeEstimate": 123}])
        mailbox = GmailReadOnlyMailbox("gmail_personale", FakeTokenProvider(), transport)
        estimate = mailbox.estimate_inbox_unread_before(
            datetime(2026, 5, 1, tzinfo=timezone.utc)
        )
        self.assertEqual(estimate, 123)
        self.assertEqual(len(transport.urls), 1)
        query = urllib.parse.parse_qs(urllib.parse.urlparse(transport.urls[0]).query)
        self.assertEqual(query["maxResults"], ["1"])
        self.assertEqual(query["q"], ["is:unread before:2026/05/01"])

    def test_read_one_time_code_prefilter_only_returns_read_inbox(self) -> None:
        transport = QueueTransport(
            [
                {"messages": [{"id": "read-otp"}]},
                gmail_message("read-otp", ["INBOX"]),
            ]
        )
        mailbox = GmailReadOnlyMailbox("gmail_personale", FakeTokenProvider(), transport)
        messages = list(
            mailbox.iter_inbox_read_one_time_code_candidates_before(
                datetime(2026, 5, 1, tzinfo=timezone.utc),
                limit=10,
            )
        )
        self.assertEqual([message.message_id for message in messages], ["read-otp"])
        query = urllib.parse.parse_qs(urllib.parse.urlparse(transport.urls[0]).query)
        self.assertIn("is:read before:2026/05/01", query["q"][0])
        self.assertEqual(query["labelIds"], ["INBOX"])

    def test_read_one_time_code_count_reads_no_message_body(self) -> None:
        transport = QueueTransport([{"resultSizeEstimate": 45}])
        mailbox = GmailReadOnlyMailbox("gmail_personale", FakeTokenProvider(), transport)
        estimate = mailbox.estimate_inbox_read_one_time_code_candidates_before(
            datetime(2026, 5, 1, tzinfo=timezone.utc)
        )
        self.assertEqual(estimate, 45)
        self.assertEqual(len(transport.urls), 1)
        query = urllib.parse.parse_qs(urllib.parse.urlparse(transport.urls[0]).query)
        self.assertEqual(query["maxResults"], ["1"])
        self.assertIn("is:read before:2026/05/01", query["q"][0])

    def test_transport_rejects_non_message_endpoints(self) -> None:
        for url in (
            "http://gmail.googleapis.com/gmail/v1/users/me/messages",
            "https://evil.invalid/gmail/v1/users/me/messages",
            "https://gmail.googleapis.com/gmail/v1/users/me/settings",
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/abc/attachments/x",
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/batchDelete",
        ):
            with self.subTest(url=url), self.assertRaises(GmailReadError):
                DirectHttpsJsonTransport._validate_url(url)

    def test_probe_only_lists_one_inbox_id(self) -> None:
        transport = QueueTransport([{"messages": [{"id": "abc123"}]}])
        mailbox = GmailReadOnlyMailbox("gmail_personale", FakeTokenProvider(), transport)
        self.assertTrue(mailbox.probe_inbox())
        self.assertEqual(len(transport.urls), 1)
        query = urllib.parse.parse_qs(urllib.parse.urlparse(transport.urls[0]).query)
        self.assertEqual(query["labelIds"], ["INBOX"])
        self.assertEqual(query["maxResults"], ["1"])
        self.assertNotIn("format", query)

    def test_public_surface_has_no_mutators(self) -> None:
        names = " ".join(name.casefold() for name in dir(GmailReadOnlyMailbox))
        for forbidden in ("delete", "modify", "trash", "send", "draft", "thread", "expunge"):
            self.assertNotIn(forbidden, names)


if __name__ == "__main__":
    unittest.main()
