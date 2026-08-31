from __future__ import annotations

import unittest
import urllib.parse
from typing import Any

from inboxlume.providers.contracts import GMAIL_MODIFY_SCOPE, GMAIL_READONLY_SCOPE
from inboxlume.providers.gmail_quarantine import (
    GMAIL_API_ORIGIN,
    LABELS_PATH,
    QUARANTINE_LABEL_NAME,
    THREAT_LABEL_NAME,
    DirectGmailQuarantineTransport,
    GmailLabelQuarantineExecutor,
    GmailQuarantineError,
    GmailThreatMarkerExecutor,
    QuarantineOutcome,
    ThreatMarkerOutcome,
)


class FakeTokenProvider:
    def __init__(self, scope: str = GMAIL_MODIFY_SCOPE) -> None:
        self.scopes = frozenset({scope})

    def get_access_token(self) -> str:
        return "test-token"


class QueueTransport:
    def __init__(
        self,
        get_responses: list[dict[str, Any]],
        post_responses: list[dict[str, Any]],
    ) -> None:
        self.get_responses = list(get_responses)
        self.post_responses = list(post_responses)
        self.get_calls: list[str] = []
        self.post_calls: list[tuple[str, dict[str, Any]]] = []

    def get_json(self, url: str, access_token: str) -> dict[str, Any]:
        self.get_calls.append(url)
        if access_token != "test-token" or not self.get_responses:
            raise AssertionError("GET inattesa")
        return self.get_responses.pop(0)

    def post_json(
        self,
        url: str,
        payload: dict[str, Any],
        access_token: str,
    ) -> dict[str, Any]:
        self.post_calls.append((url, dict(payload)))
        if access_token != "test-token" or not self.post_responses:
            raise AssertionError("POST inattesa")
        return self.post_responses.pop(0)


class GmailQuarantineTests(unittest.TestCase):
    def test_requires_exact_modify_scope(self) -> None:
        with self.assertRaises(ValueError):
            GmailLabelQuarantineExecutor(FakeTokenProvider(GMAIL_READONLY_SCOPE))

    def test_applies_only_user_label_and_never_removes_inbox(self) -> None:
        transport = QueueTransport(
            get_responses=[
                {"id": "abc123", "labelIds": ["INBOX", "UNREAD"]},
                {"labels": []},
            ],
            post_responses=[
                {
                    "id": "Label_42",
                    "name": QUARANTINE_LABEL_NAME,
                    "type": "user",
                },
                {
                    "id": "abc123",
                    "labelIds": ["INBOX", "UNREAD", "Label_42"],
                },
            ],
        )
        executor = GmailLabelQuarantineExecutor(FakeTokenProvider(), transport)
        result = executor.apply_label_quarantine(
            "abc123",
            expected_unread=True,
        )

        self.assertEqual(result.outcome, QuarantineOutcome.APPLIED)
        self.assertTrue(result.changes_mailbox)
        self.assertEqual(len(transport.post_calls), 2)
        create_url, create_payload = transport.post_calls[0]
        modify_url, modify_payload = transport.post_calls[1]
        self.assertEqual(create_url, f"{GMAIL_API_ORIGIN}{LABELS_PATH}")
        self.assertEqual(create_payload["name"], QUARANTINE_LABEL_NAME)
        self.assertTrue(modify_url.endswith("/messages/abc123/modify"))
        self.assertEqual(modify_payload, {"addLabelIds": ["Label_42"], "removeLabelIds": []})
        metadata_query = urllib.parse.parse_qs(
            urllib.parse.urlparse(transport.get_calls[0]).query
        )
        self.assertEqual(metadata_query, {"format": ["minimal"], "fields": ["id,labelIds"]})

    def test_protected_or_non_inbox_message_is_never_modified(self) -> None:
        for labels, expected in (
            (["INBOX", "IMPORTANT"], QuarantineOutcome.SKIPPED_PROTECTED),
            (["INBOX", "STARRED"], QuarantineOutcome.SKIPPED_PROTECTED),
            (["INBOX", "SENT"], QuarantineOutcome.SKIPPED_NOT_INBOX),
            (["TRASH"], QuarantineOutcome.SKIPPED_NOT_INBOX),
        ):
            with self.subTest(labels=labels):
                transport = QueueTransport(
                    get_responses=[{"id": "abc123", "labelIds": labels}],
                    post_responses=[],
                )
                executor = GmailLabelQuarantineExecutor(FakeTokenProvider(), transport)
                result = executor.apply_label_quarantine(
                    "abc123",
                    expected_unread=False,
                )
                self.assertEqual(result.outcome, expected)
                self.assertEqual(transport.post_calls, [])

    def test_expected_read_that_became_unread_is_not_labelled(self) -> None:
        transport = QueueTransport(
            get_responses=[
                {"id": "abc123", "labelIds": ["INBOX", "UNREAD"]},
            ],
            post_responses=[],
        )

        result = GmailLabelQuarantineExecutor(
            FakeTokenProvider(), transport
        ).apply_label_quarantine("abc123", expected_unread=False)

        self.assertEqual(result.outcome, QuarantineOutcome.SKIPPED_PROTECTED)
        self.assertEqual(transport.post_calls, [])

    def test_expected_unread_that_became_read_is_not_labelled(self) -> None:
        transport = QueueTransport(
            get_responses=[
                {"id": "abc123", "labelIds": ["INBOX"]},
            ],
            post_responses=[],
        )

        result = GmailLabelQuarantineExecutor(
            FakeTokenProvider(), transport
        ).apply_label_quarantine("abc123", expected_unread=True)

        self.assertEqual(result.outcome, QuarantineOutcome.SKIPPED_PROTECTED)
        self.assertEqual(transport.post_calls, [])

    def test_existing_quarantine_label_is_idempotent(self) -> None:
        transport = QueueTransport(
            get_responses=[
                {"id": "abc123", "labelIds": ["INBOX", "Label_42"]},
                {
                    "labels": [
                        {
                            "id": "Label_42",
                            "name": QUARANTINE_LABEL_NAME,
                            "type": "user",
                        }
                    ]
                },
            ],
            post_responses=[],
        )
        executor = GmailLabelQuarantineExecutor(FakeTokenProvider(), transport)
        result = executor.apply_label_quarantine(
            "abc123",
            expected_unread=False,
        )
        self.assertEqual(result.outcome, QuarantineOutcome.ALREADY_APPLIED)
        self.assertFalse(result.changes_mailbox)
        self.assertEqual(transport.post_calls, [])

    def test_threat_marker_adds_label_and_keeps_inbox_and_existing_labels(self) -> None:
        transport = QueueTransport(
            get_responses=[
                {
                    "id": "abc123",
                    "labelIds": ["INBOX", "UNREAD", "IMPORTANT"],
                },
                {"labels": []},
            ],
            post_responses=[
                {"id": "Label_99", "name": THREAT_LABEL_NAME, "type": "user"},
                {
                    "id": "abc123",
                    "labelIds": ["INBOX", "UNREAD", "IMPORTANT", "Label_99"],
                },
            ],
        )
        result = GmailThreatMarkerExecutor(FakeTokenProvider(), transport).apply("abc123")

        self.assertEqual(result.outcome, ThreatMarkerOutcome.APPLIED)
        self.assertEqual(transport.post_calls[0][1]["name"], THREAT_LABEL_NAME)
        self.assertEqual(
            transport.post_calls[1][1],
            {"addLabelIds": ["Label_99"], "removeLabelIds": []},
        )

    def test_existing_threat_label_is_idempotent_and_keeps_inbox(self) -> None:
        transport = QueueTransport(
            get_responses=[
                {"id": "abc123", "labelIds": ["INBOX", "STARRED", "Label_99"]},
                {
                    "labels": [
                        {"id": "Label_99", "name": THREAT_LABEL_NAME, "type": "user"}
                    ]
                },
            ],
            post_responses=[],
        )
        result = GmailThreatMarkerExecutor(FakeTokenProvider(), transport).apply("abc123")

        self.assertEqual(result.outcome, ThreatMarkerOutcome.ALREADY_APPLIED)
        self.assertEqual(transport.post_calls, [])

    def test_transport_rejects_every_dangerous_endpoint_and_removal(self) -> None:
        dangerous_urls = (
            f"{GMAIL_API_ORIGIN}/gmail/v1/users/me/messages/abc/send",
            f"{GMAIL_API_ORIGIN}/gmail/v1/users/me/messages/abc/trash",
            f"{GMAIL_API_ORIGIN}/gmail/v1/users/me/messages/abc/untrash",
            f"{GMAIL_API_ORIGIN}/gmail/v1/users/me/messages/batchDelete",
            f"{GMAIL_API_ORIGIN}/gmail/v1/users/me/drafts",
            f"{GMAIL_API_ORIGIN}/gmail/v1/users/me/settings",
            "https://evil.invalid/gmail/v1/users/me/labels",
        )
        for url in dangerous_urls:
            with self.subTest(url=url), self.assertRaises(GmailQuarantineError):
                DirectGmailQuarantineTransport._validate_post(url, {})
        for removed in (["INBOX"], ["SENT"], ["STARRED"]):
            with self.subTest(removed=removed), self.assertRaises(GmailQuarantineError):
                DirectGmailQuarantineTransport._validate_post(
                    f"{GMAIL_API_ORIGIN}/gmail/v1/users/me/messages/abc/modify",
                    {"addLabelIds": ["Label_42"], "removeLabelIds": removed},
                )

    def test_executor_public_surface_has_no_dangerous_action(self) -> None:
        names = " ".join(
            name.casefold()
            for name in dir(GmailLabelQuarantineExecutor)
            if not name.startswith("_")
        )
        for forbidden in ("delete", "empty", "send", "trash", "draft", "untrash"):
            self.assertNotIn(forbidden, names)


if __name__ == "__main__":
    unittest.main()
