from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from typing import Any

from inboxlume.models import EmailCategory
from inboxlume.providers.contracts import GMAIL_MODIFY_SCOPE, GMAIL_READONLY_SCOPE
from inboxlume.providers.gmail_finalizer import (
    DirectGmailFinalizationTransport,
    DirectGmailTrashTransport,
    FinalizationOutcome,
    GmailDirectTrashExecutor,
    GmailFinalizationError,
    GmailQuarantineFinalizer,
    MatureQuarantineCandidate,
)
from inboxlume.providers.gmail_quarantine import (
    GMAIL_API_ORIGIN,
    LEGACY_QUARANTINE_LABEL_NAME,
    QUARANTINE_LABEL_NAME,
)


NOW = datetime(2026, 9, 2, 12, tzinfo=timezone.utc)


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


def mature_candidate(
    category: EmailCategory = EmailCategory.ADVERTISING,
    expected_unread: bool = False,
) -> MatureQuarantineCandidate:
    return MatureQuarantineCandidate(
        "abc123",
        category,
        NOW - timedelta(days=3),
        expected_unread,
    )


def quarantine_label_response() -> dict[str, Any]:
    return {
        "labels": [
            {
                "id": "Label_42",
                "name": QUARANTINE_LABEL_NAME,
                "type": "user",
            }
        ]
    }


class GmailFinalizerTests(unittest.TestCase):
    def test_requires_exact_modify_scope(self) -> None:
        with self.assertRaises(ValueError):
            GmailQuarantineFinalizer(FakeTokenProvider(GMAIL_READONLY_SCOPE))

    def test_refuses_before_three_full_days_without_api_calls(self) -> None:
        transport = QueueTransport([], [])
        finalizer = GmailQuarantineFinalizer(FakeTokenProvider(), transport)
        candidate = MatureQuarantineCandidate(
            "abc123",
            EmailCategory.ADVERTISING,
            NOW - timedelta(days=3) + timedelta(seconds=1),
            False,
        )
        with self.assertRaises(ValueError):
            finalizer.finalize(candidate, NOW)
        self.assertEqual(transport.get_calls, [])
        self.assertEqual(transport.post_calls, [])

    def test_moves_verified_advertising_to_trash_only(self) -> None:
        transport = QueueTransport(
            [
                {"id": "abc123", "labelIds": ["INBOX", "Label_42"]},
                quarantine_label_response(),
            ],
            [{"id": "abc123", "labelIds": ["TRASH", "Label_42"]}],
        )
        finalizer = GmailQuarantineFinalizer(FakeTokenProvider(), transport)
        result = finalizer.finalize(mature_candidate(), NOW)

        self.assertEqual(result.outcome, FinalizationOutcome.MOVED_TO_TRASH)
        self.assertTrue(result.changes_mailbox)
        self.assertEqual(len(transport.post_calls), 1)
        url, payload = transport.post_calls[0]
        self.assertEqual(url, f"{GMAIL_API_ORIGIN}/gmail/v1/users/me/messages/abc123/trash")
        self.assertEqual(payload, {})

    def test_moves_mature_expected_unread_that_is_still_unread(self) -> None:
        transport = QueueTransport(
            [
                {
                    "id": "abc123",
                    "labelIds": ["INBOX", "UNREAD", "Label_42"],
                },
                quarantine_label_response(),
            ],
            [
                {
                    "id": "abc123",
                    "labelIds": ["TRASH", "UNREAD", "Label_42"],
                }
            ],
        )

        result = GmailQuarantineFinalizer(
            FakeTokenProvider(), transport
        ).finalize(mature_candidate(expected_unread=True), NOW)

        self.assertEqual(result.outcome, FinalizationOutcome.MOVED_TO_TRASH)
        self.assertEqual(len(transport.post_calls), 1)

    def test_mature_expected_read_that_became_unread_is_cancelled(self) -> None:
        transport = QueueTransport(
            [
                {
                    "id": "abc123",
                    "labelIds": ["INBOX", "UNREAD", "Label_42"],
                }
            ],
            [],
        )

        result = GmailQuarantineFinalizer(
            FakeTokenProvider(), transport
        ).finalize(mature_candidate(expected_unread=False), NOW)

        self.assertEqual(result.outcome, FinalizationOutcome.CANCELLED_PROTECTED)
        self.assertEqual(transport.post_calls, [])

    def test_mature_expected_unread_that_became_read_is_cancelled(self) -> None:
        transport = QueueTransport(
            [{"id": "abc123", "labelIds": ["INBOX", "Label_42"]}],
            [],
        )

        result = GmailQuarantineFinalizer(
            FakeTokenProvider(), transport
        ).finalize(mature_candidate(expected_unread=True), NOW)

        self.assertEqual(result.outcome, FinalizationOutcome.CANCELLED_PROTECTED)
        self.assertEqual(transport.post_calls, [])

    def test_mature_routine_security_notice_uses_same_trash_path(self) -> None:
        transport = QueueTransport(
            [
                {"id": "abc123", "labelIds": ["INBOX", "Label_42"]},
                quarantine_label_response(),
            ],
            [{"id": "abc123", "labelIds": ["TRASH", "Label_42"]}],
        )
        result = GmailQuarantineFinalizer(
            FakeTokenProvider(), transport
        ).finalize(mature_candidate(EmailCategory.SECURITY), NOW)

        self.assertEqual(result.outcome, FinalizationOutcome.MOVED_TO_TRASH)

    def test_moves_only_explicit_spam_category_to_spam(self) -> None:
        transport = QueueTransport(
            [
                {"id": "abc123", "labelIds": ["INBOX", "Label_42"]},
                quarantine_label_response(),
            ],
            [{"id": "abc123", "labelIds": ["SPAM", "Label_42"]}],
        )
        finalizer = GmailQuarantineFinalizer(FakeTokenProvider(), transport)
        result = finalizer.finalize(mature_candidate(EmailCategory.SPAM), NOW)

        self.assertEqual(result.outcome, FinalizationOutcome.MOVED_TO_SPAM)
        url, payload = transport.post_calls[0]
        self.assertTrue(url.endswith("/messages/abc123/modify"))
        self.assertEqual(
            payload,
            {"addLabelIds": ["SPAM"], "removeLabelIds": ["INBOX"]},
        )

    def test_accepts_the_legacy_quarantine_label_during_rebranding(self) -> None:
        transport = QueueTransport(
            [
                {"id": "abc123", "labelIds": ["INBOX", "Label_legacy"]},
                {
                    "labels": [
                        {
                            "id": "Label_legacy",
                            "name": LEGACY_QUARANTINE_LABEL_NAME,
                            "type": "user",
                        }
                    ]
                },
            ],
            [{"id": "abc123", "labelIds": ["TRASH", "Label_legacy"]}],
        )

        result = GmailQuarantineFinalizer(
            FakeTokenProvider(), transport
        ).finalize(mature_candidate(), NOW)

        self.assertEqual(result.outcome, FinalizationOutcome.MOVED_TO_TRASH)

    def test_removing_visible_quarantine_label_cancels_action(self) -> None:
        transport = QueueTransport(
            [
                {"id": "abc123", "labelIds": ["INBOX"]},
                quarantine_label_response(),
            ],
            [],
        )
        finalizer = GmailQuarantineFinalizer(FakeTokenProvider(), transport)
        result = finalizer.finalize(mature_candidate(), NOW)

        self.assertEqual(result.outcome, FinalizationOutcome.CANCELLED_LABEL_REMOVED)
        self.assertFalse(result.changes_mailbox)
        self.assertEqual(transport.post_calls, [])

    def test_star_important_or_not_inbox_cancels_without_post(self) -> None:
        cases = (
            (["INBOX", "Label_42", "STARRED"], FinalizationOutcome.CANCELLED_PROTECTED),
            (["INBOX", "Label_42", "IMPORTANT"], FinalizationOutcome.CANCELLED_PROTECTED),
            (["Label_42"], FinalizationOutcome.CANCELLED_NOT_INBOX),
            (["INBOX", "Label_42", "SENT"], FinalizationOutcome.CANCELLED_NOT_INBOX),
        )
        for labels, expected in cases:
            with self.subTest(labels=labels):
                transport = QueueTransport(
                    [{"id": "abc123", "labelIds": labels}],
                    [],
                )
                finalizer = GmailQuarantineFinalizer(FakeTokenProvider(), transport)
                result = finalizer.finalize(mature_candidate(), NOW)
                self.assertEqual(result.outcome, expected)
                self.assertEqual(transport.post_calls, [])

    def test_transport_allows_only_exact_reversible_payloads(self) -> None:
        DirectGmailFinalizationTransport._validate_post(
            f"{GMAIL_API_ORIGIN}/gmail/v1/users/me/messages/abc/trash",
            {},
        )
        DirectGmailFinalizationTransport._validate_post(
            f"{GMAIL_API_ORIGIN}/gmail/v1/users/me/messages/abc/modify",
            {"addLabelIds": ["SPAM"], "removeLabelIds": ["INBOX"]},
        )
        forbidden = (
            f"{GMAIL_API_ORIGIN}/gmail/v1/users/me/messages/abc/delete",
            f"{GMAIL_API_ORIGIN}/gmail/v1/users/me/messages/abc/untrash",
            f"{GMAIL_API_ORIGIN}/gmail/v1/users/me/messages/batchDelete",
            f"{GMAIL_API_ORIGIN}/gmail/v1/users/me/drafts",
            f"{GMAIL_API_ORIGIN}/gmail/v1/users/me/messages/abc/send",
            f"{GMAIL_API_ORIGIN}/gmail/v1/users/me/settings",
        )
        for url in forbidden:
            with self.subTest(url=url), self.assertRaises(GmailFinalizationError):
                DirectGmailFinalizationTransport._validate_post(url, {})
        with self.assertRaises(GmailFinalizationError):
            DirectGmailFinalizationTransport._validate_post(
                f"{GMAIL_API_ORIGIN}/gmail/v1/users/me/messages/abc/trash",
                {"deleteForever": True},
            )
        with self.assertRaises(GmailFinalizationError):
            DirectGmailFinalizationTransport._validate_post(
                f"{GMAIL_API_ORIGIN}/gmail/v1/users/me/messages/abc/modify",
                {"addLabelIds": [], "removeLabelIds": ["INBOX"]},
            )

    def test_public_surface_exposes_only_finalize(self) -> None:
        names = {
            name.casefold()
            for name in dir(GmailQuarantineFinalizer)
            if not name.startswith("_")
        }
        self.assertEqual(names, {"finalize"})

    def test_direct_trash_rechecks_read_inbox_and_moves_without_quarantine_label(self) -> None:
        transport = QueueTransport(
            [{"id": "abc123", "labelIds": ["INBOX"]}],
            [{"id": "abc123", "labelIds": ["TRASH"]}],
        )
        executor = GmailDirectTrashExecutor(FakeTokenProvider(), transport)
        result = executor.apply("abc123", expected_unread=False)

        self.assertEqual(result.outcome, FinalizationOutcome.MOVED_TO_TRASH)
        self.assertEqual(
            transport.post_calls,
            [(f"{GMAIL_API_ORIGIN}/gmail/v1/users/me/messages/abc123/trash", {})],
        )

    def test_direct_trash_moves_expected_unread_that_is_still_unread(self) -> None:
        transport = QueueTransport(
            [{"id": "abc123", "labelIds": ["INBOX", "UNREAD"]}],
            [{"id": "abc123", "labelIds": ["TRASH", "UNREAD"]}],
        )

        result = GmailDirectTrashExecutor(
            FakeTokenProvider(), transport
        ).apply("abc123", expected_unread=True)

        self.assertEqual(result.outcome, FinalizationOutcome.MOVED_TO_TRASH)
        self.assertEqual(len(transport.post_calls), 1)

    def test_direct_trash_refuses_expected_read_that_became_unread(self) -> None:
        transport = QueueTransport(
            [{"id": "abc123", "labelIds": ["INBOX", "UNREAD"]}],
            [],
        )

        result = GmailDirectTrashExecutor(
            FakeTokenProvider(), transport
        ).apply("abc123", expected_unread=False)

        self.assertEqual(result.outcome, FinalizationOutcome.CANCELLED_PROTECTED)
        self.assertEqual(transport.post_calls, [])

    def test_direct_trash_refuses_expected_unread_that_became_read(self) -> None:
        transport = QueueTransport(
            [{"id": "abc123", "labelIds": ["INBOX"]}],
            [],
        )

        result = GmailDirectTrashExecutor(
            FakeTokenProvider(), transport
        ).apply("abc123", expected_unread=True)

        self.assertEqual(result.outcome, FinalizationOutcome.CANCELLED_PROTECTED)
        self.assertEqual(transport.post_calls, [])

    def test_direct_trash_refuses_protected_sent_and_non_inbox_messages(self) -> None:
        cases = (
            (["INBOX", "STARRED"], FinalizationOutcome.CANCELLED_PROTECTED),
            (["INBOX", "IMPORTANT"], FinalizationOutcome.CANCELLED_PROTECTED),
            (["INBOX", "SENT"], FinalizationOutcome.CANCELLED_NOT_INBOX),
            (["TRASH"], FinalizationOutcome.ALREADY_FINALIZED),
        )
        for labels, expected in cases:
            with self.subTest(labels=labels):
                transport = QueueTransport(
                    [{"id": "abc123", "labelIds": labels}],
                    [],
                )
                result = GmailDirectTrashExecutor(
                    FakeTokenProvider(), transport
                ).apply("abc123", expected_unread=False)
                self.assertEqual(result.outcome, expected)
                self.assertEqual(transport.post_calls, [])

    def test_direct_trash_transport_rejects_all_non_trash_mutations(self) -> None:
        DirectGmailTrashTransport._validate_post(
            f"{GMAIL_API_ORIGIN}/gmail/v1/users/me/messages/abc/trash",
            {},
        )
        forbidden = (
            f"{GMAIL_API_ORIGIN}/gmail/v1/users/me/messages/abc/delete",
            f"{GMAIL_API_ORIGIN}/gmail/v1/users/me/messages/abc/untrash",
            f"{GMAIL_API_ORIGIN}/gmail/v1/users/me/messages/abc/modify",
            f"{GMAIL_API_ORIGIN}/gmail/v1/users/me/messages/batchDelete",
            f"{GMAIL_API_ORIGIN}/gmail/v1/users/me/messages/abc/send",
            f"{GMAIL_API_ORIGIN}/gmail/v1/users/me/settings",
        )
        for url in forbidden:
            with self.subTest(url=url), self.assertRaises(GmailFinalizationError):
                DirectGmailTrashTransport._validate_post(url, {})
        with self.assertRaises(GmailFinalizationError):
            DirectGmailTrashTransport._validate_post(
                f"{GMAIL_API_ORIGIN}/gmail/v1/users/me/messages/abc/trash",
                {"deleteForever": True},
            )

    def test_direct_trash_requires_exact_modify_scope(self) -> None:
        with self.assertRaises(ValueError):
            GmailDirectTrashExecutor(FakeTokenProvider(GMAIL_READONLY_SCOPE))


if __name__ == "__main__":
    unittest.main()
