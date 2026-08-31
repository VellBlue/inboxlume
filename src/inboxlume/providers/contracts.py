from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from enum import StrEnum
from typing import Callable, Protocol

from ..models import EmailRecord


GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
GMAIL_MODIFY_SCOPE = "https://www.googleapis.com/auth/gmail.modify"
YAHOO_IMAP_HOST = "imap.mail.yahoo.com"
YAHOO_IMAP_PORT = 993
INBOX_FOLDER = "INBOX"


class ReadOnlyCapability(StrEnum):
    LIST_UNREAD = "list_unread"
    FETCH_METADATA = "fetch_metadata"
    FETCH_BODY = "fetch_body"


READ_ONLY_CAPABILITIES = frozenset(ReadOnlyCapability)


class ReadOnlyMailbox(Protocol):
    """Il contratto espone soltanto candidati della Posta in arrivo."""

    @property
    def capabilities(self) -> frozenset[ReadOnlyCapability]: ...

    def iter_inbox_unread_before(
        self,
        before: datetime,
        limit: int,
        skip_message_id: Callable[[str], bool] | None = None,
        search_limit: int | None = None,
        oldest_first: bool = False,
    ) -> Iterator[EmailRecord]: ...

    def iter_inbox_read_one_time_code_candidates_before(
        self,
        before: datetime,
        limit: int,
        skip_message_id: Callable[[str], bool] | None = None,
        search_limit: int | None = None,
        oldest_first: bool = False,
    ) -> Iterator[EmailRecord]: ...

    def iter_inbox_read_routine_access_alert_candidates_before(
        self,
        before: datetime,
        limit: int,
        skip_message_id: Callable[[str], bool] | None = None,
        search_limit: int | None = None,
        oldest_first: bool = False,
    ) -> Iterator[EmailRecord]: ...

    def iter_inbox_quiz_sample(
        self,
        limit: int,
        old_unread_before: datetime | None = None,
        skip_message_id: Callable[[str], bool] | None = None,
        search_limit: int | None = None,
    ) -> Iterator[EmailRecord]: ...

    def iter_inbox_shadow_review_sample(
        self,
        unread_before: datetime,
        read_otp_before: datetime,
        read_access_before: datetime,
        limit: int,
        search_limit: int,
        record_for_id: Callable[[str], tuple[str, str] | None],
    ) -> Iterator[tuple[EmailRecord, str, str]]: ...

    def iter_inbox_matching_candidate_ids(
        self,
        unread_before: datetime,
        read_otp_before: datetime,
        read_access_before: datetime,
        limit: int,
        search_limit: int,
        include_message_id: Callable[[str, bool], bool],
    ) -> Iterator[str]: ...

    def count_inbox_unprocessed_candidate_ids(
        self,
        unread_before: datetime,
        read_otp_before: datetime,
        read_access_before: datetime,
        was_scanned: Callable[[str], bool],
        maximum: int | None = None,
    ) -> tuple[int, bool]: ...
