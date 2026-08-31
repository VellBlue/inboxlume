from __future__ import annotations

import imaplib
import re
from dataclasses import dataclass
from enum import StrEnum

from ..tls_trust import default_tls_context
from .contracts import INBOX_FOLDER, YAHOO_IMAP_HOST, YAHOO_IMAP_PORT
from .yahoo import (
    YAHOO_QUARANTINE_FOLDER,
    YahooImapCredentials,
    YahooImapError,
    parse_yahoo_message_id,
)


YAHOO_TRASH_FOLDER = "Trash"
_UID = re.compile(r"[1-9][0-9]{0,19}")


class YahooQuarantineOutcome(StrEnum):
    APPLIED = "applied"
    SKIPPED_NOT_INBOX = "skipped_not_inbox"
    SKIPPED_PROTECTED = "skipped_protected"


@dataclass(frozen=True, slots=True)
class YahooQuarantineResult:
    outcome: YahooQuarantineOutcome


class YahooQuarantineExecutor:
    """Può soltanto spostare UID dalla Inbox alla cartella di quarantena esatta."""

    def __init__(
        self,
        credentials: YahooImapCredentials,
        client: imaplib.IMAP4_SSL | None = None,
    ) -> None:
        if client is None:
            client = imaplib.IMAP4_SSL(
                YAHOO_IMAP_HOST,
                YAHOO_IMAP_PORT,
                ssl_context=default_tls_context(),
                timeout=30,
            )
        self._client = client
        self._closed = False
        try:
            status, _ = self._client.login(
                credentials.email_address.strip(), credentials.app_password
            )
            if status != "OK":
                raise YahooImapError("accesso IMAP Yahoo operativo rifiutato")
            capabilities = {
                item.decode("ascii", "ignore").upper()
                if isinstance(item, bytes) else str(item).upper()
                for item in getattr(self._client, "capabilities", ())
            }
            if "MOVE" not in capabilities:
                raise YahooImapError(
                    "Yahoo non dichiara MOVE: quarantena disabilitata senza fallback distruttivi"
                )
            self._ensure_quarantine_folder()
            self._select_inbox()
            self.uid_validity = self._read_uid_validity()
        except Exception:
            self.close()
            raise

    def _ensure_quarantine_folder(self) -> None:
        status, _ = self._client.select(YAHOO_QUARANTINE_FOLDER, readonly=True)
        if status == "OK":
            return
        status, _ = self._client.create(YAHOO_QUARANTINE_FOLDER)
        if status != "OK":
            raise YahooImapError("cartella Quarantena Yahoo non creabile")

    def _select_inbox(self) -> None:
        status, _ = self._client.select(INBOX_FOLDER, readonly=False)
        if status != "OK":
            raise YahooImapError("Inbox Yahoo operativa non accessibile")

    def _read_uid_validity(self) -> str:
        _, data = self._client.response("UIDVALIDITY")
        if not data or not isinstance(data[0], bytes):
            raise YahooImapError("UIDVALIDITY Yahoo operativo assente")
        value = data[0].decode("ascii", "strict")
        if _UID.fullmatch(value) is None:
            raise YahooImapError("UIDVALIDITY Yahoo operativo non valido")
        return value

    def apply_quarantine(
        self,
        message_id: str,
        expected_unread: bool,
    ) -> YahooQuarantineResult:
        if type(expected_unread) is not bool:
            raise YahooImapError("stato unread Yahoo atteso non valido")
        uid_validity, uid = parse_yahoo_message_id(message_id)
        if uid_validity != self.uid_validity:
            return YahooQuarantineResult(YahooQuarantineOutcome.SKIPPED_NOT_INBOX)
        status, data = self._client.uid("FETCH", uid, "(UID FLAGS)")
        if status != "OK" or not isinstance(data, list):
            raise YahooImapError("verifica messaggio Yahoo fallita")
        metadata = b" ".join(item for item in data if isinstance(item, bytes))
        uid_match = re.search(rb"\bUID ([0-9]+)\b", metadata)
        flags_match = re.search(rb"\bFLAGS \(([^)]*)\)", metadata)
        if uid_match is None:
            return YahooQuarantineResult(YahooQuarantineOutcome.SKIPPED_NOT_INBOX)
        if uid_match.group(1).decode("ascii") != uid or flags_match is None:
            raise YahooImapError("metadati operativi Yahoo non validi")
        flags = {item.casefold() for item in flags_match.group(1).decode("ascii").split()}
        currently_unread = "\\seen" not in flags
        # The selected read state is part of the mutation authority.  Reject
        # drift in either direction at the final FETCH before MOVE.
        if (
            currently_unread is not expected_unread
            or "\\flagged" in flags
            or "$important" in flags
            or "important" in flags
        ):
            return YahooQuarantineResult(YahooQuarantineOutcome.SKIPPED_PROTECTED)
        # UIDPLUS returns the destination UID in the tagged OK line, which
        # imaplib.uid() discards, so the move reports no pointer.  Review
        # relocates a moved proposal by its RFC Message-ID instead.
        status, _ = self._client.uid("MOVE", uid, YAHOO_QUARANTINE_FOLDER)
        if status != "OK":
            raise YahooImapError("spostamento nella Quarantena Yahoo fallito")
        return YahooQuarantineResult(YahooQuarantineOutcome.APPLIED)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._client.logout()
        except Exception:
            pass


class YahooThreatMarkerOutcome(StrEnum):
    APPLIED = "applied"
    ALREADY_APPLIED = "already_applied"
    SKIPPED_NOT_INBOX = "skipped_not_inbox"


@dataclass(frozen=True, slots=True)
class YahooThreatMarkerResult:
    outcome: YahooThreatMarkerOutcome


class YahooThreatMarkerExecutor:
    """Add ``\\Flagged`` to a high-risk Inbox UID without moving it.

    ``+FLAGS.SILENT`` is additive, so existing flags remain untouched.  This
    executor never invokes MOVE, COPY, EXPUNGE, DELETE, or a mailbox create.
    """

    def __init__(
        self,
        credentials: YahooImapCredentials,
        client: imaplib.IMAP4_SSL | None = None,
    ) -> None:
        if client is None:
            client = imaplib.IMAP4_SSL(
                YAHOO_IMAP_HOST,
                YAHOO_IMAP_PORT,
                ssl_context=default_tls_context(),
                timeout=30,
            )
        self._client = client
        self._closed = False
        try:
            status, _ = self._client.login(
                credentials.email_address.strip(), credentials.app_password
            )
            if status != "OK":
                raise YahooImapError("accesso IMAP Yahoo per avviso phishing rifiutato")
            self._select_inbox()
            self.uid_validity = self._read_uid_validity()
        except Exception:
            self.close()
            raise

    def _select_inbox(self) -> None:
        status, _ = self._client.select(INBOX_FOLDER, readonly=False)
        if status != "OK":
            raise YahooImapError("Inbox Yahoo per avviso phishing non accessibile")

    def _read_uid_validity(self) -> str:
        _, data = self._client.response("UIDVALIDITY")
        if not data or not isinstance(data[0], bytes):
            raise YahooImapError("UIDVALIDITY Yahoo per avviso phishing assente")
        value = data[0].decode("ascii", "strict")
        if _UID.fullmatch(value) is None:
            raise YahooImapError("UIDVALIDITY Yahoo per avviso phishing non valido")
        return value

    def apply(self, message_id: str) -> YahooThreatMarkerResult:
        uid_validity, uid = parse_yahoo_message_id(message_id)
        if uid_validity != self.uid_validity:
            return YahooThreatMarkerResult(YahooThreatMarkerOutcome.SKIPPED_NOT_INBOX)
        status, data = self._client.uid("FETCH", uid, "(UID FLAGS)")
        if status != "OK" or not isinstance(data, list):
            raise YahooImapError("verifica messaggio Yahoo per avviso phishing fallita")
        metadata = b" ".join(item for item in data if isinstance(item, bytes))
        uid_match = re.search(rb"\bUID ([0-9]+)\b", metadata)
        flags_match = re.search(rb"\bFLAGS \(([^)]*)\)", metadata)
        if uid_match is None:
            return YahooThreatMarkerResult(YahooThreatMarkerOutcome.SKIPPED_NOT_INBOX)
        if uid_match.group(1).decode("ascii") != uid or flags_match is None:
            raise YahooImapError("metadati Yahoo per avviso phishing non validi")
        flags = {item.casefold() for item in flags_match.group(1).decode("ascii").split()}
        if "\\flagged" in flags:
            return YahooThreatMarkerResult(YahooThreatMarkerOutcome.ALREADY_APPLIED)
        status, _ = self._client.uid("STORE", uid, "+FLAGS.SILENT", "(\\Flagged)")
        if status != "OK":
            raise YahooImapError("marcatura phishing Yahoo fallita")
        return YahooThreatMarkerResult(YahooThreatMarkerOutcome.APPLIED)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._client.logout()
        except Exception:
            pass


class YahooTrashOutcome(StrEnum):
    MOVED_TO_TRASH = "moved_to_trash"
    SKIPPED_NOT_INBOX = "skipped_not_inbox"
    SKIPPED_PROTECTED = "skipped_protected"


@dataclass(frozen=True, slots=True)
class YahooTrashResult:
    outcome: YahooTrashOutcome


class YahooDirectTrashExecutor:
    """Sposta solo dalla Inbox al Cestino Yahoo esistente tramite UID MOVE."""

    def __init__(
        self,
        credentials: YahooImapCredentials,
        client: imaplib.IMAP4_SSL | None = None,
    ) -> None:
        if client is None:
            client = imaplib.IMAP4_SSL(
                YAHOO_IMAP_HOST,
                YAHOO_IMAP_PORT,
                ssl_context=default_tls_context(),
                timeout=30,
            )
        self._client = client
        self._closed = False
        try:
            status, _ = self._client.login(
                credentials.email_address.strip(), credentials.app_password
            )
            if status != "OK":
                raise YahooImapError("accesso IMAP Yahoo operativo rifiutato")
            capabilities = {
                item.decode("ascii", "ignore").upper()
                if isinstance(item, bytes) else str(item).upper()
                for item in getattr(self._client, "capabilities", ())
            }
            if "MOVE" not in capabilities:
                raise YahooImapError(
                    "Yahoo non dichiara MOVE: Cestino disabilitato senza fallback distruttivi"
                )
            status, _ = self._client.select(YAHOO_TRASH_FOLDER, readonly=True)
            if status != "OK":
                raise YahooImapError("cartella Cestino Yahoo esatta non accessibile")
            status, _ = self._client.select(INBOX_FOLDER, readonly=False)
            if status != "OK":
                raise YahooImapError("Inbox Yahoo operativa non accessibile")
            _, data = self._client.response("UIDVALIDITY")
            if not data or not isinstance(data[0], bytes):
                raise YahooImapError("UIDVALIDITY Yahoo operativo assente")
            self.uid_validity = data[0].decode("ascii", "strict")
            if _UID.fullmatch(self.uid_validity) is None:
                raise YahooImapError("UIDVALIDITY Yahoo operativo non valido")
        except Exception:
            self.close()
            raise

    def apply(
        self,
        message_id: str,
        expected_unread: bool,
    ) -> YahooTrashResult:
        if type(expected_unread) is not bool:
            raise YahooImapError("stato unread Yahoo atteso non valido")
        uid_validity, uid = parse_yahoo_message_id(message_id)
        if uid_validity != self.uid_validity:
            return YahooTrashResult(YahooTrashOutcome.SKIPPED_NOT_INBOX)
        status, data = self._client.uid("FETCH", uid, "(UID FLAGS)")
        if status != "OK" or not isinstance(data, list):
            raise YahooImapError("verifica messaggio Yahoo fallita")
        metadata = b" ".join(item for item in data if isinstance(item, bytes))
        uid_match = re.search(rb"\bUID ([0-9]+)\b", metadata)
        flags_match = re.search(rb"\bFLAGS \(([^)]*)\)", metadata)
        if uid_match is None:
            return YahooTrashResult(YahooTrashOutcome.SKIPPED_NOT_INBOX)
        if uid_match.group(1).decode("ascii") != uid or flags_match is None:
            raise YahooImapError("metadati operativi Yahoo non validi")
        flags = {item.casefold() for item in flags_match.group(1).decode("ascii").split()}
        currently_unread = "\\seen" not in flags
        # Trash uses the same exact-state guard as reversible quarantine.
        if (
            currently_unread is not expected_unread
            or "\\flagged" in flags
            or "$important" in flags
            or "important" in flags
        ):
            return YahooTrashResult(YahooTrashOutcome.SKIPPED_PROTECTED)
        status, _ = self._client.uid("MOVE", uid, YAHOO_TRASH_FOLDER)
        if status != "OK":
            raise YahooImapError("spostamento nel Cestino Yahoo fallito")
        return YahooTrashResult(YahooTrashOutcome.MOVED_TO_TRASH)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._client.logout()
        except Exception:
            pass
