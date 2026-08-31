from __future__ import annotations

import email
import imaplib
import json
import re
import ssl
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from email import policy as email_policy
from email.message import Message
from typing import Callable, Protocol

from ..models import EmailRecord, ProviderKind
from ..sanitizer import normalize_plain_text, sanitize_body
from .contracts import (
    INBOX_FOLDER,
    READ_ONLY_CAPABILITIES,
    YAHOO_IMAP_HOST,
    YAHOO_IMAP_PORT,
)
from .google_oauth import SecretStore


# Identificatore legacy intenzionalmente stabile per riutilizzare in sicurezza la
# password per app gia custodita dal gestore credenziali del sistema.
YAHOO_CREDENTIALS_KEYCHAIN_SERVICE = "it.local.mail-guardian.yahoo.imap.v1"
MAX_MESSAGE_BYTES = 2_000_000
_ACCOUNT_ID = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_UID = re.compile(r"[1-9][0-9]{0,19}")
_MESSAGE_ID = re.compile(r"([1-9][0-9]{0,19}):([1-9][0-9]{0,19})")
_OTP_TERMS = ("code", "codice", "otp", "verifica", "monouso")
_ACCESS_TERMS = (
    "new sign-in",
    "new login",
    "nuovo accesso",
    "accesso rilevato",
    "sign-in detected",
    "login detected",
    "accesso effettuato",
    "attività di accesso",
    "avviso di accesso",
    "access alert",
    "hai effettuato l'accesso",
    "you logged in",
    "used to sign in",
)
def _quoted_search_string(value: str) -> str:
    """Send a SEARCH argument as one IMAP quoted string.

    imaplib joins criteria with spaces, so an unquoted multi-word subject term
    reaches the server as several arguments and the whole SEARCH is rejected
    with BAD.  Every access-alert term is multi-word, so that failure aborted
    the batch on a real Yahoo server.
    """

    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


# Stable local folder used for reversible Yahoo quarantine. It is separate from
# Trash; InboxLume never expunges or empties either folder.
YAHOO_QUARANTINE_FOLDER = "InboxLume-Quarantena"
_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


class YahooImapError(RuntimeError):
    pass


class YahooTransportError(YahooImapError):
    """Session/search failure: callers must fail the run, never treat it as empty."""


class YahooMessageReadError(YahooImapError):
    """One malformed or oversized message that may be skipped and retried later."""


@dataclass(frozen=True, slots=True)
class YahooInboxIdentitySync:
    """Header-only reconciliation batch for messages newly present in Inbox."""

    uid_validity: str
    identities: tuple[str, ...]
    latest_processed_uid: str
    has_more: bool


@dataclass(frozen=True, slots=True)
class YahooImapCredentials:
    email_address: str
    app_password: str

    def __post_init__(self) -> None:
        address = self.email_address.strip()
        if (
            not 3 <= len(address) <= 320
            or address.count("@") != 1
            or any(char.isspace() or ord(char) < 32 for char in address)
        ):
            raise ValueError("indirizzo Yahoo non valido")
        if (
            not 8 <= len(self.app_password) <= 128
            or any(ord(char) < 32 for char in self.app_password)
        ):
            raise ValueError("password per app Yahoo non valida")

    def to_json(self) -> str:
        return json.dumps(
            {
                "email_address": self.email_address.strip(),
                "app_password": self.app_password,
                "version": 1,
            },
            separators=(",", ":"),
            sort_keys=True,
        )

    @classmethod
    def from_json(cls, value: str) -> YahooImapCredentials:
        try:
            raw = json.loads(value)
        except json.JSONDecodeError as exc:
            raise YahooImapError("credenziali Yahoo nel Portachiavi non valide") from exc
        if not isinstance(raw, dict) or raw.get("version") != 1:
            raise YahooImapError("credenziali Yahoo nel Portachiavi non valide")
        try:
            return cls(str(raw["email_address"]), str(raw["app_password"]))
        except (KeyError, ValueError) as exc:
            raise YahooImapError("credenziali Yahoo nel Portachiavi non valide") from exc


def save_yahoo_credentials(
    store: SecretStore,
    account_id: str,
    credentials: YahooImapCredentials,
) -> None:
    if not _ACCOUNT_ID.fullmatch(account_id):
        raise ValueError("account_id Yahoo non valido")
    store.set(YAHOO_CREDENTIALS_KEYCHAIN_SERVICE, account_id, credentials.to_json())


def load_yahoo_credentials(store: SecretStore, account_id: str) -> YahooImapCredentials:
    if not _ACCOUNT_ID.fullmatch(account_id):
        raise ValueError("account_id Yahoo non valido")
    raw = store.get(YAHOO_CREDENTIALS_KEYCHAIN_SERVICE, account_id)
    if raw is None:
        raise YahooImapError("account Yahoo non ancora configurato")
    return YahooImapCredentials.from_json(raw)


class YahooReadTransport(Protocol):
    uid_validity: str
    capabilities: frozenset[str]

    def search(self, *criteria: str) -> list[str]: ...

    def fetch_message(self, uid: str, account_id: str) -> EmailRecord | None: ...

    def fetch_message_identity(self, uid: str) -> str | None: ...

    def inbox_count(self) -> int: ...

    def close(self) -> None: ...


def yahoo_message_id(uid_validity: str, uid: str) -> str:
    if not _UID.fullmatch(uid_validity) or not _UID.fullmatch(uid):
        raise YahooImapError("identificativo UID Yahoo non valido")
    return f"{uid_validity}:{uid}"


def parse_yahoo_message_id(message_id: str) -> tuple[str, str]:
    match = _MESSAGE_ID.fullmatch(message_id)
    if match is None:
        raise YahooImapError("identificativo messaggio Yahoo non valido")
    return match.group(1), match.group(2)


class DirectYahooImapReadTransport:
    """Sessione IMAP TLS fissata a una sola cartella selezionata read-only."""

    def __init__(
        self,
        credentials: YahooImapCredentials,
        client: imaplib.IMAP4_SSL | None = None,
        *,
        folder: str = INBOX_FOLDER,
    ) -> None:
        self._credentials = credentials
        if not folder or any(char in folder for char in "\r\n"):
            raise ValueError("cartella Yahoo non valida")
        self.folder = folder
        # A supplied client is a test seam.  Real sessions may reconnect once
        # after a transient Yahoo IMAP transport failure.
        self._can_reconnect = client is None
        if client is None:
            client = self._new_client()
        self._client = client
        self._closed = False
        try:
            status, _ = self._client.login(
                credentials.email_address.strip(), credentials.app_password
            )
            if status != "OK":
                raise YahooImapError("accesso IMAP Yahoo rifiutato")
            self.capabilities = frozenset(
                item.decode("ascii", "ignore").upper()
                if isinstance(item, bytes) else str(item).upper()
                for item in getattr(self._client, "capabilities", ())
            )
            status, _ = self._client.select(self.folder, readonly=True)
            if status != "OK":
                raise YahooImapError("cartella Yahoo non accessibile in sola lettura")
            self.uid_validity = self._read_uid_validity()
        except imaplib.IMAP4.abort as exc:
            self.close()
            raise YahooImapError("connessione IMAP Yahoo interrotta; riprova il controllo") from exc
        except (imaplib.IMAP4.error, OSError, ssl.SSLError) as exc:
            self.close()
            raise YahooImapError("connessione IMAP Yahoo non disponibile; riprova il controllo") from exc
        except Exception:
            self.close()
            raise

    @staticmethod
    def _new_client() -> imaplib.IMAP4_SSL:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return imaplib.IMAP4_SSL(
            YAHOO_IMAP_HOST,
            YAHOO_IMAP_PORT,
            ssl_context=context,
            timeout=30,
        )

    @staticmethod
    def _capabilities(client: imaplib.IMAP4_SSL) -> frozenset[str]:
        return frozenset(
            item.decode("ascii", "ignore").upper()
            if isinstance(item, bytes)
            else str(item).upper()
            for item in getattr(client, "capabilities", ())
        )

    @staticmethod
    def _uid_validity_from_response(data: object) -> str:
        if not data or not isinstance(data, list) or not isinstance(data[0], bytes):
            raise YahooImapError("UIDVALIDITY Yahoo assente")
        value = data[0].decode("ascii", "strict")
        if not _UID.fullmatch(value):
            raise YahooImapError("UIDVALIDITY Yahoo non valido")
        return value

    def _reconnect_once(self) -> bool:
        """Restore one read-only session; reject an unexpected UID namespace."""

        if not self._can_reconnect or self._closed:
            return False
        previous_uid_validity = getattr(self, "uid_validity", None)
        if not isinstance(previous_uid_validity, str):
            return False
        try:
            try:
                self._client.logout()
            except Exception:
                pass
            client = self._new_client()
            status, _ = client.login(
                self._credentials.email_address.strip(),
                self._credentials.app_password,
            )
            if status != "OK":
                return False
            status, _ = client.select(self.folder, readonly=True)
            if status != "OK":
                return False
            _, data = client.response("UIDVALIDITY")
            uid_validity = self._uid_validity_from_response(data)
            if uid_validity != previous_uid_validity:
                try:
                    client.logout()
                except Exception:
                    pass
                return False
            self._client = client
            self.capabilities = self._capabilities(client)
            return True
        except (imaplib.IMAP4.error, OSError, ssl.SSLError, UnicodeError):
            return False

    def _retry_after_transport_failure(
        self,
        operation: Callable[[], tuple[object, object]],
    ) -> tuple[object, object] | None:
        if not self._reconnect_once():
            return None
        try:
            return operation()
        except (imaplib.IMAP4.abort, imaplib.IMAP4.error, OSError, ssl.SSLError):
            return None

    def _uid(self, command: str, *arguments: object) -> tuple[object, object]:
        """Run one read-only IMAP command without leaking server diagnostics."""

        try:
            return self._client.uid(command, *arguments)
        except imaplib.IMAP4.abort as exc:
            retried = self._retry_after_transport_failure(
                lambda: self._client.uid(command, *arguments)
            )
            if retried is not None:
                return retried
            raise YahooTransportError(
                "connessione IMAP Yahoo interrotta durante il controllo; riprova il lotto"
            ) from exc
        except (imaplib.IMAP4.error, OSError, ssl.SSLError) as exc:
            retried = self._retry_after_transport_failure(
                lambda: self._client.uid(command, *arguments)
            )
            if retried is not None:
                return retried
            raise YahooTransportError(
                "lettura IMAP Yahoo non riuscita; riprova il lotto"
            ) from exc

    def _response(self, name: str) -> tuple[object, object]:
        try:
            return self._client.response(name)
        except imaplib.IMAP4.abort as exc:
            retried = self._retry_after_transport_failure(
                lambda: self._client.response(name)
            )
            if retried is not None:
                return retried
            raise YahooTransportError("connessione IMAP Yahoo interrotta; riprova il controllo") from exc
        except (imaplib.IMAP4.error, OSError, ssl.SSLError) as exc:
            retried = self._retry_after_transport_failure(
                lambda: self._client.response(name)
            )
            if retried is not None:
                return retried
            raise YahooTransportError("lettura IMAP Yahoo non riuscita; riprova il controllo") from exc

    def _read_uid_validity(self) -> str:
        _, data = self._response("UIDVALIDITY")
        return self._uid_validity_from_response(data)

    def inbox_count(self) -> int:
        _, data = self._response("EXISTS")
        if not data or not isinstance(data[0], bytes):
            return 0
        value = data[0].decode("ascii", "strict")
        return int(value) if value.isdigit() else 0

    def search(self, *criteria: str) -> list[str]:
        allowed = {"ALL", "UNSEEN", "SEEN", "BEFORE", "SUBJECT"}
        if not criteria or any(
            not item or "\r" in item or "\n" in item for item in criteria
        ):
            raise YahooImapError("criteri ricerca Yahoo non validi")
        for index, item in enumerate(criteria):
            if index == 0 or criteria[index - 1] not in {"BEFORE", "SUBJECT"}:
                if item not in allowed:
                    raise YahooImapError("criterio ricerca Yahoo non consentito")
        prepared = tuple(
            _quoted_search_string(item)
            if index > 0 and criteria[index - 1] == "SUBJECT"
            else item
            for index, item in enumerate(criteria)
        )
        status, data = self._uid("SEARCH", None, *prepared)
        if status != "OK" or not data or not isinstance(data[0], bytes):
            raise YahooTransportError("ricerca Inbox Yahoo fallita")
        uids = data[0].decode("ascii", "strict").split()
        if any(_UID.fullmatch(uid) is None for uid in uids):
            raise YahooImapError("UID Yahoo non valido nella ricerca")
        return sorted(set(uids), key=int, reverse=True)

    @staticmethod
    def _fetch_bytes(data: object) -> bytes:
        if not isinstance(data, list):
            raise YahooMessageReadError("risposta FETCH Yahoo non valida")
        for item in data:
            if isinstance(item, tuple) and len(item) == 2 and isinstance(item[1], bytes):
                return item[1]
        raise YahooMessageReadError("contenuto FETCH Yahoo mancante")

    def _metadata(self, uid: str) -> tuple[frozenset[str], datetime, int]:
        status, data = self._uid(
            "FETCH", uid, "(UID FLAGS INTERNALDATE RFC822.SIZE)"
        )
        if status != "OK" or not isinstance(data, list):
            raise YahooMessageReadError("metadati Yahoo non accessibili")
        header = next(
            (item[0] for item in data if isinstance(item, tuple) and isinstance(item[0], bytes)),
            None,
        )
        if header is None:
            header = next((item for item in data if isinstance(item, bytes)), None)
        if header is None:
            raise YahooMessageReadError("metadati Yahoo mancanti")
        uid_match = re.search(rb"\bUID ([0-9]+)\b", header)
        flags_match = re.search(rb"\bFLAGS \(([^)]*)\)", header)
        date_match = re.search(
            rb'\bINTERNALDATE "([0-9]{1,2})-([A-Za-z]{3})-([0-9]{4}) '
            rb'([0-9]{2}):([0-9]{2}):([0-9]{2}) ([+-])([0-9]{2})([0-9]{2})"',
            header,
        )
        size_match = re.search(rb"\bRFC822\.SIZE ([0-9]+)\b", header)
        if not uid_match or uid_match.group(1).decode() != uid or not flags_match or not date_match or not size_match:
            raise YahooMessageReadError("metadati Yahoo non validi")
        flags = frozenset(flags_match.group(1).decode("ascii", "strict").split())
        month = _MONTHS.get(date_match.group(2).decode("ascii", "strict").title())
        if month is None:
            raise YahooMessageReadError("mese INTERNALDATE Yahoo non valido")
        offset_minutes = int(date_match.group(8)) * 60 + int(date_match.group(9))
        if date_match.group(7) == b"-":
            offset_minutes *= -1
        from datetime import timedelta

        received_at = datetime(
            int(date_match.group(3)), month, int(date_match.group(1)),
            int(date_match.group(4)), int(date_match.group(5)), int(date_match.group(6)),
            tzinfo=timezone(timedelta(minutes=offset_minutes)),
        ).astimezone(timezone.utc)
        size = int(size_match.group(1))
        if size < 0 or size > MAX_MESSAGE_BYTES:
            raise YahooMessageReadError("messaggio Yahoo oltre il limite locale")
        return flags, received_at, size

    def fetch_message(self, uid: str, account_id: str) -> EmailRecord | None:
        if _UID.fullmatch(uid) is None:
            raise YahooMessageReadError("UID Yahoo non valido")
        flags, received_at, _ = self._metadata(uid)
        status, data = self._uid("FETCH", uid, "(UID BODY.PEEK[])")
        if status != "OK":
            raise YahooMessageReadError("lettura messaggio Yahoo fallita")
        raw = self._fetch_bytes(data)
        if len(raw) > MAX_MESSAGE_BYTES:
            raise YahooMessageReadError("messaggio Yahoo oltre il limite locale")
        parsed = email.message_from_bytes(raw, policy=email_policy.default)
        sender = normalize_plain_text(str(parsed.get("From", "")), max_chars=500)
        subject = normalize_plain_text(str(parsed.get("Subject", "")), max_chars=1_000)
        body_text, has_attachment = _message_body(parsed)
        public_flags: set[str] = set()
        if "\\Flagged" in flags:
            public_flags.add("STARRED")
        if any(flag.casefold() in {"$important", "important"} for flag in flags):
            public_flags.add("IMPORTANT")
        headers = {
            key: normalize_plain_text(str(value), max_chars=1_000)
            for key, value in parsed.items()
            if key.casefold() in {
                "from",
                "to",
                "cc",
                "bcc",
                "delivered-to",
                "x-original-to",
                "envelope-to",
                "subject",
                "date",
                "reply-to",
                "list-unsubscribe",
                "message-id",
            }
        }
        return EmailRecord(
            account_id=account_id,
            provider=ProviderKind.YAHOO,
            message_id=yahoo_message_id(self.uid_validity, uid),
            received_at=received_at,
            unread="\\Seen" not in flags,
            sender=sender,
            subject=subject,
            body_text=body_text,
            headers=headers,
            flags=frozenset(public_flags),
            has_attachment=has_attachment,
        )

    def fetch_message_identity(self, uid: str) -> str | None:
        """Read only Message-ID for restore reconciliation; never the body."""
        if _UID.fullmatch(uid) is None:
            raise YahooMessageReadError("UID Yahoo non valido")
        status, data = self._uid(
            "FETCH",
            uid,
            "(UID BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])",
        )
        if status != "OK":
            raise YahooMessageReadError("header Message-ID Yahoo non accessibile")
        raw = self._fetch_bytes(data)
        if len(raw) > 4_096:
            raise YahooMessageReadError("header Message-ID Yahoo oltre il limite")
        parsed = email.message_from_bytes(raw, policy=email_policy.default)
        values = parsed.get_all("Message-ID", [])
        if len(values) != 1:
            return None
        value = normalize_plain_text(str(values[0]), max_chars=998).strip()
        return value if 3 <= len(value) <= 998 else None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._client.logout()
        except Exception:
            pass


def _message_body(message: Message) -> tuple[str, bool]:
    plain: list[str] = []
    html: list[str] = []
    has_attachment = False
    parts = message.walk() if message.is_multipart() else (message,)
    for part in parts:
        if part.is_multipart():
            continue
        disposition = (part.get_content_disposition() or "").casefold()
        if disposition == "attachment" or part.get_filename():
            has_attachment = True
            continue
        content_type = part.get_content_type().casefold()
        if content_type not in {"text/plain", "text/html"}:
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeError):
            continue
        if not isinstance(content, str):
            continue
        target = html if content_type == "text/html" else plain
        target.append(sanitize_body(content, content_type, max_chars=8_000))
    chosen = plain if plain else html
    return normalize_plain_text("\n\n".join(chosen), max_chars=8_000), has_attachment


class YahooReadOnlyMailbox:
    capabilities = READ_ONLY_CAPABILITIES

    def __init__(self, account_id: str, transport: YahooReadTransport) -> None:
        if not _ACCOUNT_ID.fullmatch(account_id):
            raise ValueError("account_id Yahoo non valido")
        self.account_id = account_id
        self.transport = transport

    @classmethod
    def from_secret_store(
        cls,
        account_id: str,
        store: SecretStore,
        *,
        folder: str = INBOX_FOLDER,
    ) -> YahooReadOnlyMailbox:
        credentials = load_yahoo_credentials(store, account_id)
        return cls(
            account_id,
            DirectYahooImapReadTransport(credentials, folder=folder),
        )

    @staticmethod
    def _date(before: datetime) -> str:
        if before.tzinfo is None:
            raise ValueError("before deve includere il fuso orario")
        return before.astimezone(timezone.utc).strftime("%d-%b-%Y")

    @staticmethod
    def _search_slice(uids: list[str], search_limit: int | None) -> list[str]:
        if search_limit == 0:
            return uids
        if search_limit is None:
            return uids
        if search_limit < 1:
            raise ValueError("search_limit Yahoo non valido")
        return uids[:search_limit]

    def _search_tolerant(self, *criteria: str) -> list[str]:
        """Search one candidate family; provider failure is never an empty Inbox."""

        return self.transport.search(*criteria)

    def current_inbox_uid_cursor(self) -> tuple[str, str]:
        """Return a safe baseline without reading headers or message bodies."""
        uids = self.transport.search("ALL")
        latest_uid = max(uids, key=int) if uids else "0"
        return self.transport.uid_validity, latest_uid

    def inbox_identities_after(
        self,
        uid_validity: str,
        last_uid: str,
        limit: int = 500,
    ) -> YahooInboxIdentitySync:
        """Read only Message-ID for new Inbox UIDs after a known baseline."""
        if _UID.fullmatch(uid_validity) is None or (
            last_uid != "0" and _UID.fullmatch(last_uid) is None
        ):
            raise ValueError("cursore UID Yahoo non valido")
        if not 1 <= limit <= 1_000:
            raise ValueError("limite riconciliazione Yahoo non valido")
        if uid_validity != self.transport.uid_validity:
            raise YahooImapError("UIDVALIDITY Yahoo cambiato")

        candidates = sorted(
            (uid for uid in self.transport.search("ALL") if int(uid) > int(last_uid)),
            key=int,
        )
        batch = candidates[:limit]
        identities = tuple(
            identity
            for uid in batch
            if (identity := self.transport.fetch_message_identity(uid)) is not None
        )
        return YahooInboxIdentitySync(
            uid_validity=self.transport.uid_validity,
            identities=identities,
            latest_processed_uid=batch[-1] if batch else last_uid,
            has_more=len(candidates) > len(batch),
        )

    def _iter(
        self,
        uids: list[str],
        limit: int,
        require_unread: bool | None,
        skip_message_id: Callable[[str], bool] | None = None,
    ) -> Iterator[EmailRecord]:
        yielded = 0
        for uid in uids:
            message_id = yahoo_message_id(self.transport.uid_validity, uid)
            if skip_message_id is not None and skip_message_id(message_id):
                continue
            try:
                message = self.transport.fetch_message(uid, self.account_id)
            except YahooMessageReadError:
                # A malformed message or a transient Yahoo response must not
                # turn a read-only batch into an all-or-nothing operation.
                # The message is deliberately not recorded as processed: a
                # later session may retry it after Yahoo has recovered.
                continue
            if message is None or (
                require_unread is not None and message.unread is not require_unread
            ):
                continue
            yield message
            yielded += 1
            if yielded >= limit:
                return

    def iter_inbox_unread_before(
        self,
        before: datetime,
        limit: int,
        skip_message_id: Callable[[str], bool] | None = None,
        search_limit: int | None = None,
        oldest_first: bool = False,
    ) -> Iterator[EmailRecord]:
        uids = self._search_tolerant("UNSEEN", "BEFORE", self._date(before))
        selected = self._search_slice(uids, search_limit)
        if oldest_first:
            selected = list(reversed(selected))
        yield from self._iter(
            selected, limit, True, skip_message_id
        )

    def iter_inbox_read_one_time_code_candidates_before(
        self,
        before: datetime,
        limit: int,
        skip_message_id: Callable[[str], bool] | None = None,
        search_limit: int | None = None,
        oldest_first: bool = False,
    ) -> Iterator[EmailRecord]:
        found: set[str] = set()
        for term in _OTP_TERMS:
            found.update(self._search_tolerant(
                "SEEN", "BEFORE", self._date(before), "SUBJECT", term
            ))
        uids = sorted(found, key=int, reverse=True)
        selected = self._search_slice(uids, search_limit)
        if oldest_first:
            selected = list(reversed(selected))
        yield from self._iter(
            selected, limit, False, skip_message_id
        )

    def iter_inbox_read_routine_access_alert_candidates_before(
        self,
        before: datetime,
        limit: int,
        skip_message_id: Callable[[str], bool] | None = None,
        search_limit: int | None = None,
        oldest_first: bool = False,
    ) -> Iterator[EmailRecord]:
        found: set[str] = set()
        for term in _ACCESS_TERMS:
            # imaplib encodes SEARCH criteria as ASCII unless an explicit
            # negotiated charset is used.  Keep Italian detection local and
            # never let an accented subject term abort the entire batch.
            if not term.isascii():
                continue
            found.update(self._search_tolerant(
                "SEEN", "BEFORE", self._date(before), "SUBJECT", term
            ))
        uids = sorted(found, key=int, reverse=True)
        selected = self._search_slice(uids, search_limit)
        if oldest_first:
            selected = list(reversed(selected))
        yield from self._iter(selected, limit, False, skip_message_id)

    def iter_inbox_quiz_sample(
        self,
        limit: int,
        old_unread_before: datetime | None = None,
        skip_message_id: Callable[[str], bool] | None = None,
        search_limit: int | None = None,
    ) -> Iterator[EmailRecord]:
        if not 1 <= limit <= 500:
            raise ValueError("limit quiz Yahoo non valido")
        if old_unread_before is None:
            uids = self._search_tolerant("ALL")
        else:
            old = self._search_tolerant("UNSEEN", "BEFORE", self._date(old_unread_before))
            general = self._search_tolerant("ALL")
            uids = list(dict.fromkeys(old[: limit // 2] + general))
        yield from self._iter(
            self._search_slice(uids, search_limit),
            limit,
            None,
            skip_message_id,
        )

    def iter_inbox_shadow_review_sample(
        self,
        unread_before: datetime,
        read_otp_before: datetime,
        read_access_before: datetime,
        limit: int,
        search_limit: int,
        record_for_id: Callable[[str], tuple[str, str] | None],
    ) -> Iterator[tuple[EmailRecord, str, str]]:
        if not 1 <= limit <= 500 or not limit <= search_limit <= 1000:
            raise ValueError("limiti revisione Yahoo non validi")
        seen: set[str] = set()
        yielded = 0
        # Review must also find recorded advertising/social proposals that do
        # not match the normal age/OTP/access prefilters.  Targeted searches are
        # retained first; the Inbox-wide fallback covers every other proposal.
        searches = [
            self._search_tolerant("UNSEEN", "BEFORE", self._date(unread_before)),
            self._search_tolerant("SEEN", "BEFORE", self._date(read_otp_before)),
        ]
        searches.extend(
            self._search_tolerant(
                "SEEN", "BEFORE", self._date(read_access_before), "SUBJECT", term
            )
            for term in _ACCESS_TERMS if term.isascii()
        )
        searches.append(self._search_tolerant("ALL"))
        for uids in searches:
            for uid in uids[:search_limit]:
                message_id = yahoo_message_id(self.transport.uid_validity, uid)
                if message_id in seen:
                    continue
                seen.add(message_id)
                record = record_for_id(message_id)
                if record is None:
                    continue
                try:
                    message = self.transport.fetch_message(uid, self.account_id)
                except YahooMessageReadError:
                    continue
                if message is None:
                    continue
                yield message, record[0], record[1]
                yielded += 1
                if yielded >= limit:
                    return

    def iter_quarantine_shadow_review_sample(
        self,
        limit: int,
        search_limit: int,
        record_for_location: Callable[[str, str], tuple[str, str] | None],
    ) -> Iterator[tuple[EmailRecord, str, str]]:
        """Read only Yahoo quarantine messages linked to local proposals.

        The destination folder has a different UID namespace from INBOX.  The
        callback resolves that namespace through the local HMAC-only ledger;
        no message identifiers or email text are persisted by this method.
        """

        if not 1 <= limit <= 500 or not limit <= search_limit <= 1000:
            raise ValueError("limiti revisione Quarantena Yahoo non validi")
        yielded = 0
        for uid in self._search_tolerant("ALL")[:search_limit]:
            record = record_for_location(self.transport.uid_validity, uid)
            if record is None:
                continue
            try:
                message = self.transport.fetch_message(uid, self.account_id)
            except YahooMessageReadError:
                continue
            if message is None:
                continue
            yield message, record[0], record[1]
            yielded += 1
            if yielded >= limit:
                return

    def iter_quarantine_review_messages(
        self,
        search_limit: int,
    ) -> Iterator[EmailRecord]:
        """Yield messages from the dedicated folder for local user review.

        This is used only by the explicit review action.  The selected IMAP
        folder is read-only, bodies remain in memory, and no folder operation
        is exposed through this mailbox.
        """

        if not 1 <= search_limit <= 1000:
            raise ValueError("limite revisione Quarantena Yahoo non valido")
        for uid in self._search_tolerant("ALL")[:search_limit]:
            try:
                message = self.transport.fetch_message(uid, self.account_id)
            except YahooMessageReadError:
                continue
            if message is not None:
                yield message

    def iter_inbox_matching_candidate_ids(
        self,
        unread_before: datetime,
        read_otp_before: datetime,
        read_access_before: datetime,
        limit: int,
        search_limit: int,
        include_message_id: Callable[[str, bool], bool],
    ) -> Iterator[str]:
        if not 1 <= limit <= 500 or not limit <= search_limit <= 1000:
            raise ValueError("limiti selezione Yahoo non validi")
        seen: set[str] = set()
        yielded = 0
        searches = [
            (
                self._search_tolerant("UNSEEN", "BEFORE", self._date(unread_before)),
                True,
            ),
            (
                self._search_tolerant("SEEN", "BEFORE", self._date(read_otp_before)),
                False,
            ),
        ]
        searches.extend(
            (
                self._search_tolerant(
                    "SEEN", "BEFORE", self._date(read_access_before), "SUBJECT", term
                ),
                False,
            )
            for term in _ACCESS_TERMS if term.isascii()
        )
        for uids, currently_unread in searches:
            for uid in uids[:search_limit]:
                message_id = yahoo_message_id(self.transport.uid_validity, uid)
                if message_id in seen:
                    continue
                seen.add(message_id)
                if not include_message_id(message_id, currently_unread):
                    continue
                yield message_id
                yielded += 1
                if yielded >= limit:
                    return

    def count_inbox_unprocessed_candidate_ids(
        self,
        unread_before: datetime,
        read_otp_before: datetime,
        read_access_before: datetime,
        was_scanned: Callable[[str], bool],
        maximum: int | None = None,
    ) -> tuple[int, bool]:
        """Count unique IMAP UIDs from SEARCH results without fetching messages."""

        if maximum is not None and not 1 <= maximum <= 500:
            raise ValueError("maximum candidate count must be between 1 and 500")
        searches = [
            self._search_tolerant("UNSEEN", "BEFORE", self._date(unread_before)),
        ]
        otp: set[str] = set()
        for term in _OTP_TERMS:
            otp.update(
                self._search_tolerant(
                    "SEEN", "BEFORE", self._date(read_otp_before), "SUBJECT", term
                )
            )
        searches.append(sorted(otp, key=int, reverse=True))
        access: set[str] = set()
        for term in _ACCESS_TERMS:
            if not term.isascii():
                continue
            access.update(
                self._search_tolerant(
                    "SEEN",
                    "BEFORE",
                    self._date(read_access_before),
                    "SUBJECT",
                    term,
                )
            )
        searches.append(sorted(access, key=int, reverse=True))

        seen: set[str] = set()
        count = 0
        for uids in searches:
            for uid in uids:
                message_id = yahoo_message_id(self.transport.uid_validity, uid)
                if message_id in seen:
                    continue
                seen.add(message_id)
                if was_scanned(message_id):
                    continue
                count += 1
                if maximum is not None and count >= maximum:
                    return count, True
        return count, False

    def close(self) -> None:
        self.transport.close()
