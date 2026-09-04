from __future__ import annotations

import base64
import binascii
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

from ..models import EmailRecord, ProviderKind
from ..settings import MAX_RECOVERY_SEARCH_LIMIT, MAX_SCAN_BATCH_SIZE
from ..sanitizer import html_to_visible_text, normalize_plain_text
from ..tls_trust import https_handler
from .contracts import GMAIL_READONLY_SCOPE, READ_ONLY_CAPABILITIES, ReadOnlyCapability


GMAIL_API_ORIGIN = "https://gmail.googleapis.com"
GMAIL_MESSAGES_PATH = "/gmail/v1/users/me/messages"
GMAIL_PROFILE_PATH = "/gmail/v1/users/me/profile"
GMAIL_HISTORY_PATH = "/gmail/v1/users/me/history"
GMAIL_LABELS_PATH = "/gmail/v1/users/me/labels"
GMAIL_HISTORY_FIELDS = (
    "history(id,labelsAdded(message(id),labelIds),"
    "labelsRemoved(message(id),labelIds)),nextPageToken,historyId"
)
GMAIL_ALLOWED_PATH = re.compile(r"^/gmail/v1/users/me/messages(?:/[A-Za-z0-9_-]+)?$")
GMAIL_USER_LABEL_ID = re.compile(r"Label_[A-Za-z0-9_-]{1,250}")
QUARANTINE_LABEL_NAMES = frozenset(
    {"InboxLume/Quarantena", "Mail Guardian/Quarantena"}
)
GMAIL_RESERVED_MESSAGE_RESOURCES = frozenset(
    {
        "batchdelete",
        "batchmodify",
        "import",
        "insert",
        "modify",
        "send",
        "trash",
        "untrash",
    }
)
FORBIDDEN_LABELS = frozenset({"SENT", "DRAFT", "SPAM", "TRASH"})
MAX_HTTP_RESPONSE_BYTES = 4_000_000
MAX_INLINE_BODY_BYTES = 256_000
MAX_MIME_DEPTH = 64
MAX_MIME_PARTS = 10_000


class GmailReadError(RuntimeError):
    pass


class GmailHistoryExpired(GmailReadError):
    pass


@dataclass(frozen=True, slots=True)
class GmailLabelChange:
    message_id: str
    added_labels: frozenset[str]
    removed_labels: frozenset[str]


@dataclass(frozen=True, slots=True)
class GmailHistorySync:
    changes: tuple[GmailLabelChange, ...]
    latest_history_id: str


def _is_allowed_message_path(path: str) -> bool:
    if not GMAIL_ALLOWED_PATH.fullmatch(path):
        return False
    if path == GMAIL_MESSAGES_PATH:
        return True
    resource = path.removeprefix(f"{GMAIL_MESSAGES_PATH}/").casefold()
    return resource not in GMAIL_RESERVED_MESSAGE_RESOURCES


def _is_history_id(value: str) -> bool:
    return value.isdigit() and len(value) <= 32


class AccessTokenProvider(Protocol):
    @property
    def scopes(self) -> frozenset[str]: ...

    def get_access_token(self) -> str: ...


class JsonGetTransport(Protocol):
    def get_json(self, url: str, access_token: str) -> dict[str, Any]: ...


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class DirectHttpsJsonTransport:
    """Trasporto GET diretto, senza proxy né redirect e con host allowlist."""

    def __init__(self, max_response_bytes: int = MAX_HTTP_RESPONSE_BYTES) -> None:
        self.max_response_bytes = max_response_bytes
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            https_handler(),
            _NoRedirectHandler(),
        )

    @staticmethod
    def _validate_url(url: str) -> None:
        parsed = urllib.parse.urlparse(url)
        if (
            parsed.scheme != "https"
            or parsed.hostname != "gmail.googleapis.com"
            or parsed.port not in {None, 443}
            or parsed.username
            or parsed.password
            or parsed.fragment
        ):
            raise GmailReadError("endpoint Gmail non consentito")
        if _is_allowed_message_path(parsed.path):
            return
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if parsed.path == GMAIL_PROFILE_PATH and query == {"fields": ["historyId"]}:
            return
        if parsed.path == GMAIL_LABELS_PATH and query == {
            "fields": ["labels(id,name,type)"]
        }:
            return
        if parsed.path == GMAIL_HISTORY_PATH:
            required_keys = {
                "startHistoryId",
                "labelId",
                "historyTypes",
                "maxResults",
                "fields",
            }
            if not (
                set(query) == required_keys
                or set(query) == required_keys | {"pageToken"}
            ):
                raise GmailReadError("parametri cronologia Gmail non consentiti")
            start_ids = query.get("startHistoryId", [])
            page_tokens = query.get("pageToken", [])
            if (
                len(start_ids) == 1
                and _is_history_id(start_ids[0])
                and len(query.get("labelId", [])) == 1
                and (
                    query["labelId"][0] == "INBOX"
                    or GMAIL_USER_LABEL_ID.fullmatch(query["labelId"][0])
                    is not None
                )
                and sorted(query.get("historyTypes", []))
                == ["labelAdded", "labelRemoved"]
                and query.get("maxResults") == ["500"]
                and query.get("fields") == [GMAIL_HISTORY_FIELDS]
                and (
                    not page_tokens
                    or (
                        len(page_tokens) == 1
                        and re.fullmatch(r"[A-Za-z0-9_-]{1,512}", page_tokens[0])
                    )
                )
            ):
                return
        raise GmailReadError("endpoint Gmail non consentito")

    def get_json(self, url: str, access_token: str) -> dict[str, Any]:
        self._validate_url(url)
        if not access_token.strip():
            raise GmailReadError("access token Gmail mancante")
        request = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            },
            method="GET",
        )
        try:
            with self._opener.open(request, timeout=30) as response:
                payload = response.read(self.max_response_bytes + 1)
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
            if status == 404 and urllib.parse.urlparse(url).path == GMAIL_HISTORY_PATH:
                raise GmailHistoryExpired("cronologia Gmail scaduta") from exc
            raise GmailReadError(
                f"richiesta Gmail in sola lettura rifiutata (HTTP {status})"
            ) from exc
        except (OSError, urllib.error.URLError) as exc:
            raise GmailReadError("richiesta Gmail in sola lettura fallita") from exc
        if len(payload) > self.max_response_bytes:
            raise GmailReadError("risposta Gmail oltre il limite locale")
        try:
            decoded = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GmailReadError("risposta Gmail non valida") from exc
        if not isinstance(decoded, dict):
            raise GmailReadError("risposta Gmail non valida")
        return decoded


def _decode_base64url(value: str, remaining: int) -> bytes:
    if remaining <= 0:
        return b""
    if len(value) > (remaining * 4 // 3) + 16:
        value = value[: (remaining * 4 // 3) + 16]
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)[:remaining]
    except (ValueError, binascii.Error):
        return b""


def _part_headers(part: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    raw_headers = part.get("headers", [])
    if not isinstance(raw_headers, list):
        return result
    for raw in raw_headers:
        if not isinstance(raw, dict):
            continue
        name = raw.get("name")
        value = raw.get("value")
        if isinstance(name, str) and isinstance(value, str):
            result.setdefault(name, value)
    return result


def _charset(part: dict[str, Any]) -> str:
    content_type = ""
    for name, value in _part_headers(part).items():
        if name.casefold() == "content-type":
            content_type = value
            break
    match = re.search(r"charset\s*=\s*[\"']?([^;\"'\s]+)", content_type, re.I)
    return match.group(1) if match else "utf-8"


def _extract_inline_content(payload: dict[str, Any]) -> tuple[str, bool]:
    plain_chunks: list[str] = []
    html_chunks: list[str] = []
    remaining = MAX_INLINE_BODY_BYTES
    has_attachment = False

    stack: list[tuple[dict[str, Any], int]] = [(payload, 0)]
    visited = 0
    while stack:
        part, depth = stack.pop()
        visited += 1
        if depth > MAX_MIME_DEPTH or visited > MAX_MIME_PARTS:
            raise GmailReadError("struttura MIME Gmail oltre il limite")
        filename = part.get("filename")
        body = part.get("body")
        if not isinstance(body, dict):
            body = {}
        attachment_id = body.get("attachmentId")
        if (isinstance(filename, str) and filename.strip()) or attachment_id:
            has_attachment = True
            # Non viene mai invocato users.messages.attachments.get.
            continue

        mime_type = str(part.get("mimeType", "")).casefold()
        encoded = body.get("data")
        if (
            remaining > 0
            and isinstance(encoded, str)
            and mime_type in {"text/plain", "text/html"}
        ):
            raw = _decode_base64url(encoded, remaining)
            remaining -= len(raw)
            try:
                text = raw.decode(_charset(part), errors="replace")
            except LookupError:
                text = raw.decode("utf-8", errors="replace")
            if mime_type == "text/plain":
                plain_chunks.append(text)
            else:
                html_chunks.append(text)

        children = part.get("parts", [])
        if isinstance(children, list):
            for child in reversed(children):
                if isinstance(child, dict):
                    stack.append((child, depth + 1))
    if plain_chunks:
        return normalize_plain_text("\n".join(plain_chunks)), has_attachment
    if html_chunks:
        return html_to_visible_text("\n".join(html_chunks)), has_attachment
    return "", has_attachment


class GmailReadOnlyMailbox:
    """Acquisitore Gmail che non possiede alcun metodo di modifica."""

    capabilities: frozenset[ReadOnlyCapability] = READ_ONLY_CAPABILITIES

    def __init__(
        self,
        account_id: str,
        token_provider: AccessTokenProvider,
        transport: JsonGetTransport | None = None,
    ) -> None:
        if token_provider.scopes != frozenset({GMAIL_READONLY_SCOPE}):
            raise ValueError("Gmail richiede esattamente il solo scope gmail.readonly")
        self.account_id = account_id
        self.token_provider = token_provider
        self.transport = transport or DirectHttpsJsonTransport()

    def _get(self, path: str, query: dict[str, str | int | bool]) -> dict[str, Any]:
        if not (
            _is_allowed_message_path(path)
            or path in {GMAIL_PROFILE_PATH, GMAIL_HISTORY_PATH, GMAIL_LABELS_PATH}
        ):
            raise GmailReadError("percorso Gmail non consentito")
        encoded = urllib.parse.urlencode(query)
        url = f"{GMAIL_API_ORIGIN}{path}?{encoded}" if encoded else f"{GMAIL_API_ORIGIN}{path}"
        return self.transport.get_json(url, self.token_provider.get_access_token())

    def current_history_id(self) -> str:
        response = self._get(GMAIL_PROFILE_PATH, {"fields": "historyId"})
        history_id = response.get("historyId")
        if not isinstance(history_id, str) or not _is_history_id(history_id):
            raise GmailReadError("historyId Gmail non valido")
        return history_id

    def _label_changes_since(
        self,
        start_history_id: str,
        label_id: str,
        relevant_labels: frozenset[str],
    ) -> GmailHistorySync:
        if not _is_history_id(start_history_id):
            raise ValueError("start_history_id Gmail non valido")
        if label_id != "INBOX" and GMAIL_USER_LABEL_ID.fullmatch(label_id) is None:
            raise ValueError("label_id Gmail non valido")
        page_token: str | None = None
        seen_page_tokens: set[str] = set()
        changes: list[GmailLabelChange] = []
        seen: set[tuple[str, tuple[str, ...], tuple[str, ...]]] = set()
        latest_history_id = start_history_id
        while True:
            query: list[tuple[str, str | int]] = [
                ("startHistoryId", start_history_id),
                ("labelId", label_id),
                ("historyTypes", "labelAdded"),
                ("historyTypes", "labelRemoved"),
                ("maxResults", 500),
                ("fields", GMAIL_HISTORY_FIELDS),
            ]
            if page_token is not None:
                query.append(("pageToken", page_token))
            url = (
                f"{GMAIL_API_ORIGIN}{GMAIL_HISTORY_PATH}?"
                f"{urllib.parse.urlencode(query)}"
            )
            response = self.transport.get_json(
                url,
                self.token_provider.get_access_token(),
            )
            history = response.get("history", [])
            if not isinstance(history, list):
                raise GmailReadError("cronologia Gmail non valida")
            for raw_history in history:
                if not isinstance(raw_history, dict):
                    continue
                per_message: dict[str, tuple[set[str], set[str]]] = {}
                for field, position in (("labelsAdded", 0), ("labelsRemoved", 1)):
                    raw_changes = raw_history.get(field, [])
                    if not isinstance(raw_changes, list):
                        raise GmailReadError("variazioni label Gmail non valide")
                    for raw_change in raw_changes:
                        if not isinstance(raw_change, dict):
                            continue
                        raw_message = raw_change.get("message")
                        raw_labels = raw_change.get("labelIds", [])
                        if not isinstance(raw_message, dict) or not isinstance(raw_labels, list):
                            continue
                        message_id = raw_message.get("id")
                        if (
                            not isinstance(message_id, str)
                            or not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", message_id)
                            or not all(isinstance(label, str) for label in raw_labels)
                        ):
                            continue
                        added, removed = per_message.setdefault(message_id, (set(), set()))
                        target = added if position == 0 else removed
                        target.update(relevant_labels.intersection(raw_labels))
                for message_id, (added, removed) in per_message.items():
                    key = (message_id, tuple(sorted(added)), tuple(sorted(removed)))
                    if key in seen or (not added and not removed):
                        continue
                    seen.add(key)
                    changes.append(
                        GmailLabelChange(
                            message_id,
                            frozenset(added),
                            frozenset(removed),
                        )
                    )
            raw_latest = response.get("historyId", latest_history_id)
            if not isinstance(raw_latest, str) or not _is_history_id(raw_latest):
                raise GmailReadError("historyId risposta Gmail non valido")
            latest_history_id = raw_latest
            raw_page = response.get("nextPageToken")
            if raw_page is None:
                break
            if not isinstance(raw_page, str) or not re.fullmatch(
                r"[A-Za-z0-9_-]{1,512}", raw_page
            ):
                raise GmailReadError("pageToken cronologia Gmail non valido")
            if raw_page in seen_page_tokens:
                raise GmailReadError("paginazione cronologia Gmail ripetuta")
            seen_page_tokens.add(raw_page)
            page_token = raw_page
        return GmailHistorySync(tuple(changes), latest_history_id)

    def inbox_label_changes_since(self, start_history_id: str) -> GmailHistorySync:
        """Read Inbox label changes only; never message bodies or text."""
        return self._label_changes_since(
            start_history_id,
            "INBOX",
            frozenset({"INBOX", "UNREAD", "STARRED", "IMPORTANT", "TRASH"}),
        )

    def _quarantine_label_ids(self) -> tuple[str, ...]:
        response = self._get(
            GMAIL_LABELS_PATH,
            {"fields": "labels(id,name,type)"},
        )
        raw_labels = response.get("labels", [])
        if not isinstance(raw_labels, list):
            raise GmailReadError("elenco etichette Gmail non valido")
        matches: list[str] = []
        for raw in raw_labels:
            if not isinstance(raw, dict) or raw.get("name") not in QUARANTINE_LABEL_NAMES:
                continue
            label_id = raw.get("id")
            if (
                raw.get("type") != "user"
                or not isinstance(label_id, str)
                or GMAIL_USER_LABEL_ID.fullmatch(label_id) is None
            ):
                raise GmailReadError("etichetta Quarantena Gmail non valida")
            matches.append(label_id)
        return tuple(sorted(set(matches)))

    def behavior_label_changes_since(self, start_history_id: str) -> GmailHistorySync:
        """Combine Inbox and InboxLume-label history without reading email text."""
        syncs = [self.inbox_label_changes_since(start_history_id)]
        for label_id in self._quarantine_label_ids():
            syncs.append(
                self._label_changes_since(
                    start_history_id,
                    label_id,
                    frozenset({label_id, "INBOX", "TRASH"}),
                )
            )
        merged: dict[str, tuple[set[str], set[str]]] = {}
        for sync in syncs:
            for change in sync.changes:
                added, removed = merged.setdefault(change.message_id, (set(), set()))
                added.update(change.added_labels)
                removed.update(change.removed_labels)
        latest = max((sync.latest_history_id for sync in syncs), key=int)
        changes = tuple(
            GmailLabelChange(message_id, frozenset(added), frozenset(removed))
            for message_id, (added, removed) in sorted(merged.items())
            if added or removed
        )
        return GmailHistorySync(changes, latest)

    def _list_ids(self, limit: int | None, query: str | None) -> Iterator[str]:
        if limit is not None and limit < 1:
            raise ValueError("limit deve essere positivo oppure None")
        yielded = 0
        page_token: str | None = None
        seen_page_tokens: set[str] = set()
        while limit is None or yielded < limit:
            params: dict[str, str | int | bool] = {
                "labelIds": "INBOX",
                "includeSpamTrash": "false",
                "maxResults": 500 if limit is None else min(500, limit - yielded),
            }
            if query:
                params["q"] = query
            if page_token:
                params["pageToken"] = page_token
            response = self._get(GMAIL_MESSAGES_PATH, params)
            messages = response.get("messages", [])
            if not isinstance(messages, list):
                raise GmailReadError("elenco messaggi Gmail non valido")
            for item in messages:
                if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                    continue
                yield item["id"]
                yielded += 1
                if limit is not None and yielded >= limit:
                    return
            raw_page_token = response.get("nextPageToken")
            if not isinstance(raw_page_token, str) or not raw_page_token:
                return
            if re.fullmatch(r"[A-Za-z0-9_-]{1,512}", raw_page_token) is None:
                raise GmailReadError("pageToken messaggi Gmail non valido")
            if raw_page_token in seen_page_tokens:
                raise GmailReadError("paginazione messaggi Gmail ripetuta")
            seen_page_tokens.add(raw_page_token)
            page_token = raw_page_token

    def _fetch_message(self, message_id: str, require_unread: bool) -> EmailRecord | None:
        if not re.fullmatch(r"[A-Za-z0-9_-]+", message_id):
            raise GmailReadError("ID messaggio Gmail non valido")
        resource = self._get(
            f"{GMAIL_MESSAGES_PATH}/{urllib.parse.quote(message_id, safe='')}",
            {"format": "full"},
        )
        labels_raw = resource.get("labelIds", [])
        if not isinstance(labels_raw, list):
            raise GmailReadError("etichette Gmail non valide")
        labels = frozenset(str(label) for label in labels_raw)
        if "INBOX" not in labels or labels.intersection(FORBIDDEN_LABELS):
            return None
        if require_unread and "UNREAD" not in labels:
            return None

        payload = resource.get("payload")
        if not isinstance(payload, dict):
            raise GmailReadError("payload Gmail mancante")
        headers = _part_headers(payload)
        lowered = {key.casefold(): value for key, value in headers.items()}
        body_text, has_attachment = _extract_inline_content(payload)
        if not body_text:
            body_text = normalize_plain_text(str(resource.get("snippet", "")))
        try:
            received_at = datetime.fromtimestamp(
                int(str(resource["internalDate"])) / 1000,
                tz=timezone.utc,
            )
        except (KeyError, TypeError, ValueError, OSError) as exc:
            raise GmailReadError("data interna Gmail non valida") from exc

        resource_id = resource.get("id")
        if not isinstance(resource_id, str) or resource_id != message_id:
            raise GmailReadError("ID risposta Gmail non corrispondente")
        return EmailRecord(
            account_id=self.account_id,
            provider=ProviderKind.GMAIL,
            message_id=message_id,
            received_at=received_at,
            unread="UNREAD" in labels,
            sender=normalize_plain_text(lowered.get("from", ""), max_chars=500),
            subject=normalize_plain_text(lowered.get("subject", ""), max_chars=1_000),
            body_text=body_text,
            headers=headers,
            flags=frozenset(label for label in labels if label in {"STARRED", "IMPORTANT"}),
            known_contact=False,
            user_replied=False,
            has_attachment=has_attachment,
        )

    @staticmethod
    def _old_unread_query(before: datetime) -> str:
        if before.tzinfo is None:
            raise ValueError("before deve includere il fuso orario")
        gmail_date = before.astimezone(timezone.utc).strftime("%Y/%m/%d")
        return f"is:unread before:{gmail_date}"

    @staticmethod
    def _read_one_time_code_query(before: datetime) -> str:
        if before.tzinfo is None:
            raise ValueError("before deve includere il fuso orario")
        gmail_date = before.astimezone(timezone.utc).strftime("%Y/%m/%d")
        # Questo è soltanto un prefiltro statico sul servizio che già ospita la
        # posta. Il contenuto viene confermato esclusivamente dal classificatore
        # locale prima che la policy proponga qualunque azione.
        return (
            f'is:read before:{gmail_date} '
            '{subject:codice subject:code subject:otp "codice monouso" '
            '"codice di verifica" "verification code" "one-time code"}'
        )

    @staticmethod
    def _read_routine_access_alert_query(before: datetime) -> str:
        if before.tzinfo is None:
            raise ValueError("before deve includere il fuso orario")
        gmail_date = before.astimezone(timezone.utc).strftime("%Y/%m/%d")
        return (
            f'is:read before:{gmail_date} '
            '{subject:"new sign-in" subject:"new login" subject:"nuovo accesso" '
            'subject:"accesso rilevato" subject:"sign-in detected" '
            'subject:"login detected" subject:"accesso effettuato" '
            'subject:"attività di accesso" subject:"avviso di accesso" '
            'subject:"access alert" subject:"hai effettuato l\'accesso" '
            'subject:"you logged in" subject:"used to sign in"}'
        )

    @staticmethod
    def _candidate_search_limit(
        limit: int,
        search_limit: int | None,
    ) -> int | None:
        actual = limit if search_limit is None else search_limit
        if actual == 0:
            if limit < 1:
                raise ValueError("limiti scansione Gmail non validi")
            return None
        if not 1 <= limit <= actual:
            raise ValueError("limiti scansione Gmail non validi")
        return actual

    def iter_inbox_unread_before(
        self,
        before: datetime,
        limit: int,
        skip_message_id: Callable[[str], bool] | None = None,
        search_limit: int | None = None,
        oldest_first: bool = False,
    ) -> Iterator[EmailRecord]:
        yielded = 0
        search = self._candidate_search_limit(limit, search_limit)
        message_ids: Iterator[str] | list[str] = self._list_ids(
            search, self._old_unread_query(before)
        )
        if oldest_first:
            # Gmail restituisce gli ID dal più recente. Per partire davvero dal
            # fondo basta materializzare gli ID opachi; nessun corpo viene letto.
            message_ids = list(message_ids)
            message_ids.reverse()
        for message_id in message_ids:
            if skip_message_id is not None and skip_message_id(message_id):
                continue
            message = self._fetch_message(message_id, require_unread=True)
            if message is not None:
                yield message
                yielded += 1
                if yielded >= limit:
                    return

    def iter_inbox_read_one_time_code_candidates_before(
        self,
        before: datetime,
        limit: int,
        skip_message_id: Callable[[str], bool] | None = None,
        search_limit: int | None = None,
        oldest_first: bool = False,
    ) -> Iterator[EmailRecord]:
        yielded = 0
        search = self._candidate_search_limit(limit, search_limit)
        message_ids: Iterator[str] | list[str] = self._list_ids(
            search, self._read_one_time_code_query(before)
        )
        if oldest_first:
            message_ids = list(message_ids)
            message_ids.reverse()
        for message_id in message_ids:
            if skip_message_id is not None and skip_message_id(message_id):
                continue
            message = self._fetch_message(message_id, require_unread=False)
            # Un cambio concorrente di stato non deve trasformare una non letta
            # in un candidato alla regola dedicata ai messaggi già aperti.
            if message is not None and not message.unread:
                yield message
                yielded += 1
                if yielded >= limit:
                    return

    def iter_inbox_read_routine_access_alert_candidates_before(
        self,
        before: datetime,
        limit: int,
        skip_message_id: Callable[[str], bool] | None = None,
        search_limit: int | None = None,
        oldest_first: bool = False,
    ) -> Iterator[EmailRecord]:
        yielded = 0
        search = self._candidate_search_limit(limit, search_limit)
        message_ids: Iterator[str] | list[str] = self._list_ids(
            search, self._read_routine_access_alert_query(before)
        )
        if oldest_first:
            message_ids = list(message_ids)
            message_ids.reverse()
        for message_id in message_ids:
            if skip_message_id is not None and skip_message_id(message_id):
                continue
            message = self._fetch_message(message_id, require_unread=False)
            if message is not None and not message.unread:
                yield message
                yielded += 1
                if yielded >= limit:
                    return

    def _iter_inbox_quiz_sample_ids(
        self,
        limit: int,
        old_unread_before: datetime | None = None,
        skip_message_id: Callable[[str], bool] | None = None,
        search_limit: int | None = None,
    ) -> Iterator[tuple[str, bool]]:
        if not 1 <= limit <= 500:
            raise ValueError("limit quiz deve essere tra 1 e 500")
        search = self._candidate_search_limit(limit, search_limit)
        yielded = 0
        seen: set[str] = set()

        # Metà del campione proviene dal gruppo che l'agente elaborerà davvero.
        old_quota = limit // 2 if old_unread_before is not None else 0
        if old_quota:
            for message_id in self._list_ids(
                search,
                self._old_unread_query(old_unread_before),
            ):
                if skip_message_id is not None and skip_message_id(message_id):
                    continue
                seen.add(message_id)
                yielded += 1
                yield message_id, True
                if yielded >= old_quota:
                    break

        # L'altra metà mantiene esempi letti, recenti e protetti dalla Inbox generale.
        for message_id in self._list_ids(search, None):
            if message_id in seen or (
                skip_message_id is not None and skip_message_id(message_id)
            ):
                continue
            yielded += 1
            yield message_id, False
            if yielded >= limit:
                return

    def iter_inbox_quiz_sample(
        self,
        limit: int,
        old_unread_before: datetime | None = None,
        skip_message_id: Callable[[str], bool] | None = None,
        search_limit: int | None = None,
    ) -> Iterator[EmailRecord]:
        for message_id, require_unread in self._iter_inbox_quiz_sample_ids(
            limit,
            old_unread_before,
            skip_message_id,
            search_limit,
        ):
            message = self._fetch_message(message_id, require_unread=require_unread)
            if message is not None:
                yield message

    def iter_inbox_answered_quiz_sample(
        self,
        limit: int,
        old_unread_before: datetime,
        answer_for_id: Callable[[str], str | None],
    ) -> Iterator[tuple[EmailRecord, str]]:
        """Scarica il corpo soltanto per ID che possiedono già una risposta HMAC."""

        for message_id, _ in self._iter_inbox_quiz_sample_ids(limit, old_unread_before):
            answer = answer_for_id(message_id)
            if answer is None:
                continue
            message = self._fetch_message(message_id, require_unread=False)
            if message is not None:
                yield message, answer

    def iter_inbox_shadow_review_sample(
        self,
        unread_before: datetime,
        read_otp_before: datetime,
        read_access_before: datetime,
        limit: int,
        search_limit: int,
        record_for_id: Callable[[str], tuple[str, str] | None],
    ) -> Iterator[tuple[EmailRecord, str, str]]:
        """Recupera solo proposte shadow già registrate e ancora presenti in Inbox."""

        if not 1 <= limit <= 500 or not limit <= search_limit <= 1000:
            raise ValueError("limiti revisione shadow non validi")
        yielded = 0
        seen: set[str] = set()
        # A proposal may be advertising/social as well as an old unread/OTP or
        # access message.  Keep the cheap targeted searches first (preserving
        # their ordering) and then use one Inbox-wide fallback for every other
        # recorded proposal.
        queries = (
            (self._read_one_time_code_query(read_otp_before), False),
            (self._read_routine_access_alert_query(read_access_before), False),
            (self._old_unread_query(unread_before), True),
            (None, False),
        )
        for query, require_unread in queries:
            for message_id in self._list_ids(search_limit, query):
                if message_id in seen:
                    continue
                seen.add(message_id)
                record = record_for_id(message_id)
                if record is None:
                    continue
                category, action = record
                message = self._fetch_message(message_id, require_unread=require_unread)
                if message is None:
                    continue
                yield message, category, action
                yielded += 1
                if yielded >= limit:
                    return

    def iter_inbox_matching_candidate_ids(
        self,
        unread_before: datetime,
        read_otp_before: datetime,
        read_access_before: datetime,
        limit: int,
        search_limit: int,
        include_message_id: Callable[[str, bool], bool],
    ) -> Iterator[str]:
        """Restituisce solo ID Inbox approvati dal callback, senza leggere corpi."""

        # This selection feeds the scan batch, so it scales with the
        # batch ceiling. The review readers below keep their own,
        # smaller bounds: a review is not sized by the scan.
        if (
            not 1 <= limit <= MAX_SCAN_BATCH_SIZE
            or not limit <= search_limit <= MAX_RECOVERY_SEARCH_LIMIT
        ):
            raise ValueError("limiti selezione operativa non validi")
        yielded = 0
        seen: set[str] = set()
        for query, currently_unread in (
            (self._read_one_time_code_query(read_otp_before), False),
            (self._read_routine_access_alert_query(read_access_before), False),
            (self._old_unread_query(unread_before), True),
        ):
            for message_id in self._list_ids(search_limit, query):
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
        """Count unique candidate IDs only; never invoke users.messages.get."""

        # The count answers how much of a configured batch is still there,
        # so it has to admit the same batch the scan will accept.
        if maximum is not None and not 1 <= maximum <= MAX_SCAN_BATCH_SIZE:
            raise ValueError(
                "maximum candidate count must be between 1 and "
                f"{MAX_SCAN_BATCH_SIZE}"
            )
        seen: set[str] = set()
        count = 0
        for query in (
            self._read_one_time_code_query(read_otp_before),
            self._read_routine_access_alert_query(read_access_before),
            self._old_unread_query(unread_before),
        ):
            for message_id in self._list_ids(None, query):
                if message_id in seen:
                    continue
                seen.add(message_id)
                if was_scanned(message_id):
                    continue
                count += 1
                if maximum is not None and count >= maximum:
                    return count, True
        return count, False

    def estimate_inbox_unread_before(self, before: datetime) -> int:
        """Restituisce la stima Gmail senza invocare users.messages.get."""

        response = self._get(
            GMAIL_MESSAGES_PATH,
            {
                "labelIds": "INBOX",
                "includeSpamTrash": "false",
                "maxResults": 1,
                "q": self._old_unread_query(before),
            },
        )
        estimate = response.get("resultSizeEstimate")
        if isinstance(estimate, bool) or not isinstance(estimate, int) or estimate < 0:
            raise GmailReadError("stima messaggi Gmail non valida")
        return estimate

    def estimate_inbox_read_one_time_code_candidates_before(self, before: datetime) -> int:
        """Stima il prefiltro OTP letto senza invocare users.messages.get."""

        response = self._get(
            GMAIL_MESSAGES_PATH,
            {
                "labelIds": "INBOX",
                "includeSpamTrash": "false",
                "maxResults": 1,
                "q": self._read_one_time_code_query(before),
            },
        )
        estimate = response.get("resultSizeEstimate")
        if isinstance(estimate, bool) or not isinstance(estimate, int) or estimate < 0:
            raise GmailReadError("stima messaggi Gmail non valida")
        return estimate

    def estimate_inbox_read_routine_access_alert_candidates_before(
        self,
        before: datetime,
    ) -> int:
        """Estimate the header-prefiltered routine access alerts; read no body."""
        response = self._get(
            GMAIL_MESSAGES_PATH,
            {
                "labelIds": "INBOX",
                "includeSpamTrash": "false",
                "maxResults": 1,
                "q": self._read_routine_access_alert_query(before),
            },
        )
        estimate = response.get("resultSizeEstimate")
        if isinstance(estimate, bool) or not isinstance(estimate, int) or estimate < 0:
            raise GmailReadError("stima avvisi di accesso Gmail non valida")
        return estimate

    def probe_inbox(self) -> bool:
        """Verifica l'accesso elencando al massimo un ID, senza leggere il messaggio."""
        return next(self._list_ids(1, None), None) is not None
