from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from ..tls_trust import https_handler
from .contracts import GMAIL_MODIFY_SCOPE


GMAIL_API_ORIGIN = "https://gmail.googleapis.com"
QUARANTINE_LABEL_NAME = "InboxLume/Quarantena"
LEGACY_QUARANTINE_LABEL_NAME = "Mail Guardian/Quarantena"
THREAT_LABEL_NAME = "InboxLume/Sospetto phishing"
LABELS_PATH = "/gmail/v1/users/me/labels"
_MESSAGE_METADATA_PATH = re.compile(
    r"^/gmail/v1/users/me/messages/([A-Za-z0-9_-]+)$"
)
_MESSAGE_MODIFY_PATH = re.compile(
    r"^/gmail/v1/users/me/messages/([A-Za-z0-9_-]+)/modify$"
)
_MESSAGE_ID = re.compile(r"[A-Za-z0-9_-]{1,256}")
_LABEL_ID = re.compile(r"[A-Za-z0-9_-]{1,256}")
_FORBIDDEN_INPUT_LABELS = frozenset({"SENT", "DRAFT", "SPAM", "TRASH"})
_PROTECTED_INPUT_LABELS = frozenset({"STARRED", "IMPORTANT"})
_SYSTEM_LABEL_IDS = frozenset(
    {
        "CHAT",
        "DRAFT",
        "IMPORTANT",
        "INBOX",
        "SENT",
        "SPAM",
        "STARRED",
        "TRASH",
        "UNREAD",
    }
)
MAX_RESPONSE_BYTES = 512_000


class GmailQuarantineError(RuntimeError):
    pass


class QuarantineOutcome(StrEnum):
    APPLIED = "applied"
    ALREADY_APPLIED = "already_applied"
    SKIPPED_NOT_INBOX = "skipped_not_inbox"
    SKIPPED_PROTECTED = "skipped_protected"


@dataclass(frozen=True, slots=True)
class QuarantineResult:
    outcome: QuarantineOutcome

    @property
    def changes_mailbox(self) -> bool:
        return self.outcome is QuarantineOutcome.APPLIED


class AccessTokenProvider(Protocol):
    @property
    def scopes(self) -> frozenset[str]: ...

    def get_access_token(self) -> str: ...


class QuarantineTransport(Protocol):
    def get_json(self, url: str, access_token: str) -> dict[str, Any]: ...

    def post_json(
        self,
        url: str,
        payload: dict[str, Any],
        access_token: str,
    ) -> dict[str, Any]: ...


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class DirectGmailQuarantineTransport:
    """Minimal transport for the two allowed reversible Gmail label actions.

    It can create one of the two InboxLume labels and modify one message only by
    adding that user label; the phishing executor may additionally remove only
    ``INBOX``.  Every deletion, Trash, Spam, send, and non-allow-listed endpoint
    remains rejected before any request is issued.
    """

    def __init__(self, max_response_bytes: int = MAX_RESPONSE_BYTES) -> None:
        self.max_response_bytes = max_response_bytes
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            https_handler(),
            _NoRedirectHandler(),
        )

    @staticmethod
    def _parsed(url: str) -> urllib.parse.ParseResult:
        parsed = urllib.parse.urlparse(url)
        if (
            parsed.scheme != "https"
            or parsed.hostname != "gmail.googleapis.com"
            or parsed.port not in {None, 443}
            or parsed.username
            or parsed.password
            or parsed.fragment
        ):
            raise GmailQuarantineError("endpoint Gmail quarantena non consentito")
        return parsed

    @classmethod
    def _validate_get_url(cls, url: str) -> None:
        parsed = cls._parsed(url)
        if parsed.path == LABELS_PATH and not parsed.query:
            return
        if _MESSAGE_METADATA_PATH.fullmatch(parsed.path):
            query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if query == {"fields": ["id,labelIds"], "format": ["minimal"]}:
                return
        raise GmailQuarantineError("GET Gmail quarantena non consentita")

    @classmethod
    def _validate_post(cls, url: str, payload: dict[str, Any]) -> None:
        parsed = cls._parsed(url)
        if parsed.query:
            raise GmailQuarantineError("POST Gmail quarantena non consentita")
        if parsed.path == LABELS_PATH:
            expected_names = {QUARANTINE_LABEL_NAME, THREAT_LABEL_NAME}
            if payload == {
                "name": payload.get("name"),
                "messageListVisibility": "show",
                "labelListVisibility": "labelShow",
            } and payload.get("name") in expected_names:
                return
        match = _MESSAGE_MODIFY_PATH.fullmatch(parsed.path)
        if match and set(payload) == {"addLabelIds", "removeLabelIds"}:
            added = payload.get("addLabelIds")
            removed = payload.get("removeLabelIds")
            if (
                isinstance(added, list)
                and len(added) == 1
                and isinstance(added[0], str)
                and _LABEL_ID.fullmatch(added[0])
                and added[0] not in _SYSTEM_LABEL_IDS
                # Both Quarantine and the phishing warning are additive user
                # labels.  Removing INBOX (or any other label) is deliberately
                # outside this transport's allow-list.
                and removed == []
            ):
                return
        raise GmailQuarantineError("POST Gmail quarantena non consentita")

    def _request_json(
        self,
        request: urllib.request.Request,
    ) -> dict[str, Any]:
        try:
            with self._opener.open(request, timeout=30) as response:
                raw = response.read(self.max_response_bytes + 1)
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
            raise GmailQuarantineError(
                f"Gmail ha rifiutato la quarantena (HTTP {status})"
            ) from exc
        except (OSError, urllib.error.URLError) as exc:
            raise GmailQuarantineError("connessione Gmail quarantena fallita") from exc
        if len(raw) > self.max_response_bytes:
            raise GmailQuarantineError("risposta Gmail quarantena oltre il limite")
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GmailQuarantineError("risposta Gmail quarantena non valida") from exc
        if not isinstance(decoded, dict):
            raise GmailQuarantineError("risposta Gmail quarantena non valida")
        return decoded

    def get_json(self, url: str, access_token: str) -> dict[str, Any]:
        self._validate_get_url(url)
        if not access_token.strip():
            raise GmailQuarantineError("access token Gmail mancante")
        return self._request_json(
            urllib.request.Request(
                url,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
                method="GET",
            )
        )

    def post_json(
        self,
        url: str,
        payload: dict[str, Any],
        access_token: str,
    ) -> dict[str, Any]:
        self._validate_post(url, payload)
        if not access_token.strip():
            raise GmailQuarantineError("access token Gmail mancante")
        return self._request_json(
            urllib.request.Request(
                url,
                data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
        )


class GmailLabelQuarantineExecutor:
    """Applica solo l'etichetta pilot; non rimuove INBOX e non espone altre azioni."""

    def __init__(
        self,
        token_provider: AccessTokenProvider,
        transport: QuarantineTransport | None = None,
    ) -> None:
        if token_provider.scopes != frozenset({GMAIL_MODIFY_SCOPE}):
            raise ValueError("la quarantena richiede esattamente gmail.modify")
        self.token_provider = token_provider
        self.transport = transport or DirectGmailQuarantineTransport()
        self._label_id: str | None = None

    def _get(self, path: str, query: dict[str, str] | None = None) -> dict[str, Any]:
        encoded = urllib.parse.urlencode(query or {})
        url = f"{GMAIL_API_ORIGIN}{path}?{encoded}" if encoded else f"{GMAIL_API_ORIGIN}{path}"
        return self.transport.get_json(url, self.token_provider.get_access_token())

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self.transport.post_json(
            f"{GMAIL_API_ORIGIN}{path}",
            payload,
            self.token_provider.get_access_token(),
        )

    @staticmethod
    def _validated_label_id(raw: Any) -> str:
        if (
            not isinstance(raw, str)
            or not _LABEL_ID.fullmatch(raw)
            or raw in _SYSTEM_LABEL_IDS
        ):
            raise GmailQuarantineError("ID etichetta quarantena non valido")
        return raw

    def _ensure_label(self) -> str:
        if self._label_id is not None:
            return self._label_id
        response = self._get(LABELS_PATH)
        labels = response.get("labels", [])
        if not isinstance(labels, list):
            raise GmailQuarantineError("elenco etichette Gmail non valido")
        matches: list[str] = []
        for raw in labels:
            if not isinstance(raw, dict) or raw.get("name") != QUARANTINE_LABEL_NAME:
                continue
            if raw.get("type") != "user":
                raise GmailQuarantineError("l'etichetta quarantena non è un'etichetta utente")
            matches.append(self._validated_label_id(raw.get("id")))
        if len(matches) > 1:
            raise GmailQuarantineError("più etichette quarantena con lo stesso nome")
        if matches:
            self._label_id = matches[0]
            return matches[0]
        created = self._post(
            LABELS_PATH,
            {
                "name": QUARANTINE_LABEL_NAME,
                "messageListVisibility": "show",
                "labelListVisibility": "labelShow",
            },
        )
        if created.get("name") != QUARANTINE_LABEL_NAME:
            raise GmailQuarantineError("Gmail ha creato un'etichetta inattesa")
        self._label_id = self._validated_label_id(created.get("id"))
        return self._label_id

    def apply_label_quarantine(
        self,
        message_id: str,
        expected_unread: bool,
    ) -> QuarantineResult:
        if not _MESSAGE_ID.fullmatch(message_id):
            raise GmailQuarantineError("ID messaggio Gmail non valido")
        if type(expected_unread) is not bool:
            raise GmailQuarantineError("stato unread Gmail atteso non valido")
        safe_id = urllib.parse.quote(message_id, safe="")
        resource = self._get(
            f"/gmail/v1/users/me/messages/{safe_id}",
            {"format": "minimal", "fields": "id,labelIds"},
        )
        if resource.get("id") != message_id:
            raise GmailQuarantineError("ID risposta Gmail non corrispondente")
        raw_labels = resource.get("labelIds", [])
        if not isinstance(raw_labels, list) or not all(
            isinstance(label, str) for label in raw_labels
        ):
            raise GmailQuarantineError("etichette messaggio Gmail non valide")
        labels = frozenset(raw_labels)
        if "INBOX" not in labels or labels.intersection(_FORBIDDEN_INPUT_LABELS):
            return QuarantineResult(QuarantineOutcome.SKIPPED_NOT_INBOX)
        if ("UNREAD" in labels) is not expected_unread:
            return QuarantineResult(QuarantineOutcome.SKIPPED_PROTECTED)
        if labels.intersection(_PROTECTED_INPUT_LABELS):
            return QuarantineResult(QuarantineOutcome.SKIPPED_PROTECTED)

        label_id = self._ensure_label()
        if label_id in labels:
            return QuarantineResult(QuarantineOutcome.ALREADY_APPLIED)
        changed = self._post(
            f"/gmail/v1/users/me/messages/{safe_id}/modify",
            {"addLabelIds": [label_id], "removeLabelIds": []},
        )
        if changed.get("id") != message_id:
            raise GmailQuarantineError("risposta modifica Gmail non corrispondente")
        changed_labels = changed.get("labelIds", [])
        if not isinstance(changed_labels, list) or label_id not in changed_labels:
            raise GmailQuarantineError("Gmail non ha confermato l'etichetta quarantena")
        return QuarantineResult(QuarantineOutcome.APPLIED)


class ThreatMarkerOutcome(StrEnum):
    APPLIED = "applied"
    ALREADY_APPLIED = "already_applied"
    SKIPPED_NOT_INBOX = "skipped_not_inbox"


@dataclass(frozen=True, slots=True)
class ThreatMarkerResult:
    outcome: ThreatMarkerOutcome

    @property
    def changes_mailbox(self) -> bool:
        return self.outcome is ThreatMarkerOutcome.APPLIED


class GmailThreatMarkerExecutor(GmailLabelQuarantineExecutor):
    """Add a visible phishing label while leaving the message in Inbox."""

    def _ensure_label(self) -> str:
        if self._label_id is not None:
            return self._label_id
        response = self._get(LABELS_PATH)
        labels = response.get("labels", [])
        if not isinstance(labels, list):
            raise GmailQuarantineError("elenco etichette Gmail non valido")
        matches: list[str] = []
        for raw in labels:
            if not isinstance(raw, dict) or raw.get("name") != THREAT_LABEL_NAME:
                continue
            if raw.get("type") != "user":
                raise GmailQuarantineError("l'etichetta phishing non è un'etichetta utente")
            matches.append(self._validated_label_id(raw.get("id")))
        if len(matches) > 1:
            raise GmailQuarantineError("più etichette phishing con lo stesso nome")
        if matches:
            self._label_id = matches[0]
            return matches[0]
        created = self._post(
            LABELS_PATH,
            {
                "name": THREAT_LABEL_NAME,
                "messageListVisibility": "show",
                "labelListVisibility": "labelShow",
            },
        )
        if created.get("name") != THREAT_LABEL_NAME:
            raise GmailQuarantineError("Gmail ha creato un'etichetta phishing inattesa")
        self._label_id = self._validated_label_id(created.get("id"))
        return self._label_id

    def apply(self, message_id: str) -> ThreatMarkerResult:
        if not _MESSAGE_ID.fullmatch(message_id):
            raise GmailQuarantineError("ID messaggio Gmail non valido")
        safe_id = urllib.parse.quote(message_id, safe="")
        resource = self._get(
            f"/gmail/v1/users/me/messages/{safe_id}",
            {"format": "minimal", "fields": "id,labelIds"},
        )
        if resource.get("id") != message_id:
            raise GmailQuarantineError("ID risposta Gmail non corrispondente")
        raw_labels = resource.get("labelIds", [])
        if not isinstance(raw_labels, list) or not all(
            isinstance(label, str) for label in raw_labels
        ):
            raise GmailQuarantineError("etichette messaggio Gmail non valide")
        labels = frozenset(raw_labels)
        if "INBOX" not in labels or labels.intersection(_FORBIDDEN_INPUT_LABELS):
            return ThreatMarkerResult(ThreatMarkerOutcome.SKIPPED_NOT_INBOX)
        label_id = self._ensure_label()
        if label_id in labels:
            return ThreatMarkerResult(ThreatMarkerOutcome.ALREADY_APPLIED)
        changed = self._post(
            f"/gmail/v1/users/me/messages/{safe_id}/modify",
            {"addLabelIds": [label_id], "removeLabelIds": []},
        )
        if changed.get("id") != message_id:
            raise GmailQuarantineError("risposta modifica Gmail non corrispondente")
        changed_labels = changed.get("labelIds", [])
        if (
            not isinstance(changed_labels, list)
            or label_id not in changed_labels
            or "INBOX" not in changed_labels
        ):
            raise GmailQuarantineError("Gmail non ha confermato l'etichetta phishing")
        return ThreatMarkerResult(ThreatMarkerOutcome.APPLIED)
