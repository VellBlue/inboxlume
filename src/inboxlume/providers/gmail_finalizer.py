from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol

from ..models import EmailCategory
from .contracts import GMAIL_MODIFY_SCOPE
from .gmail_quarantine import (
    GMAIL_API_ORIGIN,
    LABELS_PATH,
    LEGACY_QUARANTINE_LABEL_NAME,
    QUARANTINE_LABEL_NAME,
)


QUARANTINE_DELAY_DAYS = 3
_MESSAGE_ID = re.compile(r"[A-Za-z0-9_-]{1,256}")
_LABEL_ID = re.compile(r"[A-Za-z0-9_-]{1,256}")
_MESSAGE_METADATA_PATH = re.compile(
    r"^/gmail/v1/users/me/messages/([A-Za-z0-9_-]+)$"
)
_MESSAGE_TRASH_PATH = re.compile(
    r"^/gmail/v1/users/me/messages/([A-Za-z0-9_-]+)/trash$"
)
_MESSAGE_MODIFY_PATH = re.compile(
    r"^/gmail/v1/users/me/messages/([A-Za-z0-9_-]+)/modify$"
)
_PROTECTED_LABELS = frozenset({"STARRED", "IMPORTANT"})
_FORBIDDEN_SOURCE_LABELS = frozenset({"SENT", "DRAFT"})
_TRASH_CATEGORIES = frozenset(
    {
        EmailCategory.ADVERTISING,
        EmailCategory.ONE_TIME_CODE,
        EmailCategory.SECURITY,
        EmailCategory.SOCIAL,
    }
)
MAX_RESPONSE_BYTES = 512_000


class GmailFinalizationError(RuntimeError):
    pass


class FinalizationOutcome(StrEnum):
    MOVED_TO_TRASH = "moved_to_trash"
    MOVED_TO_SPAM = "moved_to_spam"
    CANCELLED_LABEL_REMOVED = "cancelled_label_removed"
    CANCELLED_NOT_INBOX = "cancelled_not_inbox"
    CANCELLED_PROTECTED = "cancelled_protected"
    ALREADY_FINALIZED = "already_finalized"


@dataclass(frozen=True, slots=True)
class MatureQuarantineCandidate:
    message_id: str
    category: EmailCategory
    quarantined_at: datetime
    expected_unread: bool

    def __post_init__(self) -> None:
        if not _MESSAGE_ID.fullmatch(self.message_id):
            raise ValueError("ID candidato finalizzazione non valido")
        if self.quarantined_at.tzinfo is None:
            raise ValueError("quarantined_at deve includere il fuso orario")
        if type(self.expected_unread) is not bool:
            raise ValueError("expected_unread candidato finalizzazione non valido")


@dataclass(frozen=True, slots=True)
class FinalizationResult:
    outcome: FinalizationOutcome

    @property
    def changes_mailbox(self) -> bool:
        return self.outcome in {
            FinalizationOutcome.MOVED_TO_SPAM,
            FinalizationOutcome.MOVED_TO_TRASH,
        }


class AccessTokenProvider(Protocol):
    @property
    def scopes(self) -> frozenset[str]: ...

    def get_access_token(self) -> str: ...


class FinalizationTransport(Protocol):
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


class DirectGmailFinalizationTransport:
    """Trasporto finale ristretto a metadati, Cestino e label SPAM."""

    def __init__(self, max_response_bytes: int = MAX_RESPONSE_BYTES) -> None:
        self.max_response_bytes = max_response_bytes
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
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
            raise GmailFinalizationError("endpoint Gmail finale non consentito")
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
        raise GmailFinalizationError("GET Gmail finale non consentita")

    @classmethod
    def _validate_post(cls, url: str, payload: dict[str, Any]) -> None:
        parsed = cls._parsed(url)
        if parsed.query:
            raise GmailFinalizationError("POST Gmail finale non consentita")
        if _MESSAGE_TRASH_PATH.fullmatch(parsed.path) and payload == {}:
            return
        if _MESSAGE_MODIFY_PATH.fullmatch(parsed.path) and payload == {
            "addLabelIds": ["SPAM"],
            "removeLabelIds": ["INBOX"],
        }:
            return
        raise GmailFinalizationError("POST Gmail finale non consentita")

    def _request_json(self, request: urllib.request.Request) -> dict[str, Any]:
        try:
            with self._opener.open(request, timeout=30) as response:
                raw = response.read(self.max_response_bytes + 1)
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
            raise GmailFinalizationError(
                f"Gmail ha rifiutato la finalizzazione (HTTP {status})"
            ) from exc
        except (OSError, urllib.error.URLError) as exc:
            raise GmailFinalizationError("connessione Gmail finale fallita") from exc
        if len(raw) > self.max_response_bytes:
            raise GmailFinalizationError("risposta Gmail finale oltre il limite")
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GmailFinalizationError("risposta Gmail finale non valida") from exc
        if not isinstance(decoded, dict):
            raise GmailFinalizationError("risposta Gmail finale non valida")
        return decoded

    def get_json(self, url: str, access_token: str) -> dict[str, Any]:
        self._validate_get_url(url)
        if not access_token.strip():
            raise GmailFinalizationError("access token Gmail mancante")
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
            raise GmailFinalizationError("access token Gmail mancante")
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


class DirectGmailTrashTransport(DirectGmailFinalizationTransport):
    """Trasporto ristretto a metadati Inbox e spostamento nel Cestino."""

    @classmethod
    def _validate_get_url(cls, url: str) -> None:
        parsed = cls._parsed(url)
        if _MESSAGE_METADATA_PATH.fullmatch(parsed.path):
            query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if query == {"fields": ["id,labelIds"], "format": ["minimal"]}:
                return
        raise GmailFinalizationError("GET Gmail Cestino non consentita")

    @classmethod
    def _validate_post(cls, url: str, payload: dict[str, Any]) -> None:
        parsed = cls._parsed(url)
        if (
            not parsed.query
            and _MESSAGE_TRASH_PATH.fullmatch(parsed.path)
            and payload == {}
        ):
            return
        raise GmailFinalizationError("POST Gmail Cestino non consentita")


class GmailDirectTrashExecutor:
    """Sposta nel Cestino solo messaggi Inbox non protetti; mai delete/emptyTrash."""

    def __init__(
        self,
        token_provider: AccessTokenProvider,
        transport: FinalizationTransport | None = None,
    ) -> None:
        if token_provider.scopes != frozenset({GMAIL_MODIFY_SCOPE}):
            raise ValueError("il Cestino richiede esattamente gmail.modify")
        self.token_provider = token_provider
        self.transport = transport or DirectGmailTrashTransport()

    def _get(self, path: str, query: dict[str, str]) -> dict[str, Any]:
        encoded = urllib.parse.urlencode(query)
        return self.transport.get_json(
            f"{GMAIL_API_ORIGIN}{path}?{encoded}",
            self.token_provider.get_access_token(),
        )

    def _post(self, path: str) -> dict[str, Any]:
        return self.transport.post_json(
            f"{GMAIL_API_ORIGIN}{path}",
            {},
            self.token_provider.get_access_token(),
        )

    def apply(
        self,
        message_id: str,
        expected_unread: bool,
    ) -> FinalizationResult:
        if not _MESSAGE_ID.fullmatch(message_id):
            raise GmailFinalizationError("ID messaggio Gmail non valido")
        if type(expected_unread) is not bool:
            raise GmailFinalizationError("stato unread Gmail atteso non valido")
        safe_id = urllib.parse.quote(message_id, safe="")
        resource = self._get(
            f"/gmail/v1/users/me/messages/{safe_id}",
            {"format": "minimal", "fields": "id,labelIds"},
        )
        if resource.get("id") != message_id:
            raise GmailFinalizationError("ID risposta Gmail non corrispondente")
        raw_labels = resource.get("labelIds", [])
        if not isinstance(raw_labels, list) or not all(
            isinstance(label, str) for label in raw_labels
        ):
            raise GmailFinalizationError("etichette messaggio Gmail non valide")
        labels = frozenset(raw_labels)
        if labels.intersection({"TRASH", "SPAM"}):
            return FinalizationResult(FinalizationOutcome.ALREADY_FINALIZED)
        if "INBOX" not in labels or labels.intersection(_FORBIDDEN_SOURCE_LABELS):
            return FinalizationResult(FinalizationOutcome.CANCELLED_NOT_INBOX)
        # The selection's read state is part of its authority.  Reject either
        # direction of drift at the last provider-side boundary: a newly
        # unread message needs attention, while a newly read one is no longer
        # the same candidate that the policy approved.
        if ("UNREAD" in labels) is not expected_unread:
            return FinalizationResult(FinalizationOutcome.CANCELLED_PROTECTED)
        if labels.intersection(_PROTECTED_LABELS):
            return FinalizationResult(FinalizationOutcome.CANCELLED_PROTECTED)

        changed = self._post(f"/gmail/v1/users/me/messages/{safe_id}/trash")
        if changed.get("id") != message_id:
            raise GmailFinalizationError("risposta Gmail Cestino non corrispondente")
        changed_labels = changed.get("labelIds", [])
        if not isinstance(changed_labels, list) or "TRASH" not in changed_labels:
            raise GmailFinalizationError("Gmail non ha confermato il Cestino")
        return FinalizationResult(FinalizationOutcome.MOVED_TO_TRASH)


class GmailQuarantineFinalizer:
    """Finalizza dopo tre giorni; nessun metodo elimina definitivamente messaggi."""

    def __init__(
        self,
        token_provider: AccessTokenProvider,
        transport: FinalizationTransport | None = None,
    ) -> None:
        if token_provider.scopes != frozenset({GMAIL_MODIFY_SCOPE}):
            raise ValueError("la finalizzazione richiede esattamente gmail.modify")
        self.token_provider = token_provider
        self.transport = transport or DirectGmailFinalizationTransport()
        self._label_ids: frozenset[str] | None = None

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

    def _required_quarantine_label_ids(self) -> frozenset[str]:
        if self._label_ids is not None:
            return self._label_ids
        response = self._get(LABELS_PATH)
        labels = response.get("labels", [])
        if not isinstance(labels, list):
            raise GmailFinalizationError("elenco etichette Gmail non valido")
        accepted_names = {QUARANTINE_LABEL_NAME, LEGACY_QUARANTINE_LABEL_NAME}
        matches: dict[str, str] = {}
        for raw in labels:
            if not isinstance(raw, dict) or raw.get("name") not in accepted_names:
                continue
            name = raw["name"]
            label_id = raw.get("id")
            if (
                raw.get("type") != "user"
                or not isinstance(label_id, str)
                or not _LABEL_ID.fullmatch(label_id)
            ):
                raise GmailFinalizationError("etichetta quarantena Gmail non valida")
            if name in matches:
                raise GmailFinalizationError("etichetta quarantena Gmail ambigua")
            matches[name] = label_id
        if not matches:
            raise GmailFinalizationError("etichetta quarantena Gmail assente o ambigua")
        self._label_ids = frozenset(matches.values())
        return self._label_ids

    def finalize(
        self,
        candidate: MatureQuarantineCandidate,
        now: datetime,
    ) -> FinalizationResult:
        if now.tzinfo is None:
            raise ValueError("now deve includere il fuso orario")
        if now < candidate.quarantined_at + timedelta(days=QUARANTINE_DELAY_DAYS):
            raise ValueError("la quarantena non ha ancora raggiunto tre giorni")
        if candidate.category is EmailCategory.SPAM:
            destination = "spam"
        elif candidate.category in _TRASH_CATEGORIES:
            destination = "trash"
        else:
            raise ValueError("categoria non autorizzata alla finalizzazione")

        safe_id = urllib.parse.quote(candidate.message_id, safe="")
        resource = self._get(
            f"/gmail/v1/users/me/messages/{safe_id}",
            {"format": "minimal", "fields": "id,labelIds"},
        )
        if resource.get("id") != candidate.message_id:
            raise GmailFinalizationError("ID risposta Gmail non corrispondente")
        raw_labels = resource.get("labelIds", [])
        if not isinstance(raw_labels, list) or not all(
            isinstance(label, str) for label in raw_labels
        ):
            raise GmailFinalizationError("etichette messaggio Gmail non valide")
        labels = frozenset(raw_labels)
        if labels.intersection({"TRASH", "SPAM"}):
            return FinalizationResult(FinalizationOutcome.ALREADY_FINALIZED)
        if "INBOX" not in labels or labels.intersection(_FORBIDDEN_SOURCE_LABELS):
            return FinalizationResult(FinalizationOutcome.CANCELLED_NOT_INBOX)
        if ("UNREAD" in labels) is not candidate.expected_unread:
            return FinalizationResult(FinalizationOutcome.CANCELLED_PROTECTED)
        if labels.intersection(_PROTECTED_LABELS):
            return FinalizationResult(FinalizationOutcome.CANCELLED_PROTECTED)
        if labels.isdisjoint(self._required_quarantine_label_ids()):
            return FinalizationResult(FinalizationOutcome.CANCELLED_LABEL_REMOVED)

        if destination == "trash":
            changed = self._post(
                f"/gmail/v1/users/me/messages/{safe_id}/trash",
                {},
            )
            expected_label = "TRASH"
            outcome = FinalizationOutcome.MOVED_TO_TRASH
        else:
            changed = self._post(
                f"/gmail/v1/users/me/messages/{safe_id}/modify",
                {"addLabelIds": ["SPAM"], "removeLabelIds": ["INBOX"]},
            )
            expected_label = "SPAM"
            outcome = FinalizationOutcome.MOVED_TO_SPAM
        if changed.get("id") != candidate.message_id:
            raise GmailFinalizationError("risposta finale Gmail non corrispondente")
        changed_labels = changed.get("labelIds", [])
        if not isinstance(changed_labels, list) or expected_label not in changed_labels:
            raise GmailFinalizationError("Gmail non ha confermato la destinazione")
        return FinalizationResult(outcome)
