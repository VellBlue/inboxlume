from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import platform
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Callable, Protocol

from ..credential_store import SystemCredentialStore
from ..tls_trust import https_handler
from .contracts import GMAIL_MODIFY_SCOPE, GMAIL_READONLY_SCOPE


GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_CLIENT_AUTH_URIS = frozenset(
    {
        GOOGLE_AUTH_ENDPOINT,
        "https://accounts.google.com/o/oauth2/auth",
    }
)
CALLBACK_PATH = "/oauth2/callback"
# Gli identificatori del Portachiavi restano quelli del prototipo: sono opachi e
# mantenerli evita di richiedere una nuova autorizzazione durante il rebranding.
OAUTH_CLIENT_KEYCHAIN_SERVICE = "it.local.mail-guardian.gmail.oauth-client.v1"
REFRESH_TOKEN_KEYCHAIN_SERVICE = "it.local.mail-guardian.gmail.refresh-token.v1"
QUARANTINE_REFRESH_TOKEN_KEYCHAIN_SERVICE = (
    "it.local.mail-guardian.gmail.quarantine-refresh-token.v1"
)
MAX_CLIENT_FILE_BYTES = 64_000
MAX_TOKEN_RESPONSE_BYTES = 128_000
MAX_CALLBACK_QUERY_CHARS = 16_000
_ACCOUNT_ID = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_CLIENT_ID = re.compile(r"[A-Za-z0-9._-]+\.apps\.googleusercontent\.com")
_ALLOWED_EXACT_SCOPES = frozenset({GMAIL_READONLY_SCOPE, GMAIL_MODIFY_SCOPE})


class GoogleOAuthError(RuntimeError):
    pass


class KeychainError(RuntimeError):
    pass


class SecretStore(Protocol):
    def get(self, service: str, account: str) -> str | None: ...

    def set(self, service: str, account: str, secret: str) -> None: ...


class OAuthTokenTransport(Protocol):
    def post_form(self, url: str, fields: dict[str, str]) -> dict[str, Any]: ...


def _validate_account_id(account_id: str) -> None:
    if not _ACCOUNT_ID.fullmatch(account_id):
        raise ValueError("account_id non valido per il Portachiavi")


@dataclass(frozen=True)
class OAuthClientCredentials:
    client_id: str
    client_secret: str

    def __post_init__(self) -> None:
        if not _CLIENT_ID.fullmatch(self.client_id) or len(self.client_id) > 512:
            raise ValueError("client_id OAuth Google non valido")
        if not self.client_secret or len(self.client_secret) > 2_000:
            raise ValueError("client_secret OAuth Google non valido")

    @classmethod
    def from_json_file(cls, path: Path) -> OAuthClientCredentials:
        try:
            if not path.is_file() or path.stat().st_size > MAX_CLIENT_FILE_BYTES:
                raise ValueError("file client OAuth assente o troppo grande")
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("file client OAuth Google non valido") from exc
        if not isinstance(raw, dict) or not isinstance(raw.get("installed"), dict):
            raise ValueError("occorrono credenziali OAuth di tipo Desktop app")
        installed = raw["installed"]
        if installed.get("auth_uri") not in GOOGLE_CLIENT_AUTH_URIS:
            raise ValueError("auth_uri OAuth Google non consentito")
        if installed.get("token_uri") != GOOGLE_TOKEN_ENDPOINT:
            raise ValueError("token_uri OAuth Google non consentito")
        redirect_uris = installed.get("redirect_uris")
        if not isinstance(redirect_uris, list) or not redirect_uris:
            raise ValueError("redirect URI Desktop app mancante")
        for uri in redirect_uris:
            if not isinstance(uri, str):
                raise ValueError("redirect URI Desktop app non valido")
            parsed = urllib.parse.urlparse(uri)
            if parsed.scheme != "http" or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
                raise ValueError("il client OAuth deve usare soltanto redirect loopback")
        return cls(
            client_id=str(installed.get("client_id", "")),
            client_secret=str(installed.get("client_secret", "")),
        )

    def to_keychain_json(self) -> str:
        return json.dumps(
            {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "token_uri": GOOGLE_TOKEN_ENDPOINT,
                "version": 1,
            },
            separators=(",", ":"),
            sort_keys=True,
        )

    @classmethod
    def from_keychain_json(cls, value: str) -> OAuthClientCredentials:
        try:
            raw = json.loads(value)
        except json.JSONDecodeError as exc:
            raise KeychainError("credenziali OAuth nel Portachiavi non valide") from exc
        if (
            not isinstance(raw, dict)
            or raw.get("version") != 1
            or raw.get("token_uri") != GOOGLE_TOKEN_ENDPOINT
        ):
            raise KeychainError("credenziali OAuth nel Portachiavi non valide")
        try:
            return cls(str(raw["client_id"]), str(raw["client_secret"]))
        except (KeyError, ValueError) as exc:
            raise KeychainError("credenziali OAuth nel Portachiavi non valide") from exc


@dataclass(frozen=True)
class StoredRefreshAuthorization:
    refresh_token: str
    scopes: frozenset[str] = frozenset({GMAIL_READONLY_SCOPE})

    def __post_init__(self) -> None:
        if not self.refresh_token or len(self.refresh_token) > 16_000:
            raise ValueError("refresh token Google non valido")
        if len(self.scopes) != 1 or not self.scopes.issubset(_ALLOWED_EXACT_SCOPES):
            raise ValueError("scope OAuth memorizzati non consentiti")

    def to_keychain_json(self) -> str:
        return json.dumps(
            {
                "refresh_token": self.refresh_token,
                "scopes": sorted(self.scopes),
                "version": 1,
            },
            separators=(",", ":"),
            sort_keys=True,
        )

    @classmethod
    def from_keychain_json(cls, value: str) -> StoredRefreshAuthorization:
        try:
            raw = json.loads(value)
        except json.JSONDecodeError as exc:
            raise KeychainError("autorizzazione Gmail nel Portachiavi non valida") from exc
        if not isinstance(raw, dict) or raw.get("version") != 1:
            raise KeychainError("autorizzazione Gmail nel Portachiavi non valida")
        scopes = raw.get("scopes")
        if not isinstance(scopes, list) or not all(isinstance(item, str) for item in scopes):
            raise KeychainError("scope Gmail nel Portachiavi non validi")
        try:
            return cls(str(raw["refresh_token"]), frozenset(scopes))
        except (KeyError, ValueError) as exc:
            raise KeychainError("autorizzazione Gmail nel Portachiavi non valida") from exc


class MacOSKeychainStore:
    """Portachiavi nativo, senza passare segreti nella riga di comando."""

    _ERR_ITEM_NOT_FOUND = -25300
    _ERR_DUPLICATE_ITEM = -25299

    def __init__(self) -> None:
        if platform.system() != "Darwin":
            raise KeychainError("il Portachiavi macOS è disponibile soltanto su macOS")
        try:
            self._security = ctypes.CDLL(
                "/System/Library/Frameworks/Security.framework/Security"
            )
            self._core_foundation = ctypes.CDLL(
                "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
            )
        except OSError as exc:
            raise KeychainError("framework Portachiavi macOS non disponibile") from exc
        self._configure_functions()

    def _configure_functions(self) -> None:
        void_p = ctypes.c_void_p
        uint32 = ctypes.c_uint32
        self._security.SecKeychainFindGenericPassword.argtypes = [
            void_p,
            uint32,
            ctypes.c_char_p,
            uint32,
            ctypes.c_char_p,
            ctypes.POINTER(uint32),
            ctypes.POINTER(void_p),
            ctypes.POINTER(void_p),
        ]
        self._security.SecKeychainFindGenericPassword.restype = ctypes.c_int32
        self._security.SecKeychainCopyDefault.argtypes = [ctypes.POINTER(void_p)]
        self._security.SecKeychainCopyDefault.restype = ctypes.c_int32
        self._security.SecKeychainAddGenericPassword.argtypes = [
            void_p,
            uint32,
            ctypes.c_char_p,
            uint32,
            ctypes.c_char_p,
            uint32,
            void_p,
            ctypes.POINTER(void_p),
        ]
        self._security.SecKeychainAddGenericPassword.restype = ctypes.c_int32
        self._security.SecKeychainItemModifyAttributesAndData.argtypes = [
            void_p,
            void_p,
            uint32,
            void_p,
        ]
        self._security.SecKeychainItemModifyAttributesAndData.restype = ctypes.c_int32
        self._security.SecKeychainItemFreeContent.argtypes = [void_p, void_p]
        self._security.SecKeychainItemFreeContent.restype = ctypes.c_int32
        self._core_foundation.CFRelease.argtypes = [void_p]
        self._core_foundation.CFRelease.restype = None

    @staticmethod
    def _field(value: str, label: str) -> bytes:
        if not value or len(value) > 512 or "\x00" in value:
            raise ValueError(f"{label} Portachiavi non valido")
        return value.encode("utf-8")

    def _find(
        self, keychain: ctypes.c_void_p, service: bytes, account: bytes
    ) -> tuple[int, int, ctypes.c_void_p, ctypes.c_void_p]:
        length = ctypes.c_uint32()
        data = ctypes.c_void_p()
        item = ctypes.c_void_p()
        status = self._security.SecKeychainFindGenericPassword(
            keychain,
            len(service),
            service,
            len(account),
            account,
            ctypes.byref(length),
            ctypes.byref(data),
            ctypes.byref(item),
        )
        return int(status), int(length.value), data, item

    def _copy_default_keychain(self) -> ctypes.c_void_p:
        keychain = ctypes.c_void_p()
        status = self._security.SecKeychainCopyDefault(ctypes.byref(keychain))
        if status != 0 or not keychain:
            raise KeychainError(
                f"Portachiavi predefinito non disponibile (OSStatus {int(status)})"
            )
        return keychain

    def get(self, service: str, account: str) -> str | None:
        service_bytes = self._field(service, "service")
        account_bytes = self._field(account, "account")
        keychain = self._copy_default_keychain()
        status, length, data, item = self._find(keychain, service_bytes, account_bytes)
        try:
            if status == self._ERR_ITEM_NOT_FOUND:
                return None
            if status != 0:
                raise KeychainError(f"lettura Portachiavi fallita (OSStatus {status})")
            raw = ctypes.string_at(data, length)
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise KeychainError("dato Portachiavi non UTF-8") from exc
        finally:
            if data:
                self._security.SecKeychainItemFreeContent(None, data)
            if item:
                self._core_foundation.CFRelease(item)
            self._core_foundation.CFRelease(keychain)

    def set(self, service: str, account: str, secret: str) -> None:
        service_bytes = self._field(service, "service")
        account_bytes = self._field(account, "account")
        secret_bytes = secret.encode("utf-8")
        if not secret_bytes or len(secret_bytes) > 64_000:
            raise ValueError("segreto Portachiavi non valido")
        secret_buffer = ctypes.create_string_buffer(secret_bytes, len(secret_bytes) + 1)
        keychain = self._copy_default_keychain()
        try:
            status, _, found_data, item = self._find(
                keychain, service_bytes, account_bytes
            )
            if found_data:
                self._security.SecKeychainItemFreeContent(None, found_data)
            if status == 0:
                try:
                    update_status = self._security.SecKeychainItemModifyAttributesAndData(
                        item,
                        None,
                        len(secret_bytes),
                        secret_buffer,
                    )
                finally:
                    if item:
                        self._core_foundation.CFRelease(item)
                if update_status != 0:
                    raise KeychainError(
                        f"aggiornamento Portachiavi fallito (OSStatus {update_status})"
                    )
                return
            if item:
                self._core_foundation.CFRelease(item)
            if status != self._ERR_ITEM_NOT_FOUND:
                raise KeychainError(f"ricerca Portachiavi fallita (OSStatus {status})")
            add_status = self._security.SecKeychainAddGenericPassword(
                keychain,
                len(service_bytes),
                service_bytes,
                len(account_bytes),
                account_bytes,
                len(secret_bytes),
                secret_buffer,
                None,
            )
            if add_status == self._ERR_DUPLICATE_ITEM:
                # Una rara corsa tra find e add viene risolta con un solo nuovo tentativo.
                return self.set(service, account, secret)
            if add_status != 0:
                raise KeychainError(
                    f"scrittura Portachiavi fallita (OSStatus {add_status})"
                )
        finally:
            ctypes.memset(secret_buffer, 0, len(secret_buffer))
            self._core_foundation.CFRelease(keychain)


def save_authorization(
    store: SecretStore,
    account_id: str,
    credentials: OAuthClientCredentials,
    refresh_token: str,
    scope: str = GMAIL_READONLY_SCOPE,
) -> None:
    _validate_account_id(account_id)
    authorization = StoredRefreshAuthorization(refresh_token, frozenset({scope}))
    store.set(OAUTH_CLIENT_KEYCHAIN_SERVICE, account_id, credentials.to_keychain_json())
    store.set(
        _refresh_token_service(scope),
        account_id,
        authorization.to_keychain_json(),
    )


def load_authorization(
    store: SecretStore,
    account_id: str,
    scope: str = GMAIL_READONLY_SCOPE,
) -> tuple[OAuthClientCredentials, StoredRefreshAuthorization]:
    _validate_account_id(account_id)
    client_raw = store.get(OAUTH_CLIENT_KEYCHAIN_SERVICE, account_id)
    token_raw = store.get(_refresh_token_service(scope), account_id)
    if client_raw is None or token_raw is None:
        raise KeychainError("account Gmail non ancora autorizzato")
    result = (
        OAuthClientCredentials.from_keychain_json(client_raw),
        StoredRefreshAuthorization.from_keychain_json(token_raw),
    )
    if result[1].scopes != frozenset({scope}):
        raise KeychainError("autorizzazione Gmail con scope inatteso")
    return result


def _refresh_token_service(scope: str) -> str:
    if scope == GMAIL_READONLY_SCOPE:
        return REFRESH_TOKEN_KEYCHAIN_SERVICE
    if scope == GMAIL_MODIFY_SCOPE:
        return QUARANTINE_REFRESH_TOKEN_KEYCHAIN_SERVICE
    raise ValueError("scope Gmail non consentito")


class DirectOAuthTokenTransport:
    """Accetta POST solo verso l'endpoint token Google, senza proxy o redirect."""

    def __init__(self, max_response_bytes: int = MAX_TOKEN_RESPONSE_BYTES) -> None:
        self.max_response_bytes = max_response_bytes
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            https_handler(),
            _NoRedirectHandler(),
        )

    @staticmethod
    def _validate_url(url: str) -> None:
        if url != GOOGLE_TOKEN_ENDPOINT:
            raise GoogleOAuthError("endpoint token OAuth non consentito")

    def post_form(self, url: str, fields: dict[str, str]) -> dict[str, Any]:
        self._validate_url(url)
        if not fields or not all(isinstance(k, str) and isinstance(v, str) for k, v in fields.items()):
            raise GoogleOAuthError("richiesta token OAuth non valida")
        body = urllib.parse.urlencode(fields).encode("ascii")
        request = urllib.request.Request(
            url,
            data=body,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )
        try:
            with self._opener.open(request, timeout=30) as response:
                payload = response.read(self.max_response_bytes + 1)
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
            raise GoogleOAuthError(f"Google ha rifiutato il token OAuth (HTTP {status})") from exc
        except (OSError, urllib.error.URLError) as exc:
            raise GoogleOAuthError("connessione all'endpoint token Google fallita") from exc
        if len(payload) > self.max_response_bytes:
            raise GoogleOAuthError("risposta token Google oltre il limite locale")
        try:
            decoded = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GoogleOAuthError("risposta token Google non valida") from exc
        if not isinstance(decoded, dict):
            raise GoogleOAuthError("risposta token Google non valida")
        return decoded


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


@dataclass(frozen=True)
class OAuthTokenResult:
    access_token: str
    expires_in: int
    refresh_token: str | None


def _validate_token_result(
    raw: dict[str, Any], *, require_refresh_token: bool, expected_scope: str
) -> OAuthTokenResult:
    _refresh_token_service(expected_scope)
    access_token = raw.get("access_token")
    token_type = raw.get("token_type")
    refresh_token = raw.get("refresh_token")
    try:
        expires_in = int(raw.get("expires_in"))
    except (TypeError, ValueError) as exc:
        raise GoogleOAuthError("scadenza access token Google non valida") from exc
    if not isinstance(access_token, str) or not access_token or len(access_token) > 16_000:
        raise GoogleOAuthError("access token Google non valido")
    if not isinstance(token_type, str) or token_type.casefold() != "bearer":
        raise GoogleOAuthError("tipo di token Google non consentito")
    if not 1 <= expires_in <= 86_400:
        raise GoogleOAuthError("scadenza access token Google non valida")
    if refresh_token is not None and (
        not isinstance(refresh_token, str) or not refresh_token or len(refresh_token) > 16_000
    ):
        raise GoogleOAuthError("refresh token Google non valido")
    if require_refresh_token and not refresh_token:
        raise GoogleOAuthError(
            "Google non ha restituito un refresh token; revoca il consenso precedente e riprova"
        )
    scope = raw.get("scope")
    if scope is not None:
        if not isinstance(scope, str) or frozenset(scope.split()) != frozenset(
            {expected_scope}
        ):
            raise GoogleOAuthError("Google ha restituito scope Gmail inattesi")
    return OAuthTokenResult(access_token, expires_in, refresh_token)


def generate_pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    return verifier, challenge


def build_authorization_url(
    credentials: OAuthClientCredentials,
    redirect_uri: str,
    state: str,
    code_challenge: str,
    scope: str = GMAIL_READONLY_SCOPE,
) -> str:
    _refresh_token_service(scope)
    parsed_redirect = urllib.parse.urlparse(redirect_uri)
    if (
        parsed_redirect.scheme != "http"
        or parsed_redirect.hostname != "127.0.0.1"
        or parsed_redirect.port is None
        or parsed_redirect.path != CALLBACK_PATH
    ):
        raise ValueError("redirect OAuth non limitato a 127.0.0.1")
    if not state or not code_challenge:
        raise ValueError("parametri OAuth di sicurezza mancanti")
    query = urllib.parse.urlencode(
        {
            "access_type": "offline",
            "client_id": credentials.client_id,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "include_granted_scopes": "false",
            "prompt": "consent",
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": scope,
            "state": state,
        }
    )
    return f"{GOOGLE_AUTH_ENDPOINT}?{query}"


class _LoopbackOAuthServer:
    def __init__(self, expected_state: str) -> None:
        self.expected_state = expected_state
        self.code: str | None = None
        self.error: str | None = None
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if self.client_address[0] != "127.0.0.1":
                    self.send_error(403)
                    return
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path != CALLBACK_PATH or len(parsed.query) > MAX_CALLBACK_QUERY_CHARS:
                    self.send_error(404)
                    return
                values = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                states = values.get("state", [])
                if len(states) != 1 or not secrets.compare_digest(states[0], outer.expected_state):
                    self._reply(400, "Richiesta OAuth non valida. Puoi chiudere questa scheda.")
                    return
                errors = values.get("error", [])
                codes = values.get("code", [])
                if len(errors) == 1:
                    outer.error = errors[0][:200]
                    self._reply(400, "Autorizzazione rifiutata. Puoi chiudere questa scheda.")
                    return
                if len(codes) != 1 or not codes[0] or len(codes[0]) > 8_000:
                    self._reply(400, "Codice OAuth non valido. Puoi chiudere questa scheda.")
                    return
                outer.code = codes[0]
                self._reply(200, "Autorizzazione ricevuta. Puoi chiudere questa scheda.")

            def do_POST(self) -> None:  # noqa: N802
                self.send_error(405)

            def _reply(self, status: int, message: str) -> None:
                body = (
                    "<!doctype html><meta charset=utf-8>"
                    "<meta name=referrer content=no-referrer>"
                    f"<title>InboxLume</title><p>{message}</p>"
                ).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'none'")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                return

        self._server = HTTPServer(("127.0.0.1", 0), Handler)

    @property
    def redirect_uri(self) -> str:
        port = int(self._server.server_address[1])
        return f"http://127.0.0.1:{port}{CALLBACK_PATH}"

    def wait(self, timeout_seconds: float) -> str:
        deadline = time.monotonic() + timeout_seconds
        while self.code is None and self.error is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise GoogleOAuthError("tempo scaduto in attesa del consenso Google")
            self._server.timeout = min(1.0, remaining)
            self._server.handle_request()
        if self.error is not None:
            raise GoogleOAuthError("autorizzazione Google rifiutata")
        assert self.code is not None
        return self.code

    def close(self) -> None:
        self._server.server_close()


class GoogleDesktopOAuthFlow:
    def __init__(
        self,
        transport: OAuthTokenTransport | None = None,
        scope: str = GMAIL_READONLY_SCOPE,
    ) -> None:
        self.transport = transport or DirectOAuthTokenTransport()
        _refresh_token_service(scope)
        self.scope = scope

    def authorize(
        self,
        credentials: OAuthClientCredentials,
        open_authorization_url: Callable[[str], None],
        timeout_seconds: float = 300,
    ) -> OAuthTokenResult:
        verifier, challenge = generate_pkce()
        state = secrets.token_urlsafe(32)
        server = _LoopbackOAuthServer(state)
        try:
            url = build_authorization_url(
                credentials,
                server.redirect_uri,
                state,
                challenge,
                self.scope,
            )
            open_authorization_url(url)
            code = server.wait(timeout_seconds)
            fields = {
                "client_id": credentials.client_id,
                "client_secret": credentials.client_secret,
                "code": code,
                "code_verifier": verifier,
                "grant_type": "authorization_code",
                "redirect_uri": server.redirect_uri,
            }
            raw = self.transport.post_form(GOOGLE_TOKEN_ENDPOINT, fields)
            return _validate_token_result(
                raw,
                require_refresh_token=True,
                expected_scope=self.scope,
            )
        finally:
            server.close()


class GoogleAccessTokenProvider:
    """Aggiorna l'access token in memoria partendo dal refresh token nel Portachiavi."""

    def __init__(
        self,
        account_id: str,
        store: SecretStore | None = None,
        transport: OAuthTokenTransport | None = None,
        scope: str = GMAIL_READONLY_SCOPE,
    ) -> None:
        _validate_account_id(account_id)
        _refresh_token_service(scope)
        self.account_id = account_id
        self.scope = scope
        self.scopes = frozenset({scope})
        self.store = store or SystemCredentialStore()
        self.transport = transport or DirectOAuthTokenTransport()
        self._access_token: str | None = None
        self._expires_at = 0.0

    def get_access_token(self) -> str:
        now = time.monotonic()
        if self._access_token is not None and now < self._expires_at:
            return self._access_token
        credentials, authorization = load_authorization(
            self.store,
            self.account_id,
            self.scope,
        )
        fields = {
            "client_id": credentials.client_id,
            "client_secret": credentials.client_secret,
            "grant_type": "refresh_token",
            "refresh_token": authorization.refresh_token,
        }
        raw = self.transport.post_form(GOOGLE_TOKEN_ENDPOINT, fields)
        token = _validate_token_result(
            raw,
            require_refresh_token=False,
            expected_scope=self.scope,
        )
        self._access_token = token.access_token
        self._expires_at = now + max(1, token.expires_in - 60)
        return token.access_token
