from __future__ import annotations

import json
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from typing import Any

from inboxlume.cli import authorize_gmail, authorize_gmail_quarantine
from inboxlume.providers.contracts import GMAIL_MODIFY_SCOPE, GMAIL_READONLY_SCOPE
from inboxlume.providers.google_oauth import (
    GOOGLE_AUTH_ENDPOINT,
    GOOGLE_TOKEN_ENDPOINT,
    OAUTH_CLIENT_KEYCHAIN_SERVICE,
    QUARANTINE_REFRESH_TOKEN_KEYCHAIN_SERVICE,
    REFRESH_TOKEN_KEYCHAIN_SERVICE,
    DirectOAuthTokenTransport,
    GoogleAccessTokenProvider,
    GoogleOAuthError,
    MacOSKeychainStore,
    OAuthClientCredentials,
    OAuthTokenResult,
    build_authorization_url,
    generate_pkce,
    save_authorization,
)


ROOT = Path(__file__).resolve().parents[1]


class MemorySecretStore:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get(self, service: str, account: str) -> str | None:
        return self.values.get((service, account))

    def set(self, service: str, account: str, secret: str) -> None:
        self.values[(service, account)] = secret


class QueueTokenTransport:
    def __init__(self, responses: list[dict[str, Any]]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, dict[str, str]]] = []

    def post_form(self, url: str, fields: dict[str, str]) -> dict[str, Any]:
        self.calls.append((url, dict(fields)))
        if not self.responses:
            raise AssertionError("richiesta token inattesa")
        return self.responses.pop(0)


class FakeFlow:
    def __init__(self, result: OAuthTokenResult) -> None:
        self.result = result
        self.calls: list[tuple[OAuthClientCredentials, float]] = []

    def authorize(
        self,
        credentials: OAuthClientCredentials,
        open_authorization_url,
        timeout_seconds: float = 300,
    ) -> OAuthTokenResult:
        self.calls.append((credentials, timeout_seconds))
        return self.result


def client_document(redirect_uris: list[str] | None = None) -> dict[str, Any]:
    return {
        "installed": {
            "client_id": "123456-example.apps.googleusercontent.com",
            "project_id": "mail-guardian-test",
            # È il valore ancora presente in molti JSON Desktop scaricati da Google.
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": GOOGLE_TOKEN_ENDPOINT,
            "client_secret": "desktop-test-secret",
            "redirect_uris": redirect_uris or ["http://localhost"],
        }
    }


class GoogleOAuthTests(unittest.TestCase):
    def test_client_file_requires_desktop_and_google_loopback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            valid_path = Path(directory) / "client.json"
            valid_path.write_text(json.dumps(client_document()), encoding="utf-8")
            credentials = OAuthClientCredentials.from_json_file(valid_path)
            self.assertTrue(credentials.client_id.endswith(".apps.googleusercontent.com"))

            invalid_path = Path(directory) / "bad.json"
            invalid_path.write_text(
                json.dumps(client_document(["https://example.invalid/callback"])),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                OAuthClientCredentials.from_json_file(invalid_path)

    def test_authorization_url_has_only_readonly_scope_and_pkce(self) -> None:
        credentials = OAuthClientCredentials(
            "123456-example.apps.googleusercontent.com",
            "desktop-test-secret",
        )
        verifier, challenge = generate_pkce()
        url = build_authorization_url(
            credentials,
            "http://127.0.0.1:49152/oauth2/callback",
            "random-state",
            challenge,
        )
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        self.assertEqual(f"{parsed.scheme}://{parsed.netloc}{parsed.path}", GOOGLE_AUTH_ENDPOINT)
        self.assertEqual(query["scope"], [GMAIL_READONLY_SCOPE])
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.assertEqual(query["access_type"], ["offline"])
        self.assertEqual(query["redirect_uri"], ["http://127.0.0.1:49152/oauth2/callback"])
        self.assertGreaterEqual(len(verifier), 43)
        self.assertNotEqual(verifier, challenge)

    def test_quarantine_authorization_url_has_exact_modify_scope(self) -> None:
        credentials = OAuthClientCredentials(
            "123456-example.apps.googleusercontent.com",
            "desktop-test-secret",
        )
        _, challenge = generate_pkce()
        url = build_authorization_url(
            credentials,
            "http://127.0.0.1:49152/oauth2/callback",
            "random-state",
            challenge,
            GMAIL_MODIFY_SCOPE,
        )
        query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        self.assertEqual(query["scope"], [GMAIL_MODIFY_SCOPE])
        self.assertEqual(query["include_granted_scopes"], ["false"])

    def test_token_transport_rejects_every_other_endpoint(self) -> None:
        for url in (
            "http://oauth2.googleapis.com/token",
            "https://accounts.google.com/o/oauth2/token",
            "https://evil.invalid/token",
            f"{GOOGLE_TOKEN_ENDPOINT}?redirect=evil",
        ):
            with self.subTest(url=url), self.assertRaises(GoogleOAuthError):
                DirectOAuthTokenTransport._validate_url(url)

    def test_authorize_saves_refresh_but_never_access_token(self) -> None:
        store = MemorySecretStore()
        flow = FakeFlow(OAuthTokenResult("access-secret", 3600, "refresh-secret"))
        with tempfile.TemporaryDirectory() as directory:
            client_path = Path(directory) / "client.json"
            client_path.write_text(json.dumps(client_document()), encoding="utf-8")
            authorize_gmail(
                ROOT / "config" / "accounts.example.json",
                "gmail_personale",
                client_path,
                lambda _: None,
                timeout_seconds=120,
                store=store,
                flow=flow,  # type: ignore[arg-type]
            )
        all_stored = "\n".join(store.values.values())
        self.assertNotIn("access-secret", all_stored)
        self.assertIn("refresh-secret", all_stored)
        self.assertEqual(
            set(store.values),
            {
                (OAUTH_CLIENT_KEYCHAIN_SERVICE, "gmail_personale"),
                (REFRESH_TOKEN_KEYCHAIN_SERVICE, "gmail_personale"),
            },
        )

    def test_access_provider_refreshes_once_and_caches_in_memory(self) -> None:
        store = MemorySecretStore()
        credentials = OAuthClientCredentials(
            "123456-example.apps.googleusercontent.com",
            "desktop-test-secret",
        )
        save_authorization(store, "gmail_personale", credentials, "refresh-secret")
        transport = QueueTokenTransport(
            [
                {
                    "access_token": "access-secret",
                    "expires_in": 3600,
                    "scope": GMAIL_READONLY_SCOPE,
                    "token_type": "Bearer",
                }
            ]
        )
        provider = GoogleAccessTokenProvider(
            "gmail_personale",
            store=store,
            transport=transport,
        )
        self.assertEqual(provider.get_access_token(), "access-secret")
        self.assertEqual(provider.get_access_token(), "access-secret")
        self.assertEqual(len(transport.calls), 1)
        url, fields = transport.calls[0]
        self.assertEqual(url, GOOGLE_TOKEN_ENDPOINT)
        self.assertEqual(fields["grant_type"], "refresh_token")
        self.assertEqual(fields["refresh_token"], "refresh-secret")
        self.assertEqual(provider.scopes, frozenset({GMAIL_READONLY_SCOPE}))

    def test_access_provider_rejects_scope_expansion(self) -> None:
        store = MemorySecretStore()
        credentials = OAuthClientCredentials(
            "123456-example.apps.googleusercontent.com",
            "desktop-test-secret",
        )
        save_authorization(store, "gmail_personale", credentials, "refresh-secret")
        transport = QueueTokenTransport(
            [
                {
                    "access_token": "access-secret",
                    "expires_in": 3600,
                    "scope": f"{GMAIL_READONLY_SCOPE} https://mail.google.com/",
                    "token_type": "Bearer",
                }
            ]
        )
        provider = GoogleAccessTokenProvider(
            "gmail_personale",
            store=store,
            transport=transport,
        )
        with self.assertRaises(GoogleOAuthError):
            provider.get_access_token()

    def test_modify_token_is_stored_separately_and_refreshed_exactly(self) -> None:
        store = MemorySecretStore()
        credentials = OAuthClientCredentials(
            "123456-example.apps.googleusercontent.com",
            "desktop-test-secret",
        )
        save_authorization(store, "gmail_personale", credentials, "readonly-refresh")
        flow = FakeFlow(OAuthTokenResult("modify-access", 3600, "modify-refresh"))
        authorize_gmail_quarantine(
            ROOT / "config" / "accounts.example.json",
            "gmail_personale",
            lambda _: None,
            store=store,
            flow=flow,  # type: ignore[arg-type]
        )
        self.assertIn(
            (QUARANTINE_REFRESH_TOKEN_KEYCHAIN_SERVICE, "gmail_personale"),
            store.values,
        )
        self.assertIn("readonly-refresh", store.values[(REFRESH_TOKEN_KEYCHAIN_SERVICE, "gmail_personale")])
        self.assertIn(
            "modify-refresh",
            store.values[(QUARANTINE_REFRESH_TOKEN_KEYCHAIN_SERVICE, "gmail_personale")],
        )

        transport = QueueTokenTransport(
            [
                {
                    "access_token": "modify-access",
                    "expires_in": 3600,
                    "scope": GMAIL_MODIFY_SCOPE,
                    "token_type": "Bearer",
                }
            ]
        )
        provider = GoogleAccessTokenProvider(
            "gmail_personale",
            store=store,
            transport=transport,
            scope=GMAIL_MODIFY_SCOPE,
        )
        self.assertEqual(provider.get_access_token(), "modify-access")
        self.assertEqual(provider.scopes, frozenset({GMAIL_MODIFY_SCOPE}))

    def test_keychain_class_exposes_no_delete_operation(self) -> None:
        public = {name.casefold() for name in dir(MacOSKeychainStore) if not name.startswith("_")}
        self.assertEqual(public, {"get", "set"})


if __name__ == "__main__":
    unittest.main()
