from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

from inboxlume.auth import AuthenticationService, ConnectionState
from inboxlume.credential_store import CredentialStoreError, SystemCredentialStore
from inboxlume.models import ProviderKind
from inboxlume.providers.contracts import GMAIL_MODIFY_SCOPE
from inboxlume.providers.google_oauth import (
    OAuthClientCredentials,
    save_authorization,
)
from inboxlume.providers.yahoo import YahooImapCredentials, save_yahoo_credentials


class FakeKeyring:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, account: str) -> str | None:
        return self.values.get((service, account))

    def set_password(self, service: str, account: str, secret: str) -> None:
        self.values[(service, account)] = secret

    def delete_password(self, service: str, account: str) -> None:
        del self.values[(service, account)]


class AuthenticationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = FakeKeyring()
        self.store = SystemCredentialStore(self.adapter)
        self.service = AuthenticationService(Path("config.json"), self.store)
        self.client = OAuthClientCredentials(
            "client.apps.googleusercontent.com",
            "client-secret",
        )

    def test_gmail_status_distinguishes_readonly_and_action_permission(self) -> None:
        initial = self.service.status("gmail_personale", ProviderKind.GMAIL)
        save_authorization(self.store, "gmail_personale", self.client, "read-token")
        readonly = self.service.status("gmail_personale", ProviderKind.GMAIL)
        save_authorization(
            self.store,
            "gmail_personale",
            self.client,
            "modify-token",
            scope=GMAIL_MODIFY_SCOPE,
        )
        ready = self.service.status("gmail_personale", ProviderKind.GMAIL)

        self.assertEqual(initial.state, ConnectionState.NOT_CONFIGURED)
        self.assertEqual(readonly.state, ConnectionState.READ_ONLY)
        self.assertTrue(readonly.read_access)
        self.assertFalse(readonly.action_access)
        self.assertEqual(ready.state, ConnectionState.READY)

    def test_yahoo_status_never_exposes_password(self) -> None:
        password = "abcdefghijklmnop"
        save_yahoo_credentials(
            self.store,
            "yahoo_personale",
            YahooImapCredentials("utente@example.invalid", password),
        )
        status = self.service.status("yahoo_personale", ProviderKind.YAHOO)

        self.assertEqual(status.state, ConnectionState.READY)
        self.assertNotIn(password, repr(status))
        self.assertNotIn("utente@example.invalid", repr(status))

    def test_disconnect_removes_only_selected_provider_credentials(self) -> None:
        save_authorization(self.store, "gmail_personale", self.client, "read-token")
        save_yahoo_credentials(
            self.store,
            "yahoo_personale",
            YahooImapCredentials("utente@example.invalid", "abcdefghijklmnop"),
        )

        removed = self.service.disconnect("gmail_personale", ProviderKind.GMAIL)

        self.assertEqual(removed, 2)
        self.assertEqual(
            self.service.status("gmail_personale", ProviderKind.GMAIL).state,
            ConnectionState.NOT_CONFIGURED,
        )
        self.assertEqual(
            self.service.status("yahoo_personale", ProviderKind.YAHOO).state,
            ConnectionState.READY,
        )

    def test_system_store_delete_is_idempotent(self) -> None:
        self.store.set("service", "account", "secret")
        self.assertTrue(self.store.delete("service", "account"))
        self.assertFalse(self.store.delete("service", "account"))

    def test_auto_store_rejects_positive_priority_plaintext_backend(self) -> None:
        PlaintextBackend = type(
            "PlaintextKeyring",
            (),
            {"__module__": "keyrings.alt.file", "priority": 5},
        )
        fake_keyring = ModuleType("keyring")
        fake_backends = ModuleType("keyring.backends")
        fake_fail = ModuleType("keyring.backends.fail")
        fake_fail.Keyring = type("FailingKeyring", (), {})  # type: ignore[attr-defined]
        fake_keyring.get_keyring = lambda: PlaintextBackend()  # type: ignore[attr-defined]
        fake_keyring.backends = fake_backends  # type: ignore[attr-defined]
        fake_backends.fail = fake_fail  # type: ignore[attr-defined]
        with (
            patch.dict(
                sys.modules,
                {
                    "keyring": fake_keyring,
                    "keyring.backends": fake_backends,
                    "keyring.backends.fail": fake_fail,
                },
            ),
            self.assertRaises(CredentialStoreError),
        ):
            SystemCredentialStore()


if __name__ == "__main__":
    unittest.main()
