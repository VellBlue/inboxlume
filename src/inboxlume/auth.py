from __future__ import annotations

import webbrowser
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Callable

from .cli import (
    authorize_gmail,
    authorize_gmail_quarantine,
    authorize_yahoo,
    probe_gmail,
    yahoo_probe,
)
from .credential_store import SystemCredentialStore
from .models import ProviderKind
from .providers.contracts import GMAIL_MODIFY_SCOPE, GMAIL_READONLY_SCOPE
from .providers.google_oauth import (
    OAUTH_CLIENT_KEYCHAIN_SERVICE,
    QUARANTINE_REFRESH_TOKEN_KEYCHAIN_SERVICE,
    REFRESH_TOKEN_KEYCHAIN_SERVICE,
    KeychainError,
    SecretStore,
    load_authorization,
)
from .providers.yahoo import (
    YAHOO_CREDENTIALS_KEYCHAIN_SERVICE,
    YahooImapError,
    load_yahoo_credentials,
)
from .runtime import runtime_policy


class ConnectionState(StrEnum):
    NOT_CONFIGURED = "not_configured"
    READ_ONLY = "read_only"
    READY = "ready"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class AccountConnectionStatus:
    provider: ProviderKind
    state: ConnectionState
    read_access: bool
    action_access: bool
    detail: str


class AuthenticationService:
    def __init__(
        self,
        config_path: Path,
        store: SecretStore | None = None,
    ) -> None:
        self.config_path = config_path
        self.store = store or SystemCredentialStore()

    def status(self, account_id: str, provider: ProviderKind) -> AccountConnectionStatus:
        if provider is ProviderKind.GMAIL:
            return self._gmail_status(account_id)
        if provider is ProviderKind.YAHOO:
            return self._yahoo_status(account_id)
        raise ValueError("unsupported authentication provider")

    def _gmail_status(self, account_id: str) -> AccountConnectionStatus:
        try:
            load_authorization(self.store, account_id, GMAIL_READONLY_SCOPE)
            read_access = True
        except KeychainError as exc:
            if "non ancora autorizzato" not in str(exc):
                return AccountConnectionStatus(
                    ProviderKind.GMAIL,
                    ConnectionState.ERROR,
                    False,
                    False,
                    "Invalid local Gmail credentials",
                )
            read_access = False
        if not read_access:
            return AccountConnectionStatus(
                ProviderKind.GMAIL,
                ConnectionState.NOT_CONFIGURED,
                False,
                False,
                "Connect Gmail to allow read-only Inbox access",
            )
        try:
            load_authorization(self.store, account_id, GMAIL_MODIFY_SCOPE)
            action_access = True
        except KeychainError:
            action_access = False
        return AccountConnectionStatus(
            ProviderKind.GMAIL,
            ConnectionState.READY if action_access else ConnectionState.READ_ONLY,
            True,
            action_access,
            (
                "Inbox read access and protected actions are authorised"
                if action_access
                else "Inbox read access is authorised; Quarantine/Trash is not authorised yet"
            ),
        )

    def _yahoo_status(self, account_id: str) -> AccountConnectionStatus:
        try:
            load_yahoo_credentials(self.store, account_id)
        except YahooImapError as exc:
            if "non ancora configurato" not in str(exc):
                return AccountConnectionStatus(
                    ProviderKind.YAHOO,
                    ConnectionState.ERROR,
                    False,
                    False,
                    "Invalid local Yahoo credentials",
                )
            return AccountConnectionStatus(
                ProviderKind.YAHOO,
                ConnectionState.NOT_CONFIGURED,
                False,
                False,
                "Enter a Yahoo app password",
            )
        return AccountConnectionStatus(
            ProviderKind.YAHOO,
            ConnectionState.READY,
            True,
            True,
            "Yahoo credentials are present in the system credential manager",
        )

    @staticmethod
    def open_browser(url: str) -> None:
        if not webbrowser.open(url, new=1, autoraise=True):
            raise RuntimeError("could not open the default browser")

    def connect_gmail_readonly(
        self,
        account_id: str,
        client_json: Path,
        open_url: Callable[[str], None] | None = None,
    ) -> None:
        authorize_gmail(
            self.config_path,
            account_id,
            client_json,
            open_url or self.open_browser,
            store=self.store,
            policy_override=runtime_policy(
                self.config_path, account_id, ProviderKind.GMAIL
            ),
        )

    def connect_gmail_actions(
        self,
        account_id: str,
        open_url: Callable[[str], None] | None = None,
    ) -> None:
        authorize_gmail_quarantine(
            self.config_path,
            account_id,
            open_url or self.open_browser,
            store=self.store,
            policy_override=runtime_policy(
                self.config_path, account_id, ProviderKind.GMAIL
            ),
        )

    def connect_yahoo(
        self,
        account_id: str,
        email_address: str,
        app_password: str,
    ) -> None:
        authorize_yahoo(
            self.config_path,
            account_id,
            email_address,
            app_password,
            store=self.store,
            policy_override=runtime_policy(
                self.config_path, account_id, ProviderKind.YAHOO
            ),
        )

    def test_connection(self, account_id: str, provider: ProviderKind) -> str:
        if provider is ProviderKind.GMAIL:
            has_message = probe_gmail(
                self.config_path,
                account_id,
                self.store,
                policy_override=runtime_policy(
                    self.config_path, account_id, ProviderKind.GMAIL
                ),
            )
            return "Gmail Inbox is accessible" + (
                " and is not empty" if has_message else " and is empty"
            )
        summary = yahoo_probe(
            self.config_path,
            account_id,
            self.store,
            policy_override=runtime_policy(
                self.config_path, account_id, ProviderKind.YAHOO
            ),
        )
        return f"Yahoo Inbox is accessible · {summary['inbox_count']} messages"

    def disconnect(self, account_id: str, provider: ProviderKind) -> int:
        delete = getattr(self.store, "delete", None)
        if not callable(delete):
            raise RuntimeError("questo archivio credenziali non supporta la disconnessione")
        services = (
            (
                OAUTH_CLIENT_KEYCHAIN_SERVICE,
                REFRESH_TOKEN_KEYCHAIN_SERVICE,
                QUARANTINE_REFRESH_TOKEN_KEYCHAIN_SERVICE,
            )
            if provider is ProviderKind.GMAIL
            else (YAHOO_CREDENTIALS_KEYCHAIN_SERVICE,)
        )
        return sum(bool(delete(service, account_id)) for service in services)
