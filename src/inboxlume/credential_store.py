from __future__ import annotations

import platform
from typing import Protocol


class CredentialStoreError(RuntimeError):
    pass


class KeyringAdapter(Protocol):
    def get_password(self, service: str, account: str) -> str | None: ...

    def set_password(self, service: str, account: str, secret: str) -> None: ...

    def delete_password(self, service: str, account: str) -> None: ...


class SystemCredentialStore:
    """Adattatore per Keychain, Credential Locker o Secret Service/KWallet."""

    def __init__(self, adapter: KeyringAdapter | None = None) -> None:
        if adapter is None:
            try:
                import keyring
                from keyring.backends.fail import Keyring as FailingKeyring
            except ModuleNotFoundError as exc:
                raise CredentialStoreError(
                    "il gestore credenziali di sistema richiede il pacchetto keyring"
                ) from exc
            backend = keyring.get_keyring()
            if isinstance(backend, FailingKeyring) or backend.priority <= 0:
                raise CredentialStoreError(
                    "nessun gestore credenziali sicuro disponibile sul sistema"
                )
            backend_module = type(backend).__module__
            allowed_modules = {
                "Darwin": ("keyring.backends.macOS",),
                "Windows": ("keyring.backends.Windows",),
                "Linux": (
                    "keyring.backends.SecretService",
                    "keyring.backends.kwallet",
                    "keyring.backends.libsecret",
                ),
            }.get(platform.system(), ())
            if not any(
                backend_module == prefix or backend_module.startswith(f"{prefix}.")
                for prefix in allowed_modules
            ):
                raise CredentialStoreError(
                    "il backend credenziali non è un gestore nativo cifrato consentito"
                )
            adapter = keyring
        self._adapter = adapter

    @staticmethod
    def _validate_field(value: str, label: str) -> None:
        if not value or len(value) > 512 or "\x00" in value:
            raise ValueError(f"{label} credenziale non valido")

    def get(self, service: str, account: str) -> str | None:
        self._validate_field(service, "service")
        self._validate_field(account, "account")
        try:
            return self._adapter.get_password(service, account)
        except Exception as exc:
            raise CredentialStoreError("lettura credenziali di sistema fallita") from exc

    def set(self, service: str, account: str, secret: str) -> None:
        self._validate_field(service, "service")
        self._validate_field(account, "account")
        if not secret or len(secret.encode("utf-8")) > 64_000:
            raise ValueError("segreto credenziale non valido")
        try:
            self._adapter.set_password(service, account, secret)
        except Exception as exc:
            raise CredentialStoreError("scrittura credenziali di sistema fallita") from exc

    def delete(self, service: str, account: str) -> bool:
        self._validate_field(service, "service")
        self._validate_field(account, "account")
        if self.get(service, account) is None:
            return False
        try:
            self._adapter.delete_password(service, account)
        except Exception as exc:
            raise CredentialStoreError("rimozione credenziali di sistema fallita") from exc
        return True
