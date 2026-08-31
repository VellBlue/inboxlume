#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUTS = {
    "en": ROOT / "docs" / "assets" / "inboxlume-settings.png",
    "it": ROOT / "docs" / "assets" / "inboxlume-settings-it.png",
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a public screenshot using synthetic data only.",
    )
    parser.add_argument("--language", choices=("en", "it"), default="en")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from PySide6.QtWidgets import QApplication

    from inboxlume.auth import AccountConnectionStatus, ConnectionState
    from inboxlume.desktop_app import SettingsWindow
    from inboxlume.local_models import (
        HardwareProfile,
        LocalModelProfile,
        ModelAvailability,
    )
    from inboxlume.models import ProviderKind
    from inboxlume.native_scheduler import ScheduleStatus
    from inboxlume.settings import ApplicationSettings, SettingsStore
    from inboxlume.i18n import UiLanguage

    class SyntheticSecretStore:
        def __init__(self) -> None:
            self.values: dict[tuple[str, str], str] = {}

        def get(self, service: str, account: str) -> str | None:
            return self.values.get((service, account))

        def set(self, service: str, account: str, secret: str) -> None:
            self.values[(service, account)] = secret

    class SyntheticAuthService:
        store = SyntheticSecretStore()

        def status(
            self,
            account_id: str,  # noqa: ARG002
            provider: ProviderKind,
        ) -> AccountConnectionStatus:
            return AccountConnectionStatus(
                provider,
                ConnectionState.NOT_CONFIGURED,
                False,
                False,
                (
                    "Account dimostrativo non collegato · nessun accesso alla casella"
                    if args.language == "it"
                    else "Synthetic account not connected · no mailbox access"
                ),
            )

    class SyntheticScheduleBackend:
        name = "demo"

        def status(self, account_id: str) -> ScheduleStatus:  # noqa: ARG002
            if args.language == "it":
                return ScheduleStatus("servizio nativo", False, "Non installata")
            return ScheduleStatus("native service", False, "Not installed")

    hardware = HardwareProfile(
        "macOS · Windows · Linux",
        "rilevamento locale" if args.language == "it" else "local detection",
        24.0,
    )
    availability = {
        profile: ModelAvailability(
            profile,
            True,
            (
                "Profilo locale rilevato; nessun modello caricato"
                if args.language == "it"
                else "Local profile detected; no model loaded"
            ),
        )
        for profile in LocalModelProfile
    }

    app = QApplication.instance() or QApplication([])
    with tempfile.TemporaryDirectory() as directory:
        store = SettingsStore(Path(directory) / "settings.json")
        settings = ApplicationSettings.defaults().replacing_language(
            UiLanguage(args.language)
        )
        for account in settings.accounts:
            provider_name = (
                ("Gmail demo" if args.language == "it" else "Demo Gmail")
                if account.provider is ProviderKind.GMAIL
                else ("Yahoo demo" if args.language == "it" else "Demo Yahoo")
            )
            settings = settings.replacing_account(
                account.account_id,
                display_name=provider_name,
                model_profile=LocalModelProfile.GEMMA26,
            )
        store.save(settings)
        with (
            patch("inboxlume.desktop_app.detect_hardware", return_value=hardware),
            patch(
                "inboxlume.desktop_app.inspect_model_availability",
                return_value=availability,
            ),
            patch(
                "inboxlume.desktop_app.recommended_available_profile",
                return_value=LocalModelProfile.GEMMA26,
            ),
        ):
            window = SettingsWindow(
                store=store,
                auth_service=SyntheticAuthService(),  # type: ignore[arg-type]
                schedule_backend=SyntheticScheduleBackend(),  # type: ignore[arg-type]
            )
            window.resize(1280, 900)
            window.show()
            app.processEvents()
            output = (args.output or DEFAULT_OUTPUTS[args.language]).resolve()
            output.parent.mkdir(parents=True, exist_ok=True)
            if not window.grab().save(str(output), "PNG"):
                raise RuntimeError("public screenshot could not be saved")
            window.close()
    print(f"Synthetic screenshot created: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
