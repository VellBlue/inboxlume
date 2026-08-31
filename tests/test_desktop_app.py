from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    from PySide6.QtGui import QCloseEvent
    from PySide6.QtWidgets import QApplication, QMessageBox

    from inboxlume.auth import AccountConnectionStatus, ConnectionState
    from inboxlume.desktop_app import (
        BRAND_MARK_FILE,
        BRAND_MARK_SIZE,
        SettingsWindow,
        _brand_mark_pixmap,
    )
    from inboxlume.duration_estimator import (
        EstimateConfidence,
        ScanDurationEstimate,
    )
    from inboxlume.local_models import LocalModelProfile
    from inboxlume.models import ProviderKind
    from inboxlume.native_scheduler import ScheduleStatus
    from inboxlume.settings import ApplicationSettings, SettingsStore
    from inboxlume.i18n import UiLanguage

    PYSIDE_AVAILABLE = True
except (ModuleNotFoundError, SystemExit):
    PYSIDE_AVAILABLE = False


class FakeCredentialStore:
    def __init__(self) -> None:
        self.values = {}

    def get(self, service, account):  # noqa: ANN001
        return self.values.get((service, account))

    def set(self, service, account, secret):  # noqa: ANN001
        self.values[(service, account)] = secret


class FakeAuthService:
    def __init__(self) -> None:
        self.store = FakeCredentialStore()

    def status(
        self, account_id: str, provider: ProviderKind
    ) -> AccountConnectionStatus:
        return AccountConnectionStatus(
            provider,
            ConnectionState.NOT_CONFIGURED,
            False,
            False,
            "Account di test non collegato",
        )


class FakeScheduleBackend:
    name = "fake"

    def status(self, account_id: str) -> ScheduleStatus:
        return ScheduleStatus("fake", False, "Non installata")

    def install(self, request):  # noqa: ANN001
        return ScheduleStatus("fake", True, "Installata")

    def remove(self, account_id: str) -> ScheduleStatus:
        return ScheduleStatus("fake", False, "Rimossa")


@unittest.skipUnless(PYSIDE_AVAILABLE, "PySide6 non disponibile")
class DesktopAppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        cls.application = QApplication.instance() or QApplication([])

    def test_schedule_card_is_local_one_shot_and_defaults_to_four(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            store = SettingsStore(path)
            store.save(ApplicationSettings.defaults())
            window = SettingsWindow(
                store=store,
                auth_service=FakeAuthService(),  # type: ignore[arg-type]
                schedule_backend=FakeScheduleBackend(),  # type: ignore[arg-type]
            )

            self.assertEqual(window.windowTitle(), "InboxLume — Preferences")
            self.assertTrue(window.english_language_button.isChecked())
            self.assertFalse(window.italian_language_button.isChecked())
            self.assertEqual(window.schedule_time.time().hour(), 4)
            self.assertEqual(window.batch_size.minimum(), 0)
            self.assertEqual(window.batch_size.specialValueText(), "All eligible")
            self.assertIn(
                "available after the account is connected",
                window.governor_status.text(),
            )
            self.assertFalse(window.governor_enforced_checkbox.isEnabled())
            self.assertFalse(window.governor_enforced_checkbox.isChecked())
            self.assertFalse(window.backtest_button.isEnabled())
            self.assertIn("after the account is connected", window.drift_status.text())
            self.assertFalse(window.duration_estimate_button.isEnabled())
            self.assertEqual(window.scan_card.objectName(), "scanCard")
            self.assertEqual(window.scan_button.objectName(), "scanPrimaryButton")
            card_order = [
                window.settings_cards_layout.itemAt(index).widget().objectName()
                for index in range(window.settings_cards_layout.count())
                if window.settings_cards_layout.itemAt(index).widget() is not None
            ]
            self.assertEqual(
                card_order,
                [
                    "scanCard",
                    "optionalModulesCard",
                    "threatCard",
                    "connectionCard",
                    "modelCard",
                    "selectionCard",
                    "executionCard",
                    "destinationCard",
                    "governorCard",
                    "scheduleCard",
                ],
            )
            self.assertIn("Inbox scan", window.scan_button.text())
            self.assertIn("Proof of Obsolescence", window.proof_status.text())
            self.assertIn("Threat Protection", window.threat_status.text())
            self.assertEqual(window.threat_card.objectName(), "threatCard")
            self.assertIn("synthetic", window.threat_backtest_status.text())
            self.assertIn("does not read message bodies", window.duration_estimate_status.text())
            self.assertIn("does not reopen messages", window.backtest_status.text())
            self.assertIn("before enabling", window.backtest_guidance.text())
            self.assertIn("40", window.backtest_guidance.text())
            self.assertIn("not under heavy load", window.schedule_advice.text())
            self.assertIn("releases memory", window.schedule_advice.text())
            self.assertEqual(window.model_profile.count(), 3)
            self.assertEqual(
                window.model_profile.currentData(),
                LocalModelProfile.QWEN8,
            )
            self.assertFalse(window.trash_radio.isEnabled())
            self.assertEqual(
                SettingsWindow._worker_model_arguments(
                    window.settings.account("gmail_personale")
                ),
                ["--backend", "ollama", "--ollama-model", "qwen3-vl:8b"],
            )
            self.assertFalse(window.remove_schedule_button.isEnabled())
            window.close()

    def test_existing_user_can_run_the_natural_italian_interface(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SettingsStore(Path(directory) / "settings.json")
            store.save(ApplicationSettings.defaults().replacing_language(UiLanguage.ITALIAN))
            window = SettingsWindow(
                store=store,
                auth_service=FakeAuthService(),  # type: ignore[arg-type]
                schedule_backend=FakeScheduleBackend(),  # type: ignore[arg-type]
            )
            self.assertEqual(window.windowTitle(), "InboxLume — Preferenze")
            self.assertTrue(window.italian_language_button.isChecked())
            self.assertIn("non è sotto sforzo", window.schedule_advice.text())
            self.assertEqual(window.save_button.text(), "Salva preferenze")
            self.assertIn(
                "Safety Governor operativo",
                window.governor_enforced_checkbox.text(),
            )
            self.assertIn("deriva temporale", window.drift_status.text())
            window.close()

    def test_duration_estimate_control_reports_scope_and_uncertainty(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SettingsStore(Path(directory) / "settings.json")
            store.save(ApplicationSettings.defaults())
            window = SettingsWindow(
                store=store,
                auth_service=FakeAuthService(),  # type: ignore[arg-type]
                schedule_backend=FakeScheduleBackend(),  # type: ignore[arg-type]
            )
            window._connection_read_access = True
            window._refresh_operation_availability()
            self.assertTrue(window.duration_estimate_button.isEnabled())

            window._show_duration_estimate(
                ScanDurationEstimate(
                    eligible_unprocessed=50,
                    planned_messages=50,
                    session_limit_reached=True,
                    estimated_seconds=90,
                    lower_seconds=60,
                    upper_seconds=150,
                    confidence=EstimateConfidence.LOW,
                    timing_sample_count=0,
                    basis="preliminary_reference_benchmark",
                    factors=("gemma26", "gmail"),
                )
            )
            self.assertIn("50 eligible IDs", window.duration_estimate_status.text())
            self.assertIn("more eligible messages may remain", window.duration_estimate_status.text())
            self.assertIn("no body read", window.duration_estimate_status.text())
            window.close()

    def test_worker_receipt_keeps_header_outcome_consistent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SettingsStore(Path(directory) / "settings.json")
            store.save(ApplicationSettings.defaults())
            window = SettingsWindow(
                store=store,
                auth_service=FakeAuthService(),  # type: ignore[arg-type]
                schedule_backend=FakeScheduleBackend(),  # type: ignore[arg-type]
            )
            window._operation = "scan"
            with patch("inboxlume.desktop_app.QMessageBox.critical"):
                window._handle_worker_event(
                    {
                        "type": "error",
                        "message": "The local model runtime did not become ready. Restart InboxLume from its launcher and retry; if the problem persists, rebuild the supported Python environment.",
                        "error_code": "local_model_runtime",
                        "mailbox_outcome": "unchanged",
                        "mailbox_changes_unknown": False,
                    }
                )
            self.assertEqual(window.status_pill.text(), "No email changed")
            self.assertEqual(
                window.status_pill.property("outcomeState"), "safe"
            )
            self.assertIn(
                "no mailbox action started", window.operation_summary.text()
            )

            with patch("inboxlume.desktop_app.QMessageBox.critical"):
                window._handle_worker_event(
                    {
                        "type": "error",
                        "message": "The local operation did not complete. Restart InboxLume from its launcher and retry.",
                        "error_code": "local_runtime",
                        "mailbox_outcome": "unknown",
                        "mailbox_changes_unknown": True,
                    }
                )
            self.assertEqual(window.status_pill.text(), "Outcome to verify")
            self.assertEqual(
                window.status_pill.property("outcomeState"), "warning"
            )
            self.assertIn("requires review", window.operation_summary.text())
            window.close()

    def test_direct_trash_is_independent_but_governed_trash_needs_strict_capability(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SettingsStore(Path(directory) / "settings.json")
            store.save(ApplicationSettings.defaults())
            window = SettingsWindow(
                store=store,
                auth_service=FakeAuthService(),  # type: ignore[arg-type]
                schedule_backend=FakeScheduleBackend(),  # type: ignore[arg-type]
            )

            self.assertFalse(window.trash_radio.isEnabled())
            gemma26 = window.model_profile.findData(LocalModelProfile.GEMMA26)
            window.model_profile.blockSignals(True)
            window.model_profile.setCurrentIndex(gemma26)
            window.model_profile.blockSignals(False)
            window._refresh_destination_capabilities()

            self.assertTrue(window.trash_radio.isEnabled())
            window.trash_radio.setChecked(True)
            self.assertFalse(window.governor_enforced_checkbox.isChecked())

            self.assertTrue(window.trash_radio.isEnabled())
            self.assertFalse(window.governor_enforced_checkbox.isEnabled())
            self.assertIn("not active", window.destination_notice.text())
            window.quarantine_radio.setChecked(True)
            window.dirty = False
            window.close()

    def test_existing_account_display_name_can_be_changed_and_discarded_locally(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SettingsStore(Path(directory) / "settings.json")
            store.save(ApplicationSettings.defaults())
            window = SettingsWindow(
                store=store,
                auth_service=FakeAuthService(),  # type: ignore[arg-type]
                schedule_backend=FakeScheduleBackend(),  # type: ignore[arg-type]
            )

            account_id = window.current_account_id
            self.assertIsNotNone(account_id)
            original = store.load().account(str(account_id))
            window.account_display_name.setText("Archive Gmail")

            self.assertTrue(window.dirty)
            self.assertEqual(window.page_title.text(), "Archive Gmail")
            self.assertTrue(window.save())
            saved = store.load().account(str(account_id))
            self.assertEqual(saved.display_name, "Archive Gmail")
            self.assertFalse(saved.safety_governor_enforced)
            self.assertEqual(saved.provider, original.provider)
            self.assertEqual(saved.schedule, original.schedule)
            self.assertIn("Archive Gmail", window.account_list.currentItem().text())

            window.account_display_name.setText("Temporary name")
            window.discard_changes()
            self.assertEqual(window.account_display_name.text(), "Archive Gmail")
            self.assertEqual(window.page_title.text(), "Archive Gmail")
            self.assertFalse(window.dirty)
            window.close()

    def test_close_prompt_discard_closes_and_cancel_keeps_window_open(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SettingsStore(Path(directory) / "settings.json")
            store.save(ApplicationSettings.defaults())
            window = SettingsWindow(
                store=store,
                auth_service=FakeAuthService(),  # type: ignore[arg-type]
                schedule_backend=FakeScheduleBackend(),  # type: ignore[arg-type]
            )
            window.dirty = True
            discard_event = QCloseEvent()
            with patch(
                "inboxlume.desktop_app.QMessageBox.question",
                return_value=QMessageBox.StandardButton.Discard,
            ):
                window.closeEvent(discard_event)
            self.assertTrue(discard_event.isAccepted())

            window.dirty = True
            cancel_event = QCloseEvent()
            with patch(
                "inboxlume.desktop_app.QMessageBox.question",
                return_value=QMessageBox.StandardButton.Cancel,
            ):
                window.closeEvent(cancel_event)
            self.assertFalse(cancel_event.isAccepted())

            window.dirty = True
            save_event = QCloseEvent()
            with patch(
                "inboxlume.desktop_app.QMessageBox.question",
                return_value=QMessageBox.StandardButton.Save,
            ):
                window.closeEvent(save_event)
            self.assertTrue(save_event.isAccepted())
            self.assertFalse(window.dirty)
            window.dirty = False
            window.close()


@unittest.skipUnless(PYSIDE_AVAILABLE, "PySide6 non disponibile")
class BrandMarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        cls.app = QApplication.instance() or QApplication([])

    def test_the_vector_mark_ships_with_the_package(self) -> None:
        import inboxlume

        asset = Path(inboxlume.__file__).with_name(BRAND_MARK_FILE)
        self.assertTrue(asset.is_file(), asset)

        # Declared package data, or an installed build would open without it.
        pyproject = (
            Path(__file__).resolve().parents[1] / "pyproject.toml"
        ).read_text(encoding="utf-8")
        self.assertIn(BRAND_MARK_FILE, pyproject)

    def test_the_badge_renders_at_the_requested_logical_size(self) -> None:
        pixmap = _brand_mark_pixmap(BRAND_MARK_SIZE)

        assert pixmap is not None
        self.assertFalse(pixmap.isNull())
        ratio = pixmap.devicePixelRatio()
        self.assertEqual(round(pixmap.width() / ratio), BRAND_MARK_SIZE)
        self.assertEqual(round(pixmap.height() / ratio), BRAND_MARK_SIZE)

    def test_a_missing_asset_falls_back_instead_of_an_empty_square(self) -> None:
        with patch("inboxlume.desktop_app.BRAND_MARK_FILE", "assente.svg"):
            self.assertIsNone(_brand_mark_pixmap(BRAND_MARK_SIZE))


if __name__ == "__main__":
    unittest.main()
