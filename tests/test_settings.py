from __future__ import annotations

import json
import os
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from inboxlume.settings import (
    AccountSettings,
    ApplicationSettings,
    MessageDestination,
    ScanOrder,
    ScheduleFrequency,
    ScheduleSettings,
    SettingsStore,
    default_settings_path,
    legacy_settings_path,
    scoped_account_removal,
    scoped_account_replacement,
)
from inboxlume.threat_signals import ThreatSemanticMode
from inboxlume.local_models import LocalModelProfile
from inboxlume.i18n import UiLanguage
from inboxlume.models import ProviderKind


class SettingsTests(unittest.TestCase):
    def test_scoped_account_replacement_does_not_persist_other_drafts(self) -> None:
        saved = ApplicationSettings.defaults()
        drafts = saved.replacing_account(
            "yahoo_personale",
            unread_age_days=17,
        )
        schedule = ScheduleSettings(enabled=True, hour=6, minute=30)

        in_memory, persisted = scoped_account_replacement(
            drafts,
            saved,
            "gmail_personale",
            schedule=schedule,
        )

        self.assertEqual(in_memory.account("yahoo_personale").unread_age_days, 17)
        self.assertEqual(
            persisted.account("yahoo_personale"),
            saved.account("yahoo_personale"),
        )
        self.assertEqual(in_memory.account("gmail_personale").schedule, schedule)
        self.assertEqual(persisted.account("gmail_personale").schedule, schedule)
        self.assertNotEqual(in_memory, persisted)

    def test_scoped_account_removal_keeps_other_drafts_out_of_saved_state(self) -> None:
        saved = ApplicationSettings.defaults()
        drafts = saved.replacing_account(
            "yahoo_personale",
            display_name="Unsaved Yahoo draft",
        )

        in_memory, persisted = scoped_account_removal(
            drafts,
            saved,
            "gmail_personale",
        )

        self.assertEqual(
            in_memory.account("yahoo_personale").display_name,
            "Unsaved Yahoo draft",
        )
        self.assertEqual(
            persisted.account("yahoo_personale").display_name,
            saved.account("yahoo_personale").display_name,
        )
        self.assertNotEqual(in_memory, persisted)

    def test_defaults_keep_gmail_and_yahoo_independent(self) -> None:
        original = ApplicationSettings.defaults()
        updated = original.replacing_account(
            "gmail_personale",
            unread_age_days=14,
            scan_order=ScanOrder.OLDEST_FIRST,
            destination=MessageDestination.TRASH,
            model_profile=LocalModelProfile.GEMMA26,
            safety_governor_enforced=True,
        )

        self.assertEqual(updated.account("gmail_personale").unread_age_days, 14)
        self.assertEqual(
            updated.account("gmail_personale").destination,
            MessageDestination.TRASH,
        )
        self.assertEqual(
            updated.account("yahoo_personale"),
            original.account("yahoo_personale"),
        )

    def test_round_trip_is_atomic_and_contains_no_secret_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            store = SettingsStore(path)
            expected = ApplicationSettings.defaults().replacing_account(
                "yahoo_personale",
                batch_size=125,
                quiz_size=40,
            )
            store.save(expected)
            loaded = store.load()
            raw = path.read_text(encoding="utf-8")

            self.assertEqual(loaded, expected)
            self.assertNotIn("password", raw.casefold())
            self.assertNotIn("token", raw.casefold())
            self.assertEqual(list(path.parent.glob("*.tmp")), [])
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_zero_batch_size_means_all_eligible_messages(self) -> None:
        settings = ApplicationSettings.defaults().replacing_account(
            "gmail_personale",
            batch_size=0,
        )
        self.assertEqual(settings.account("gmail_personale").batch_size, 0)

    def test_rejects_unknown_fields_and_out_of_range_values(self) -> None:
        raw = ApplicationSettings.defaults().to_dict()
        raw["accounts"][0]["unexpected"] = True
        with self.assertRaises(ValueError):
            ApplicationSettings.from_dict(raw)

        with self.assertRaises(ValueError):
            AccountSettings.from_dict(
                {
                    **ApplicationSettings.defaults().accounts[0].to_dict(),
                    "unread_age_days": 0,
                }
            )
        with self.assertRaises(ValueError):
            AccountSettings.from_dict(
                {
                    **ApplicationSettings.defaults().accounts[0].to_dict(),
                    "batch_size": 12.5,
                }
            )

    def test_corrupt_file_fails_closed_instead_of_resetting_preferences(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            path.write_text(json.dumps({"version": 999, "accounts": []}))
            with self.assertRaises(ValueError):
                SettingsStore(path).load()

    def test_default_paths_follow_each_operating_system(self) -> None:
        home = Path("/users/example")
        self.assertEqual(
            default_settings_path(system_name="Darwin", environ={}, home=home),
            home / "Library" / "Application Support" / "InboxLume" / "settings.json",
        )
        self.assertEqual(
            default_settings_path(
                system_name="Windows",
                environ={"APPDATA": "C:/Users/example/AppData/Roaming"},
                home=home,
            ),
            Path("C:/Users/example/AppData/Roaming/InboxLume/settings.json"),
        )
        self.assertEqual(
            default_settings_path(
                system_name="Linux",
                environ={"XDG_CONFIG_HOME": "/users/example/.config"},
                home=home,
            ),
            Path("/users/example/.config/inboxlume/settings.json"),
        )

    def test_existing_legacy_settings_are_reused_without_copy_or_deletion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            primary = root / "InboxLume" / "settings.json"
            legacy = root / "Mail Guardian" / "settings.json"
            legacy.parent.mkdir(parents=True)
            legacy.write_text(
                json.dumps(ApplicationSettings.defaults().to_dict()),
                encoding="utf-8",
            )

            with (
                patch("inboxlume.settings.default_settings_path", return_value=primary),
                patch("inboxlume.settings.legacy_settings_path", return_value=legacy),
                patch.dict(os.environ, {}, clear=True),
            ):
                store = SettingsStore()

            self.assertEqual(store.path, legacy)
            self.assertEqual(store.load(), ApplicationSettings.defaults())
            self.assertFalse(primary.exists())

    def test_legacy_paths_remain_documented_for_existing_installations(self) -> None:
        home = Path("/users/example")
        self.assertEqual(
            legacy_settings_path(system_name="Darwin", environ={}, home=home),
            home / "Library" / "Application Support" / "Mail Guardian" / "settings.json",
        )
        self.assertEqual(
            legacy_settings_path(
                system_name="Linux",
                environ={"XDG_CONFIG_HOME": "/users/example/.config"},
                home=home,
            ),
            Path("/users/example/.config/mail-guardian/settings.json"),
        )

    def test_multiple_accounts_of_the_same_provider_remain_independent(self) -> None:
        settings = ApplicationSettings.defaults().adding_account(
            ProviderKind.GMAIL,
            "Gmail lavoro",
            account_id="gmail_lavoro",
        )
        updated = settings.replacing_account("gmail_lavoro", unread_age_days=9)

        self.assertEqual(len(updated.accounts), 3)
        self.assertEqual(updated.account("gmail_lavoro").unread_age_days, 9)
        self.assertEqual(updated.account("gmail_personale").unread_age_days, 30)
        self.assertEqual(
            updated.removing_account("gmail_lavoro"),
            ApplicationSettings.defaults(),
        )

    def test_version_one_preferences_are_migrated_without_losing_rules(self) -> None:
        current = ApplicationSettings.defaults().to_dict()
        legacy = deepcopy(current)
        legacy["version"] = 1
        for account in legacy["accounts"]:
            account.pop("display_name")
            account.pop("schedule")
        legacy["accounts"][0]["batch_size"] = 125

        migrated = ApplicationSettings.from_dict(legacy)

        self.assertEqual(migrated.version, 9)
        self.assertEqual(migrated.language, UiLanguage.ITALIAN)
        self.assertEqual(migrated.account("gmail_personale").batch_size, 125)
        self.assertEqual(
            migrated.account("gmail_personale").display_name,
            "Gmail personale",
        )
        self.assertFalse(migrated.account("gmail_personale").schedule.enabled)
        self.assertEqual(
            migrated.account("gmail_personale").model_profile,
            LocalModelProfile.GEMMA26,
        )

    def test_version_two_preferences_gain_a_disabled_schedule(self) -> None:
        legacy = ApplicationSettings.defaults().to_dict()
        legacy["version"] = 2
        for account in legacy["accounts"]:
            account.pop("schedule")

        migrated = ApplicationSettings.from_dict(legacy)

        self.assertEqual(migrated.version, 9)
        self.assertEqual(migrated.language, UiLanguage.ITALIAN)
        self.assertEqual(
            migrated.account("yahoo_personale").schedule,
            ScheduleSettings(),
        )

    def test_version_three_preferences_preserve_schedule_and_gain_gemma26(self) -> None:
        legacy = ApplicationSettings.defaults().to_dict()
        legacy["version"] = 3
        for account in legacy["accounts"]:
            account.pop("model_profile")
        legacy["accounts"][0]["schedule"] = ScheduleSettings(
            enabled=True,
            hour=3,
        ).to_dict()

        migrated = ApplicationSettings.from_dict(legacy)

        self.assertTrue(migrated.account("gmail_personale").schedule.enabled)
        self.assertEqual(
            migrated.account("gmail_personale").model_profile,
            LocalModelProfile.GEMMA26,
        )

    def test_clean_install_is_english_first_and_language_round_trips(self) -> None:
        defaults = ApplicationSettings.defaults()
        self.assertEqual(defaults.language, UiLanguage.ENGLISH)
        self.assertEqual(defaults.account("gmail_personale").display_name, "Personal Gmail")

        italian = defaults.replacing_language(UiLanguage.ITALIAN)
        self.assertEqual(
            ApplicationSettings.from_dict(italian.to_dict()).language,
            UiLanguage.ITALIAN,
        )

    def test_version_four_italian_only_settings_keep_italian_on_migration(self) -> None:
        legacy = ApplicationSettings.defaults().to_dict()
        legacy["version"] = 4
        legacy.pop("language")

        migrated = ApplicationSettings.from_dict(legacy)

        self.assertEqual(migrated.version, 9)
        self.assertEqual(migrated.language, UiLanguage.ITALIAN)

    def test_version_five_preserves_model_and_gains_disabled_operational_governor(self) -> None:
        legacy = ApplicationSettings.defaults().replacing_account(
            "gmail_personale",
            model_profile=LocalModelProfile.QWEN8,
        ).to_dict()
        legacy["version"] = 5
        for account in legacy["accounts"]:
            account.pop("safety_governor_enforced")

        migrated = ApplicationSettings.from_dict(legacy)

        gmail = migrated.account("gmail_personale")
        self.assertEqual(migrated.version, 9)
        self.assertEqual(gmail.model_profile, LocalModelProfile.QWEN8)
        self.assertFalse(gmail.safety_governor_enforced)

    def test_version_six_direct_trash_remains_independent_from_governor(self) -> None:
        legacy = ApplicationSettings.defaults().to_dict()
        legacy["version"] = 6
        account = legacy["accounts"][0]
        account["model_profile"] = LocalModelProfile.GEMMA26.value
        account["destination"] = MessageDestination.TRASH.value
        account["safety_governor_enforced"] = False

        migrated = ApplicationSettings.from_dict(legacy)

        gmail = migrated.account("gmail_personale")
        self.assertEqual(migrated.version, 9)
        self.assertEqual(gmail.destination, MessageDestination.TRASH)
        self.assertFalse(gmail.safety_governor_enforced)

    def test_version_seven_accidental_trash_governor_coupling_is_repaired(self) -> None:
        legacy = ApplicationSettings.defaults().to_dict()
        legacy["version"] = 7
        legacy["language"] = UiLanguage.ENGLISH.value
        account = legacy["accounts"][0]
        account["model_profile"] = LocalModelProfile.GEMMA26.value
        account["destination"] = MessageDestination.TRASH.value
        account["safety_governor_enforced"] = True

        migrated = ApplicationSettings.from_dict(legacy)

        gmail = migrated.account("gmail_personale")
        self.assertEqual(migrated.version, 9)
        self.assertEqual(migrated.language, UiLanguage.ENGLISH)
        self.assertEqual(gmail.destination, MessageDestination.TRASH)
        self.assertFalse(gmail.safety_governor_enforced)

    def test_version_eight_defaults_to_targeted_threat_screening(self) -> None:
        legacy = ApplicationSettings.defaults().to_dict()
        legacy["version"] = 8
        for account in legacy["accounts"]:
            account.pop("threat_semantic_mode")

        migrated = ApplicationSettings.from_dict(legacy)

        self.assertEqual(migrated.version, 9)
        self.assertEqual(
            migrated.account("gmail_personale").threat_semantic_mode,
            ThreatSemanticMode.TARGETED_SEMANTIC,
        )

    def test_model_profile_is_validated_and_round_trips_per_account(self) -> None:
        settings = ApplicationSettings.defaults().replacing_account(
            "gmail_personale",
            model_profile=LocalModelProfile.GEMMA12,
        )

        decoded = ApplicationSettings.from_dict(settings.to_dict())

        self.assertEqual(
            decoded.account("gmail_personale").model_profile,
            LocalModelProfile.GEMMA12,
        )
        raw = settings.to_dict()
        raw["accounts"][0]["model_profile"] = "modello-non-consentito"
        with self.assertRaises(ValueError):
            ApplicationSettings.from_dict(raw)
        with self.assertRaisesRegex(ValueError, "soltanto la Quarantena"):
            AccountSettings(
                "qwen_trash",
                ProviderKind.GMAIL,
                destination=MessageDestination.TRASH,
                model_profile=LocalModelProfile.QWEN8,
                safety_governor_enforced=True,
            )

    def test_operational_governor_and_direct_trash_are_independent_and_round_trip(self) -> None:
        settings = ApplicationSettings.defaults().replacing_account(
            "gmail_personale",
            safety_governor_enforced=True,
        )
        decoded = ApplicationSettings.from_dict(settings.to_dict())
        self.assertTrue(
            decoded.account("gmail_personale").safety_governor_enforced
        )
        direct = AccountSettings(
            "direct_trash",
            ProviderKind.GMAIL,
            destination=MessageDestination.TRASH,
            model_profile=LocalModelProfile.GEMMA26,
            safety_governor_enforced=False,
        )
        self.assertEqual(direct.destination, MessageDestination.TRASH)
        self.assertFalse(direct.safety_governor_enforced)

    def test_schedule_is_validated_and_round_trips_per_account(self) -> None:
        schedule = ScheduleSettings(
            enabled=True,
            hour=3,
            minute=30,
            frequency=ScheduleFrequency.WEEKLY,
            weekday=7,
        )
        settings = ApplicationSettings.defaults().replacing_account(
            "gmail_personale", schedule=schedule
        )

        decoded = ApplicationSettings.from_dict(settings.to_dict())

        self.assertEqual(decoded.account("gmail_personale").schedule, schedule)
        self.assertFalse(decoded.account("yahoo_personale").schedule.enabled)
        with self.assertRaises(ValueError):
            ScheduleSettings(hour=24)


class ThreatSemanticModeSettingsTests(unittest.TestCase):
    def test_the_confirmed_mode_survives_a_save_and_reload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            account = AccountSettings(
                "yahoo_test",
                ProviderKind.YAHOO,
                threat_semantic_mode=ThreatSemanticMode.CONFIRMED_SEMANTIC,
            )
            SettingsStore(path).save(ApplicationSettings((account,)))
            reloaded = SettingsStore(path).load().account("yahoo_test")

        self.assertIs(
            reloaded.threat_semantic_mode,
            ThreatSemanticMode.CONFIRMED_SEMANTIC,
        )


if __name__ == "__main__":
    unittest.main()
