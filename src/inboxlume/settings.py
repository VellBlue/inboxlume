from __future__ import annotations

import json
import os
import platform
import re
import tempfile
import uuid
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import Any, Mapping

from .local_models import LocalModelProfile, model_spec
from .i18n import UiLanguage
from .models import ProviderKind
from .threat_signals import ThreatSemanticMode


SETTINGS_VERSION = 9
LEGACY_SETTINGS_VERSIONS = frozenset({1, 2, 3, 4, 5, 6, 7, 8})
RECOMMENDED_INITIAL_QUIZ_ANSWERS = 40
RECOMMENDED_INITIAL_KEEP_ANSWERS = 3
RECOMMENDED_INITIAL_DONT_KEEP_ANSWERS = 20
# The scan worker validates this same bound. Keeping one constant is what
# stops a batch the settings accept from being refused by the worker at the
# first instant of a run, which a scheduled run cannot report to anyone.
MAX_SCAN_BATCH_SIZE = 5000
APPLICATION_NAME = "InboxLume"
APPLICATION_SLUG = "inboxlume"
ENV_SETTINGS_PATH = "INBOXLUME_SETTINGS_PATH"

# Compatibilita con il prototipo locale gia in uso. Questi identificatori non
# vengono rimossi o riscritti automaticamente: nessuna preferenza personale deve
# andare persa durante il rebranding pubblico.
LEGACY_APPLICATION_NAME = "Mail Guardian"
LEGACY_APPLICATION_SLUG = "mail-guardian"
LEGACY_ENV_SETTINGS_PATH = "MAIL_GUARDIAN_SETTINGS_PATH"


class ScanOrder(StrEnum):
    NEWEST_FIRST = "newest_first"
    OLDEST_FIRST = "oldest_first"


class MessageDestination(StrEnum):
    QUARANTINE = "quarantine"
    TRASH = "trash"


class ScheduleFrequency(StrEnum):
    DAILY = "daily"
    WEEKDAYS = "weekdays"
    WEEKLY = "weekly"


@dataclass(frozen=True, slots=True)
class ScheduleSettings:
    enabled: bool = False
    hour: int = 4
    minute: int = 0
    frequency: ScheduleFrequency = ScheduleFrequency.DAILY
    weekday: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValueError("stato pianificazione non valido")
        if not isinstance(self.hour, int) or isinstance(self.hour, bool):
            raise ValueError("ora pianificazione non valida")
        if not isinstance(self.minute, int) or isinstance(self.minute, bool):
            raise ValueError("minuto pianificazione non valido")
        if not isinstance(self.weekday, int) or isinstance(self.weekday, bool):
            raise ValueError("giorno pianificazione non valido")
        if not 0 <= self.hour <= 23 or not 0 <= self.minute <= 59:
            raise ValueError("orario pianificazione non valido")
        if not 1 <= self.weekday <= 7:
            raise ValueError("il giorno settimanale deve essere tra 1 e 7")

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "hour": self.hour,
            "minute": self.minute,
            "frequency": self.frequency.value,
            "weekday": self.weekday,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ScheduleSettings:
        if set(raw) != {"enabled", "hour", "minute", "frequency", "weekday"}:
            raise ValueError("campi pianificazione mancanti o sconosciuti")
        if not isinstance(raw["enabled"], bool) or not isinstance(
            raw["frequency"], str
        ):
            raise ValueError("pianificazione non valida")
        try:
            return cls(
                enabled=raw["enabled"],
                hour=raw["hour"],
                minute=raw["minute"],
                frequency=ScheduleFrequency(raw["frequency"]),
                weekday=raw["weekday"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("pianificazione non valida") from exc


@dataclass(frozen=True, slots=True)
class AccountSettings:
    account_id: str
    provider: ProviderKind
    display_name: str = ""
    unread_age_days: int = 30
    read_one_time_code_age_days: int = 7
    scan_order: ScanOrder = ScanOrder.NEWEST_FIRST
    batch_size: int = 50
    quiz_size: int = 20
    destination: MessageDestination = MessageDestination.QUARANTINE
    model_profile: LocalModelProfile = LocalModelProfile.QWEN8
    safety_governor_enforced: bool = False
    # The expensive secondary analyses remain enabled by default for existing
    # users, but can be disabled independently when a fast ordinary scan is
    # preferred.  They never change the mailbox by themselves.
    threat_protection_enabled: bool = True
    threat_semantic_mode: ThreatSemanticMode = ThreatSemanticMode.TARGETED_SEMANTIC
    lumegraph_enabled: bool = True
    obsolescence_proof_enabled: bool = True
    schedule: ScheduleSettings = field(default_factory=ScheduleSettings)

    def __post_init__(self) -> None:
        if re.fullmatch(r"[A-Za-z0-9_-]{1,128}", self.account_id) is None:
            raise ValueError("account_id impostazioni non valido")
        if len(self.display_name.strip()) > 80:
            raise ValueError("nome account troppo lungo")
        if not isinstance(self.safety_governor_enforced, bool):
            raise ValueError("stato Safety Governor non valido")
        for name in (
            "threat_protection_enabled",
            "lumegraph_enabled",
            "obsolescence_proof_enabled",
        ):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"stato modulo locale non valido: {name}")
        if not isinstance(self.threat_semantic_mode, ThreatSemanticMode):
            raise ValueError("modalità semantica antiphishing non valida")
        if not 1 <= self.unread_age_days <= 3650:
            raise ValueError("i giorni delle email non lette devono essere tra 1 e 3650")
        if not 1 <= self.read_one_time_code_age_days <= 3650:
            raise ValueError("i giorni dei codici monouso devono essere tra 1 e 3650")
        if not 0 <= self.batch_size <= MAX_SCAN_BATCH_SIZE:
            raise ValueError(
                "la dimensione del lotto deve essere 0 (tutte le email idonee) "
                f"oppure tra 1 e {MAX_SCAN_BATCH_SIZE}"
            )
        if not 1 <= self.quiz_size <= 500:
            raise ValueError("la dimensione del quiz deve essere tra 1 e 500")
        if (
            self.destination is MessageDestination.TRASH
            and not model_spec(self.model_profile).direct_trash_allowed
        ):
            raise ValueError(
                "il modello selezionato consente soltanto la Quarantena"
            )
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.account_id,
            "provider": self.provider.value,
            "display_name": self.display_name.strip(),
            "unread_age_days": self.unread_age_days,
            "read_one_time_code_age_days": self.read_one_time_code_age_days,
            "scan_order": self.scan_order.value,
            "batch_size": self.batch_size,
            "quiz_size": self.quiz_size,
            "destination": self.destination.value,
            "model_profile": self.model_profile.value,
            "safety_governor_enforced": self.safety_governor_enforced,
            "threat_protection_enabled": self.threat_protection_enabled,
            "threat_semantic_mode": self.threat_semantic_mode.value,
            "lumegraph_enabled": self.lumegraph_enabled,
            "obsolescence_proof_enabled": self.obsolescence_proof_enabled,
            "schedule": self.schedule.to_dict(),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> AccountSettings:
        # Settings written before the optional-module controls are still valid;
        # preserve their previous behaviour by enabling all three modules.
        raw = dict(raw)
        for field_name in (
            "threat_protection_enabled",
            "lumegraph_enabled",
            "obsolescence_proof_enabled",
        ):
            raw.setdefault(field_name, True)
        raw.setdefault(
            "threat_semantic_mode",
            ThreatSemanticMode.TARGETED_SEMANTIC.value,
        )
        expected = {
            "id",
            "provider",
            "display_name",
            "unread_age_days",
            "read_one_time_code_age_days",
            "scan_order",
            "batch_size",
            "quiz_size",
            "destination",
            "model_profile",
            "safety_governor_enforced",
            "threat_protection_enabled",
            "threat_semantic_mode",
            "lumegraph_enabled",
            "obsolescence_proof_enabled",
            "schedule",
        }
        if set(raw) != expected:
            raise ValueError("campi impostazioni account mancanti o sconosciuti")
        integer_fields = (
            "unread_age_days",
            "read_one_time_code_age_days",
            "batch_size",
            "quiz_size",
        )
        if any(
            not isinstance(raw[field], int) or isinstance(raw[field], bool)
            for field in integer_fields
        ):
            raise ValueError("i valori numerici devono essere interi")
        if (
            not isinstance(raw["id"], str)
            or not isinstance(raw["provider"], str)
            or not isinstance(raw["display_name"], str)
            or not isinstance(raw["safety_governor_enforced"], bool)
        ):
            raise ValueError("identità account non valida")
        if (
            not isinstance(raw["scan_order"], str)
            or not isinstance(raw["destination"], str)
            or not isinstance(raw["model_profile"], str)
            or not isinstance(raw["threat_semantic_mode"], str)
        ):
            raise ValueError("selezioni account non valide")
        if not isinstance(raw["schedule"], dict):
            raise ValueError("pianificazione account non valida")
        try:
            return cls(
                account_id=str(raw["id"]),
                provider=ProviderKind(str(raw["provider"])),
                display_name=str(raw["display_name"]),
                unread_age_days=int(raw["unread_age_days"]),
                read_one_time_code_age_days=int(
                    raw["read_one_time_code_age_days"]
                ),
                scan_order=ScanOrder(str(raw["scan_order"])),
                batch_size=int(raw["batch_size"]),
                quiz_size=int(raw["quiz_size"]),
                destination=MessageDestination(str(raw["destination"])),
                model_profile=LocalModelProfile(str(raw["model_profile"])),
                safety_governor_enforced=raw["safety_governor_enforced"],
                threat_protection_enabled=raw["threat_protection_enabled"],
                threat_semantic_mode=ThreatSemanticMode(
                    raw["threat_semantic_mode"]
                ),
                lumegraph_enabled=raw["lumegraph_enabled"],
                obsolescence_proof_enabled=raw["obsolescence_proof_enabled"],
                schedule=ScheduleSettings.from_dict(raw["schedule"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("impostazioni account non valide") from exc


@dataclass(frozen=True, slots=True)
class ApplicationSettings:
    accounts: tuple[AccountSettings, ...]
    language: UiLanguage = UiLanguage.ENGLISH
    version: int = SETTINGS_VERSION

    def __post_init__(self) -> None:
        if self.version != SETTINGS_VERSION:
            raise ValueError("versione impostazioni non supportata")
        if not self.accounts:
            raise ValueError("deve esistere almeno un account")
        identifiers = [account.account_id for account in self.accounts]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("account duplicato nelle impostazioni")

    @classmethod
    def defaults(cls) -> ApplicationSettings:
        return cls(
            accounts=(
                AccountSettings(
                    "gmail_personale", ProviderKind.GMAIL, "Personal Gmail"
                ),
                AccountSettings(
                    "yahoo_personale", ProviderKind.YAHOO, "Personal Yahoo"
                ),
            ),
            language=UiLanguage.ENGLISH,
        )

    def account(self, account_id: str) -> AccountSettings:
        for account in self.accounts:
            if account.account_id == account_id:
                return account
        raise KeyError(account_id)

    def replacing_account(
        self,
        account_id: str,
        **changes: Any,
    ) -> ApplicationSettings:
        updated: list[AccountSettings] = []
        found = False
        for account in self.accounts:
            if account.account_id == account_id:
                updated.append(replace(account, **changes))
                found = True
            else:
                updated.append(account)
        if not found:
            raise KeyError(account_id)
        return ApplicationSettings(tuple(updated), self.language, self.version)

    def replacing_language(self, language: UiLanguage | str) -> ApplicationSettings:
        return ApplicationSettings(self.accounts, UiLanguage(language), self.version)

    def adding_account(
        self,
        provider: ProviderKind,
        display_name: str,
        *,
        account_id: str | None = None,
        model_profile: LocalModelProfile = LocalModelProfile.QWEN8,
    ) -> ApplicationSettings:
        label = display_name.strip()
        if not label:
            raise ValueError("inserisci un nome per distinguere l'account")
        identifier = account_id or f"{provider.value}_{uuid.uuid4().hex[:12]}"
        if any(account.account_id == identifier for account in self.accounts):
            raise ValueError("identificatore account già presente")
        return ApplicationSettings(
            (
                *self.accounts,
                AccountSettings(
                    identifier,
                    provider,
                    label,
                    model_profile=model_profile,
                ),
            ),
            self.language,
            self.version,
        )

    def removing_account(self, account_id: str) -> ApplicationSettings:
        remaining = tuple(
            account for account in self.accounts if account.account_id != account_id
        )
        if len(remaining) == len(self.accounts):
            raise KeyError(account_id)
        if not remaining:
            raise ValueError("deve rimanere almeno un account")
        return ApplicationSettings(remaining, self.language, self.version)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "language": self.language.value,
            "accounts": [account.to_dict() for account in self.accounts],
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ApplicationSettings:
        if set(raw) not in ({"version", "accounts"}, {"version", "language", "accounts"}):
            raise ValueError("documento impostazioni non valido")
        if (
            not isinstance(raw["version"], int)
            or isinstance(raw["version"], bool)
            or raw["version"]
            not in {*LEGACY_SETTINGS_VERSIONS, SETTINGS_VERSION}
        ):
            raise ValueError("versione impostazioni non supportata")
        accounts = raw["accounts"]
        if not isinstance(accounts, list) or not all(
            isinstance(item, dict) for item in accounts
        ):
            raise ValueError("accounts deve essere una lista di oggetti")
        version = int(raw["version"])
        if version == SETTINGS_VERSION or (
            version >= 6 and isinstance(raw.get("language"), str)
        ):
            if not isinstance(raw.get("language"), str):
                raise ValueError("lingua interfaccia non valida")
            language = UiLanguage(str(raw["language"]))
        else:
            # Existing builds were Italian-only. Preserve that experience while
            # clean installations use the new English-first default.
            language = UiLanguage.ITALIAN
        migrated: list[AccountSettings] = []
        for item in accounts:
            account_raw = dict(item)
            if version == 1:
                provider = ProviderKind(str(account_raw.get("provider", "")))
                provider_name = "Gmail" if provider is ProviderKind.GMAIL else "Yahoo"
                account_raw["display_name"] = f"{provider_name} personale"
            if version in {1, 2}:
                account_raw["schedule"] = ScheduleSettings().to_dict()
            if version in {1, 2, 3, 4}:
                # Tutte le scansioni della GUI precedente usavano Gemma 26B.
                # La migrazione preserva il comportamento invece di cambiare
                # silenziosamente modello a un account già configurato.
                account_raw["model_profile"] = LocalModelProfile.GEMMA26.value
            if version in {1, 2, 3, 4, 5}:
                account_raw["safety_governor_enforced"] = False
            if (
                version == 7
                and str(account_raw.get("destination"))
                == MessageDestination.TRASH.value
            ):
                # La v7 di sviluppo aveva accoppiato per errore Cestino diretto
                # e Governor. Ripristina l'indipendenza voluta dall'utente.
                account_raw["safety_governor_enforced"] = False
            migrated.append(AccountSettings.from_dict(account_raw))
        return cls(tuple(migrated), language, SETTINGS_VERSION)


def scoped_account_replacement(
    draft_settings: ApplicationSettings,
    saved_settings: ApplicationSettings,
    account_id: str,
    **changes: Any,
) -> tuple[ApplicationSettings, ApplicationSettings]:
    """Apply one confirmed account change without persisting unrelated drafts."""

    return (
        draft_settings.replacing_account(account_id, **changes),
        saved_settings.replacing_account(account_id, **changes),
    )


def scoped_account_removal(
    draft_settings: ApplicationSettings,
    saved_settings: ApplicationSettings,
    account_id: str,
) -> tuple[ApplicationSettings, ApplicationSettings]:
    """Remove one account while keeping other unsaved account drafts in memory."""

    return (
        draft_settings.removing_account(account_id),
        saved_settings.removing_account(account_id),
    )


def default_settings_path(
    *,
    system_name: str | None = None,
    environ: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> Path:
    environment = os.environ if environ is None else environ
    explicit = environment.get(ENV_SETTINGS_PATH, "").strip()
    if not explicit:
        explicit = environment.get(LEGACY_ENV_SETTINGS_PATH, "").strip()
    if explicit:
        return Path(explicit).expanduser()

    current_system = system_name or platform.system()
    user_home = home or Path.home()
    if current_system == "Windows":
        root = environment.get("APPDATA", "").strip()
        return Path(root) / APPLICATION_NAME / "settings.json" if root else (
            user_home / "AppData" / "Roaming" / APPLICATION_NAME / "settings.json"
        )
    if current_system == "Darwin":
        return user_home / "Library" / "Application Support" / APPLICATION_NAME / "settings.json"
    root = environment.get("XDG_CONFIG_HOME", "").strip()
    return (Path(root) if root else user_home / ".config") / APPLICATION_SLUG / "settings.json"


def legacy_settings_path(
    *,
    system_name: str | None = None,
    environ: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> Path:
    """Percorso del prototipo precedente, consultato senza cancellarlo."""

    environment = os.environ if environ is None else environ
    current_system = system_name or platform.system()
    user_home = home or Path.home()
    if current_system == "Windows":
        root = environment.get("APPDATA", "").strip()
        return Path(root) / LEGACY_APPLICATION_NAME / "settings.json" if root else (
            user_home
            / "AppData"
            / "Roaming"
            / LEGACY_APPLICATION_NAME
            / "settings.json"
        )
    if current_system == "Darwin":
        return (
            user_home
            / "Library"
            / "Application Support"
            / LEGACY_APPLICATION_NAME
            / "settings.json"
        )
    root = environment.get("XDG_CONFIG_HOME", "").strip()
    return (
        (Path(root) if root else user_home / ".config")
        / LEGACY_APPLICATION_SLUG
        / "settings.json"
    )


class SettingsStore:
    """Archivio JSON atomico per sole preferenze; non accetta credenziali."""

    def __init__(self, path: Path | None = None) -> None:
        if path is not None:
            self.path = path
            return

        primary = default_settings_path()
        explicit = any(
            os.environ.get(name, "").strip()
            for name in (ENV_SETTINGS_PATH, LEGACY_ENV_SETTINGS_PATH)
        )
        legacy = legacy_settings_path()
        self.path = legacy if not explicit and not primary.exists() and legacy.exists() else primary

    def load(self) -> ApplicationSettings:
        if not self.path.exists():
            return ApplicationSettings.defaults()
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("file impostazioni non leggibile") from exc
        if not isinstance(raw, dict):
            raise ValueError("documento impostazioni non valido")
        return ApplicationSettings.from_dict(raw)

    def save(self, settings: ApplicationSettings) -> None:
        payload = json.dumps(
            settings.to_dict(),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ) + "\n"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary.write(payload)
                temporary.flush()
                os.fsync(temporary.fileno())
                temporary_path = Path(temporary.name)
            if os.name == "posix":
                temporary_path.chmod(0o600)
            os.replace(temporary_path, self.path)
            temporary_path = None
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
