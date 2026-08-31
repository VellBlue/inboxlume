from __future__ import annotations

import json
import hashlib
import math
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from .models import EmailCategory, ProviderKind


SAFETY_POLICY_ENGINE_VERSION = "safety-policy-v3"


def _is_finite_number(value: object) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(float(value))
    )


def _strict_int(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} deve essere un numero intero")
    return value


def _strict_float(value: object, field_name: str) -> float:
    if not _is_finite_number(value):
        raise ValueError(f"{field_name} deve essere un numero finito")
    return float(value)


def _strict_bool(value: object, field_name: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{field_name} deve essere booleano")
    return value


class OperatingMode(StrEnum):
    SHADOW = "shadow"


DEFAULT_PROTECTED_CATEGORIES = frozenset(
    {
        EmailCategory.BANKING,
        EmailCategory.IMPORTANT,
        EmailCategory.MEDICAL_LEGAL,
        EmailCategory.ONE_TIME_CODE,
        EmailCategory.SCHOOL,
        EmailCategory.SECURITY,
        EmailCategory.TRANSACTIONAL,
    }
)


@dataclass(frozen=True, slots=True)
class LearningPolicy:
    enabled: bool = False
    minimum_observations: int = 5
    protect_score: float = 0.72
    keep_similarity_threshold: float = 0.72
    discard_similarity_threshold: float = 0.82
    similarity_conflict_margin: float = 0.12

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool:
            raise ValueError("learning.enabled deve essere booleano")
        if (
            isinstance(self.minimum_observations, bool)
            or not isinstance(self.minimum_observations, int)
            or self.minimum_observations < 1
        ):
            raise ValueError("minimum_observations deve essere almeno 1")
        if not _is_finite_number(self.protect_score) or not 0.5 <= float(
            self.protect_score
        ) <= 1.0:
            raise ValueError("protect_score deve essere tra 0.5 e 1")
        if not _is_finite_number(
            self.keep_similarity_threshold
        ) or not 0.5 <= float(self.keep_similarity_threshold) <= 1.0:
            raise ValueError("keep_similarity_threshold deve essere tra 0.5 e 1")
        if not _is_finite_number(
            self.discard_similarity_threshold
        ) or not 0.5 <= float(self.discard_similarity_threshold) <= 1.0:
            raise ValueError("discard_similarity_threshold deve essere tra 0.5 e 1")
        if not _is_finite_number(
            self.similarity_conflict_margin
        ) or not 0.0 <= float(self.similarity_conflict_margin) <= 0.5:
            raise ValueError("similarity_conflict_margin deve essere tra 0 e 0.5")


@dataclass(frozen=True, slots=True)
class AccountPolicy:
    account_id: str
    provider: ProviderKind
    unread_age_days: int
    read_one_time_code_age_days: int = 7
    read_routine_access_alert_age_days: int = 90
    mode: OperatingMode = OperatingMode.SHADOW
    review_confidence: float = 0.70
    quarantine_confidence: float = 0.93
    max_candidates_per_run: int = 100
    protect_attachments: bool = True
    protected_categories: frozenset[EmailCategory] = DEFAULT_PROTECTED_CATEGORIES
    protected_senders: frozenset[str] = field(default_factory=frozenset)
    protected_domains: frozenset[str] = field(default_factory=frozenset)
    protected_keywords: frozenset[str] = field(default_factory=frozenset)
    learning: LearningPolicy = field(default_factory=LearningPolicy)

    def __post_init__(self) -> None:
        if not isinstance(self.account_id, str) or not self.account_id.strip():
            raise ValueError("account_id non può essere vuoto")
        if not isinstance(self.provider, ProviderKind):
            raise ValueError("provider non valido")
        if (
            isinstance(self.unread_age_days, bool)
            or not isinstance(self.unread_age_days, int)
            or not 1 <= self.unread_age_days <= 3650
        ):
            raise ValueError("unread_age_days deve essere tra 1 e 3650")
        if (
            isinstance(self.read_one_time_code_age_days, bool)
            or not isinstance(self.read_one_time_code_age_days, int)
            or not 1 <= self.read_one_time_code_age_days <= 3650
        ):
            raise ValueError(
                "read_one_time_code_age_days deve essere tra 1 e 3650"
            )
        if (
            isinstance(self.read_routine_access_alert_age_days, bool)
            or not isinstance(self.read_routine_access_alert_age_days, int)
            or not 1 <= self.read_routine_access_alert_age_days <= 3650
        ):
            raise ValueError(
                "read_routine_access_alert_age_days deve essere tra 1 e 3650"
            )
        if (
            not _is_finite_number(self.review_confidence)
            or not _is_finite_number(self.quarantine_confidence)
            or not 0.0
            <= float(self.review_confidence)
            <= float(self.quarantine_confidence)
            <= 1.0
        ):
            raise ValueError("soglie di confidenza non valide")
        if (
            isinstance(self.max_candidates_per_run, bool)
            or not isinstance(self.max_candidates_per_run, int)
            or not 1 <= self.max_candidates_per_run <= 1000
        ):
            raise ValueError("max_candidates_per_run deve essere tra 1 e 1000")
        if type(self.protect_attachments) is not bool:
            raise ValueError("protect_attachments deve essere booleano")
        if self.mode is not OperatingMode.SHADOW:
            raise ValueError("questa versione supporta esclusivamente mode=shadow")


def policy_safety_fingerprint(policy: AccountPolicy) -> str:
    """Fingerprint every setting that can change a mailbox decision."""

    payload = {
        "policy_engine": SAFETY_POLICY_ENGINE_VERSION,
        "account_id": policy.account_id,
        "provider": policy.provider.value,
        "unread_age_days": policy.unread_age_days,
        "read_one_time_code_age_days": policy.read_one_time_code_age_days,
        "read_routine_access_alert_age_days": policy.read_routine_access_alert_age_days,
        "mode": policy.mode.value,
        "review_confidence": policy.review_confidence,
        "quarantine_confidence": policy.quarantine_confidence,
        "protect_attachments": policy.protect_attachments,
        "protected_categories": sorted(item.value for item in policy.protected_categories),
        "protected_senders": sorted(policy.protected_senders),
        "protected_domains": sorted(policy.protected_domains),
        "protected_keywords": sorted(policy.protected_keywords),
        "learning": {
            "enabled": policy.learning.enabled,
            "minimum_observations": policy.learning.minimum_observations,
            "protect_score": policy.learning.protect_score,
            "keep_similarity_threshold": policy.learning.keep_similarity_threshold,
            "discard_similarity_threshold": policy.learning.discard_similarity_threshold,
            "similarity_conflict_margin": policy.learning.similarity_conflict_margin,
        },
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _string_set(value: Any, field_name: str) -> frozenset[str]:
    if value is None:
        return frozenset()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{field_name} deve essere una lista di stringhe")
    return frozenset(item.strip().casefold() for item in value if item.strip())


def account_policy_from_dict(raw: dict[str, Any]) -> AccountPolicy:
    protected = raw.get("protected", {})
    learning_raw = raw.get("learning", {})
    if not isinstance(protected, dict):
        raise ValueError("protected deve essere un oggetto")
    if not isinstance(learning_raw, dict):
        raise ValueError("learning deve essere un oggetto")
    account_id = raw.get("id")
    provider = raw.get("provider")
    mode = raw.get("mode", "shadow")
    if not isinstance(account_id, str):
        raise ValueError("id deve essere una stringa")
    if not isinstance(provider, str):
        raise ValueError("provider deve essere una stringa")
    if not isinstance(mode, str):
        raise ValueError("mode deve essere una stringa")
    categories_raw = protected.get(
        "categories", [category.value for category in DEFAULT_PROTECTED_CATEGORIES]
    )
    if not isinstance(categories_raw, list) or not all(
        isinstance(item, str) for item in categories_raw
    ):
        raise ValueError("protected.categories deve essere una lista di stringhe")

    return AccountPolicy(
        account_id=account_id,
        provider=ProviderKind(provider),
        unread_age_days=_strict_int(raw.get("unread_age_days"), "unread_age_days"),
        read_one_time_code_age_days=_strict_int(
            raw.get("read_one_time_code_age_days", 7),
            "read_one_time_code_age_days",
        ),
        read_routine_access_alert_age_days=_strict_int(
            raw.get("read_routine_access_alert_age_days", 90),
            "read_routine_access_alert_age_days",
        ),
        mode=OperatingMode(mode),
        review_confidence=_strict_float(
            raw.get("review_confidence", 0.70), "review_confidence"
        ),
        quarantine_confidence=_strict_float(
            raw.get("quarantine_confidence", 0.93), "quarantine_confidence"
        ),
        max_candidates_per_run=_strict_int(
            raw.get("max_candidates_per_run", 100), "max_candidates_per_run"
        ),
        protect_attachments=_strict_bool(
            raw.get("protect_attachments", True), "protect_attachments"
        ),
        protected_categories=frozenset(EmailCategory(item) for item in categories_raw),
        protected_senders=_string_set(protected.get("senders"), "protected.senders"),
        protected_domains=_string_set(protected.get("domains"), "protected.domains"),
        protected_keywords=_string_set(protected.get("keywords"), "protected.keywords"),
        learning=LearningPolicy(
            enabled=_strict_bool(
                learning_raw.get("enabled", False),
                "learning.enabled",
            ),
            minimum_observations=_strict_int(
                learning_raw.get("minimum_observations", 5),
                "learning.minimum_observations",
            ),
            protect_score=_strict_float(
                learning_raw.get("protect_score", 0.72), "learning.protect_score"
            ),
            keep_similarity_threshold=_strict_float(
                learning_raw.get("keep_similarity_threshold", 0.72),
                "learning.keep_similarity_threshold",
            ),
            discard_similarity_threshold=_strict_float(
                learning_raw.get("discard_similarity_threshold", 0.82),
                "learning.discard_similarity_threshold",
            ),
            similarity_conflict_margin=_strict_float(
                learning_raw.get("similarity_conflict_margin", 0.12),
                "learning.similarity_conflict_margin",
            ),
        ),
    )


def load_policies(path: str | Path) -> dict[str, AccountPolicy]:
    with Path(path).open("r", encoding="utf-8") as handle:
        root = json.load(handle)
    if not isinstance(root, dict) or not isinstance(root.get("accounts"), list):
        raise ValueError("il file deve contenere una lista 'accounts'")

    policies: dict[str, AccountPolicy] = {}
    for item in root["accounts"]:
        if not isinstance(item, dict):
            raise ValueError("ogni account deve essere un oggetto JSON")
        policy = account_policy_from_dict(item)
        if policy.account_id in policies:
            raise ValueError(f"account duplicato: {policy.account_id}")
        policies[policy.account_id] = policy
    return policies
