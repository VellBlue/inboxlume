from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Mapping


TEMPORAL_DRIFT_ENGINE_VERSION = "preference-drift-v1"
DEFAULT_RECENT_DAYS = 45
DEFAULT_HISTORICAL_DAYS = 180
MINIMUM_MESSAGES_PER_WINDOW = 5
MINIMUM_WEIGHT_PER_WINDOW = 8.0
PROTECTIVE_SHIFT_DELTA = 0.20
DECLINING_INTEREST_DELTA = -0.25


class TemporalDriftStatus(StrEnum):
    COLLECTING = "collecting"
    STABLE = "stable"
    WEAK_INTEREST_RISE = "weak_interest_rise"
    PROTECTIVE_SHIFT = "protective_shift"
    DECLINING_INTEREST = "declining_interest"
    CONFLICTING_RECENT_SIGNALS = "conflicting_recent_signals"


_SIGNAL_WEIGHTS: dict[str, tuple[float, float]] = {
    "opened": (1.0, 0.0),
    "starred": (3.0, 0.0),
    "marked_important": (3.0, 0.0),
    "restored": (5.0, 0.0),
    "left_unread": (0.0, 0.15),
    "quiz_keep": (4.0, 0.0),
    "quiz_keep_legacy": (4.0, 0.0),
    "quiz_dont_keep": (0.0, 3.0),
    "quiz_dont_keep_legacy": (0.0, 3.0),
}


@dataclass(frozen=True, slots=True)
class TemporalWindowEvidence:
    message_count: int
    signal_count: int
    positive_weight: float
    negative_weight: float
    protective_events: int
    explicit_discard_events: int
    legacy_approximated_events: int

    @property
    def effective_weight(self) -> float:
        return self.positive_weight + self.negative_weight

    @property
    def interest_score(self) -> float:
        # Symmetric prior prevents a handful of weak openings from looking
        # conclusive while remaining neutral at 0.5 without evidence.
        return (2.0 + self.positive_weight) / (
            4.0 + self.positive_weight + self.negative_weight
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "message_count": self.message_count,
            "signal_count": self.signal_count,
            "positive_weight": round(self.positive_weight, 3),
            "negative_weight": round(self.negative_weight, 3),
            "effective_weight": round(self.effective_weight, 3),
            "interest_score": round(self.interest_score, 6),
            "protective_events": self.protective_events,
            "explicit_discard_events": self.explicit_discard_events,
            "legacy_approximated_events": self.legacy_approximated_events,
        }


@dataclass(frozen=True, slots=True)
class FamilyTemporalDrift:
    family: str
    recent: TemporalWindowEvidence
    historical: TemporalWindowEvidence
    score_delta: float
    status: TemporalDriftStatus
    restricts_cleanup: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "family": self.family,
            "recent": self.recent.as_dict(),
            "historical": self.historical.as_dict(),
            "score_delta": round(self.score_delta, 6),
            "status": self.status.value,
            "restricts_cleanup": self.restricts_cleanup,
        }


@dataclass(frozen=True, slots=True)
class TemporalDriftReport:
    account_id: str
    scan_profile: str
    recent_days: int
    historical_days: int
    families: tuple[FamilyTemporalDrift, ...]

    @property
    def restricted_families(self) -> frozenset[str]:
        return frozenset(
            item.family for item in self.families if item.restricts_cleanup
        )

    @property
    def shifted_families(self) -> frozenset[str]:
        return frozenset(
            item.family
            for item in self.families
            if item.status
            not in {TemporalDriftStatus.COLLECTING, TemporalDriftStatus.STABLE}
        )

    @property
    def collecting_families(self) -> int:
        return sum(
            item.status is TemporalDriftStatus.COLLECTING
            for item in self.families
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "type": "temporal_preference_drift",
            "engine_version": TEMPORAL_DRIFT_ENGINE_VERSION,
            "account_id": self.account_id,
            "scan_profile": self.scan_profile,
            "recent_days": self.recent_days,
            "historical_days": self.historical_days,
            "families": [item.as_dict() for item in self.families],
            "restricted_families": sorted(self.restricted_families),
            "shifted_families": sorted(self.shifted_families),
            "authorizes_actions": False,
            "restricts_only": True,
            "read_bodies": False,
            "loads_model": False,
            "changes_mailbox": False,
            "stored_plaintext": False,
        }


def _window(raw: Mapping[str, int]) -> TemporalWindowEvidence:
    unknown = set(raw) - (set(_SIGNAL_WEIGHTS) | {"messages"})
    if unknown:
        raise ValueError("unknown temporal evidence signal")
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in raw.values()
    ):
        raise ValueError("invalid temporal evidence count")
    positive = 0.0
    negative = 0.0
    signal_count = 0
    for signal, (positive_weight, negative_weight) in _SIGNAL_WEIGHTS.items():
        count = int(raw.get(signal, 0))
        signal_count += count
        positive += positive_weight * count
        negative += negative_weight * count
    return TemporalWindowEvidence(
        message_count=int(raw.get("messages", 0)),
        signal_count=signal_count,
        positive_weight=positive,
        negative_weight=negative,
        protective_events=sum(
            int(raw.get(signal, 0))
            for signal in (
                "quiz_keep",
                "quiz_keep_legacy",
                "restored",
                "starred",
                "marked_important",
            )
        ),
        explicit_discard_events=(
            int(raw.get("quiz_dont_keep", 0))
            + int(raw.get("quiz_dont_keep_legacy", 0))
        ),
        legacy_approximated_events=(
            int(raw.get("quiz_keep_legacy", 0))
            + int(raw.get("quiz_dont_keep_legacy", 0))
        ),
    )


def evaluate_temporal_preference_drift(
    account_id: str,
    scan_profile: str,
    evidence_by_family: Mapping[str, Mapping[str, Mapping[str, int]]],
    *,
    recent_days: int = DEFAULT_RECENT_DAYS,
    historical_days: int = DEFAULT_HISTORICAL_DAYS,
) -> TemporalDriftReport:
    """Compare recent and preceding local evidence without broadening authority."""

    if not account_id.strip() or not scan_profile.strip():
        raise ValueError("account and scan profile are required")
    if not 1 <= recent_days < historical_days <= 3650:
        raise ValueError("invalid temporal drift windows")
    families: list[FamilyTemporalDrift] = []
    for family, raw_windows in sorted(evidence_by_family.items()):
        if set(raw_windows) - {"recent", "historical"}:
            raise ValueError("unknown temporal evidence window")
        recent = _window(raw_windows.get("recent", {}))
        historical = _window(raw_windows.get("historical", {}))
        delta = recent.interest_score - historical.interest_score
        enough_evidence = (
            recent.message_count >= MINIMUM_MESSAGES_PER_WINDOW
            and historical.message_count >= MINIMUM_MESSAGES_PER_WINDOW
            and recent.effective_weight >= MINIMUM_WEIGHT_PER_WINDOW
            and historical.effective_weight >= MINIMUM_WEIGHT_PER_WINDOW
        )
        if not enough_evidence:
            status = TemporalDriftStatus.COLLECTING
            restricts = False
        elif (
            recent.protective_events >= 2
            and recent.explicit_discard_events >= 2
        ):
            status = TemporalDriftStatus.CONFLICTING_RECENT_SIGNALS
            restricts = True
        elif delta >= PROTECTIVE_SHIFT_DELTA:
            if recent.protective_events >= 2:
                status = TemporalDriftStatus.PROTECTIVE_SHIFT
                restricts = True
            else:
                status = TemporalDriftStatus.WEAK_INTEREST_RISE
                restricts = False
        elif delta <= DECLINING_INTEREST_DELTA:
            status = TemporalDriftStatus.DECLINING_INTEREST
            restricts = False
        else:
            status = TemporalDriftStatus.STABLE
            restricts = False
        families.append(
            FamilyTemporalDrift(
                family=family,
                recent=recent,
                historical=historical,
                score_delta=delta,
                status=status,
                restricts_cleanup=restricts,
            )
        )
    return TemporalDriftReport(
        account_id=account_id,
        scan_profile=scan_profile,
        recent_days=recent_days,
        historical_days=historical_days,
        families=tuple(families),
    )
