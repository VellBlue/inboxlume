from __future__ import annotations

import math
from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable, Mapping


DEFAULT_CONFIDENCE_LEVEL = 0.95
DEFAULT_TARGET_FALSE_CLEANUP_RATE = 0.01
DEFAULT_MINIMUM_CONCLUSIVE_REVIEWS = 40
DIRECT_TRASH_MINIMUM_CONCLUSIVE_REVIEWS = 299
QUARANTINE_BLOCK_MINIMUM_CONCLUSIVE_REVIEWS = 20
QUARANTINE_BLOCK_MINIMUM_FALSE_CLEANUPS = 3


class GovernorStatus(StrEnum):
    COLLECTING = "collecting"
    NOT_QUALIFIED = "not_qualified"
    QUALIFIED_SHADOW = "qualified_shadow"


@dataclass(frozen=True, slots=True)
class SafetyEvidenceBand:
    name: str
    proposals: int
    confirmed_cleanup: int
    false_cleanup: int
    unsure: int
    unreviewed: int
    lower_false_cleanup_rate: float | None
    upper_false_cleanup_rate: float | None
    target_false_cleanup_rate: float
    confidence_level: float
    status: GovernorStatus

    @property
    def conclusive_reviews(self) -> int:
        return self.confirmed_cleanup + self.false_cleanup

    @property
    def reviewed(self) -> int:
        return self.conclusive_reviews + self.unsure

    @property
    def reviewed_fraction(self) -> float:
        return self.reviewed / self.proposals if self.proposals else 0.0

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "proposals": self.proposals,
            "confirmed_cleanup": self.confirmed_cleanup,
            "false_cleanup": self.false_cleanup,
            "unsure": self.unsure,
            "unreviewed": self.unreviewed,
            "conclusive_reviews": self.conclusive_reviews,
            "reviewed_fraction": round(self.reviewed_fraction, 6),
            "lower_false_cleanup_rate": (
                round(self.lower_false_cleanup_rate, 6)
                if self.lower_false_cleanup_rate is not None
                else None
            ),
            "upper_false_cleanup_rate": (
                round(self.upper_false_cleanup_rate, 6)
                if self.upper_false_cleanup_rate is not None
                else None
            ),
            "target_false_cleanup_rate": self.target_false_cleanup_rate,
            "confidence_level": self.confidence_level,
            "status": self.status.value,
        }


@dataclass(frozen=True, slots=True)
class SafetyGovernorReport:
    account_id: str
    scan_profile: str
    overall: SafetyEvidenceBand
    semantic_families: tuple[SafetyEvidenceBand, ...]
    shadow_only: bool = True
    authorizes_actions: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "account_id": self.account_id,
            "scan_profile": self.scan_profile,
            "overall": self.overall.as_dict(),
            "semantic_families": [item.as_dict() for item in self.semantic_families],
            "shadow_only": self.shadow_only,
            "authorizes_actions": self.authorizes_actions,
            "stored_plaintext": False,
        }


@dataclass(frozen=True, slots=True)
class OperationalQuarantineGate:
    """Fail-closed capability derived only from qualified local evidence."""

    enforced: bool
    overall_status: GovernorStatus
    authorized_families: frozenset[str]
    blocked_families: frozenset[str]
    direct_trash_authorized_families: frozenset[str]
    temporal_drift_restricted_families: frozenset[str]

    def permits(self, family: str) -> bool:
        if not self.enforced:
            return True
        return family not in self.blocked_families

    def permits_direct_trash(self, family: str) -> bool:
        if not self.enforced:
            return True
        return family in self.direct_trash_authorized_families

    def as_dict(self) -> dict[str, object]:
        return {
            "enforced": self.enforced,
            "overall_status": self.overall_status.value,
            "authorized_families": sorted(self.authorized_families),
            "blocked_families": sorted(self.blocked_families),
            "direct_trash_authorized_families": sorted(
                self.direct_trash_authorized_families
            ),
            "temporal_drift_restricted_families": sorted(
                self.temporal_drift_restricted_families
            ),
            "quarantine_only": (
                self.enforced and not bool(self.direct_trash_authorized_families)
            ),
            "authorizes_trash": (
                self.enforced and bool(self.direct_trash_authorized_families)
            ),
            "authorizes_permanent_delete": False,
            "insufficient_evidence_behavior": "ordinary",
        }


def operational_quarantine_gate(
    report: SafetyGovernorReport,
    *,
    enforced: bool,
    protective_drift_families: Iterable[str] = (),
) -> OperationalQuarantineGate:
    """Build the operational gate without broadening the policy's authority."""

    # A stored or programmatically supplied opt-in is not sufficient by itself.
    # Keep the backend fail-safe as well as the GUI: the operational layer only
    # exists after the account/model envelope has a minimally meaningful sample.
    effective_enforcement = enforced and operational_governor_available(report)

    authorized = frozenset(
        band.name
        for band in report.semantic_families
        if band.status is GovernorStatus.QUALIFIED_SHADOW
    )
    blocked_candidates = frozenset(
        band.name
        for band in report.semantic_families
        if band.conclusive_reviews
        >= QUARANTINE_BLOCK_MINIMUM_CONCLUSIVE_REVIEWS
        and band.false_cleanup >= QUARANTINE_BLOCK_MINIMUM_FALSE_CLEANUPS
        and band.lower_false_cleanup_rate is not None
        and band.lower_false_cleanup_rate
        > band.target_false_cleanup_rate
    )
    drift_restricted = frozenset(
        family.strip()
        for family in protective_drift_families
        if family.strip()
    )
    blocked = (
        blocked_candidates | drift_restricted
        if effective_enforcement
        else frozenset()
    )
    overall_direct_trash_ready = (
        report.overall.status is GovernorStatus.QUALIFIED_SHADOW
        and report.overall.conclusive_reviews
        >= DIRECT_TRASH_MINIMUM_CONCLUSIVE_REVIEWS
        and report.overall.false_cleanup == 0
    )
    direct_trash_authorized = frozenset(
        band.name
        for band in report.semantic_families
        if overall_direct_trash_ready
        and band.name not in drift_restricted
        and band.status is GovernorStatus.QUALIFIED_SHADOW
        and band.conclusive_reviews >= DIRECT_TRASH_MINIMUM_CONCLUSIVE_REVIEWS
        and band.false_cleanup == 0
    )
    return OperationalQuarantineGate(
        enforced=effective_enforcement,
        overall_status=report.overall.status,
        authorized_families=authorized,
        blocked_families=blocked,
        direct_trash_authorized_families=direct_trash_authorized,
        temporal_drift_restricted_families=(
            drift_restricted if effective_enforcement else frozenset()
        ),
    )


def operational_governor_available(report: SafetyGovernorReport) -> bool:
    """Whether a user may opt into the operational Governor for this envelope."""

    return (
        report.overall.conclusive_reviews
        >= DEFAULT_MINIMUM_CONCLUSIVE_REVIEWS
    )


def _direct_binomial_lower_tail(
    maximum: int,
    trials: int,
    probability: float,
) -> float:
    log_probability = math.log(probability)
    log_complement = math.log1p(-probability)
    common = math.lgamma(trials + 1)
    terms = [
        common
        - math.lgamma(observed + 1)
        - math.lgamma(trials - observed + 1)
        + observed * log_probability
        + (trials - observed) * log_complement
        for observed in range(maximum + 1)
    ]
    largest = max(terms)
    return math.exp(largest) * math.fsum(
        math.exp(term - largest) for term in terms
    )


def _binomial_cdf_at_most(errors: int, trials: int, probability: float) -> float:
    if probability <= 0.0:
        return 1.0
    if probability >= 1.0:
        return 1.0 if errors >= trials else 0.0
    if errors <= trials // 2:
        return min(
            1.0,
            _direct_binomial_lower_tail(errors, trials, probability),
        )
    # P(X <= k; p) = 1 - P(Y <= n-k-1; 1-p), which keeps the sum short and
    # numerically stable when the observed error count is in the upper half.
    opposite_tail = _direct_binomial_lower_tail(
        trials - errors - 1,
        trials,
        1.0 - probability,
    )
    return max(0.0, min(1.0, 1.0 - opposite_tail))


def upper_binomial_error_rate(
    errors: int,
    trials: int,
    *,
    confidence_level: float = DEFAULT_CONFIDENCE_LEVEL,
) -> float | None:
    """Exact one-sided Clopper-Pearson upper bound for a binomial error rate."""
    if trials < 0 or errors < 0 or errors > trials:
        raise ValueError("invalid binomial evidence")
    if not 0.5 < confidence_level < 1.0:
        raise ValueError("confidence_level must be between 0.5 and 1")
    if trials == 0:
        return None
    if errors == trials:
        return 1.0
    alpha = 1.0 - confidence_level
    if errors == 0:
        return 1.0 - math.pow(alpha, 1.0 / trials)
    low = errors / trials
    high = 1.0
    for _ in range(70):
        midpoint = (low + high) / 2.0
        if _binomial_cdf_at_most(errors, trials, midpoint) > alpha:
            low = midpoint
        else:
            high = midpoint
    return high


def lower_binomial_error_rate(
    errors: int,
    trials: int,
    *,
    confidence_level: float = DEFAULT_CONFIDENCE_LEVEL,
) -> float | None:
    """Exact one-sided Clopper-Pearson lower bound for a binomial error rate."""
    upper_complement = upper_binomial_error_rate(
        trials - errors,
        trials,
        confidence_level=confidence_level,
    )
    return None if upper_complement is None else 1.0 - upper_complement


def _evidence_band(
    name: str,
    counts: Mapping[str, int],
    *,
    confidence_level: float,
    target_false_cleanup_rate: float,
    minimum_conclusive_reviews: int,
) -> SafetyEvidenceBand:
    normalized = {
        answer: int(counts.get(answer, 0))
        for answer in ("keep", "dont_keep", "unsure", "unreviewed")
    }
    if any(value < 0 for value in normalized.values()):
        raise ValueError("negative safety evidence")
    conclusive = normalized["keep"] + normalized["dont_keep"]
    upper = upper_binomial_error_rate(
        normalized["keep"],
        conclusive,
        confidence_level=confidence_level,
    )
    lower = lower_binomial_error_rate(
        normalized["keep"],
        conclusive,
        confidence_level=confidence_level,
    )
    if conclusive < minimum_conclusive_reviews:
        status = GovernorStatus.COLLECTING
    elif upper is not None and upper <= target_false_cleanup_rate:
        status = GovernorStatus.QUALIFIED_SHADOW
    else:
        status = GovernorStatus.NOT_QUALIFIED
    return SafetyEvidenceBand(
        name=name,
        proposals=sum(normalized.values()),
        confirmed_cleanup=normalized["dont_keep"],
        false_cleanup=normalized["keep"],
        unsure=normalized["unsure"],
        unreviewed=normalized["unreviewed"],
        lower_false_cleanup_rate=lower,
        upper_false_cleanup_rate=upper,
        target_false_cleanup_rate=target_false_cleanup_rate,
        confidence_level=confidence_level,
        status=status,
    )


def evaluate_safety_governor(
    account_id: str,
    scan_profile: str,
    evidence_by_family: Mapping[str, Mapping[str, int]],
    *,
    confidence_level: float = DEFAULT_CONFIDENCE_LEVEL,
    target_false_cleanup_rate: float = DEFAULT_TARGET_FALSE_CLEANUP_RATE,
    minimum_conclusive_reviews: int = DEFAULT_MINIMUM_CONCLUSIVE_REVIEWS,
) -> SafetyGovernorReport:
    if not account_id.strip() or not scan_profile.strip():
        raise ValueError("account and scan profile are required")
    if not 0.0 < target_false_cleanup_rate < 0.5:
        raise ValueError("target_false_cleanup_rate must be between 0 and 0.5")
    if minimum_conclusive_reviews < 1:
        raise ValueError("minimum_conclusive_reviews must be positive")

    totals = {answer: 0 for answer in ("keep", "dont_keep", "unsure", "unreviewed")}
    families: list[SafetyEvidenceBand] = []
    for family, raw_counts in evidence_by_family.items():
        band = _evidence_band(
            str(family),
            raw_counts,
            confidence_level=confidence_level,
            target_false_cleanup_rate=target_false_cleanup_rate,
            minimum_conclusive_reviews=minimum_conclusive_reviews,
        )
        families.append(band)
        totals["keep"] += band.false_cleanup
        totals["dont_keep"] += band.confirmed_cleanup
        totals["unsure"] += band.unsure
        totals["unreviewed"] += band.unreviewed
    families.sort(key=lambda item: (-item.proposals, item.name))
    overall = _evidence_band(
        "overall",
        totals,
        confidence_level=confidence_level,
        target_false_cleanup_rate=target_false_cleanup_rate,
        minimum_conclusive_reviews=minimum_conclusive_reviews,
    )
    return SafetyGovernorReport(
        account_id=account_id,
        scan_profile=scan_profile,
        overall=overall,
        semantic_families=tuple(families),
    )
