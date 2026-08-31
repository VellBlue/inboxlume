from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum
from typing import Mapping

from .safety_governor import SafetyGovernorReport, evaluate_safety_governor


BACKTEST_ENGINE_VERSION = "historical-v1"


class BacktestTrend(StrEnum):
    NO_EVIDENCE = "no_evidence"
    BASELINE = "baseline"
    UNCHANGED = "unchanged"
    STABLE = "stable"
    IMPROVED_EVIDENCE = "improved_evidence"
    PROTECTIVE_REGRESSION = "protective_regression"


@dataclass(frozen=True, slots=True)
class VersionedSafetyBacktestReport:
    """Replay aggregate cleanup outcomes without reopening any message."""

    engine_version: str
    run_id: str
    evidence_fingerprint: str
    created_at: datetime
    safety_report: SafetyGovernorReport
    trend: BacktestTrend
    previous_evidence_fingerprint: str | None
    conclusive_review_delta: int
    false_cleanup_delta: int
    upper_bound_delta: float | None
    regressed_families: tuple[str, ...]
    snapshot_recorded: bool = False

    def with_snapshot_recorded(self, recorded: bool) -> VersionedSafetyBacktestReport:
        return replace(self, snapshot_recorded=recorded)

    def as_dict(self) -> dict[str, object]:
        return {
            "type": "local_safety_backtest",
            "engine_version": self.engine_version,
            "run_id": self.run_id,
            "evidence_fingerprint": self.evidence_fingerprint,
            "created_at": self.created_at.isoformat(),
            "account_id": self.safety_report.account_id,
            "scan_profile": self.safety_report.scan_profile,
            "overall": self.safety_report.overall.as_dict(),
            "semantic_families": [
                band.as_dict() for band in self.safety_report.semantic_families
            ],
            "trend": self.trend.value,
            "comparison": {
                "previous_evidence_fingerprint": (
                    self.previous_evidence_fingerprint
                ),
                "conclusive_review_delta": self.conclusive_review_delta,
                "false_cleanup_delta": self.false_cleanup_delta,
                "upper_bound_delta": (
                    round(self.upper_bound_delta, 6)
                    if self.upper_bound_delta is not None
                    else None
                ),
                "regressed_families": list(self.regressed_families),
            },
            "snapshot_recorded": self.snapshot_recorded,
            "authorizes_actions": False,
            "read_bodies": False,
            "changes_mailbox": False,
            "stored_plaintext": False,
        }


def _report_evidence(
    report: SafetyGovernorReport,
) -> dict[str, dict[str, int]]:
    return {
        band.name: {
            "keep": band.false_cleanup,
            "dont_keep": band.confirmed_cleanup,
            "unsure": band.unsure,
            "unreviewed": band.unreviewed,
        }
        for band in report.semantic_families
    }


def _fingerprint(
    scan_profile: str,
    engine_version: str,
    evidence: Mapping[str, Mapping[str, int]],
) -> str:
    canonical = json.dumps(
        {
            "engine_version": engine_version,
            "scan_profile": scan_profile,
            "evidence": evidence,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def evaluate_versioned_safety_backtest(
    account_id: str,
    scan_profile: str,
    evidence_by_family: Mapping[str, Mapping[str, int]],
    created_at: datetime,
    *,
    previous_evidence_by_family: Mapping[str, Mapping[str, int]] | None = None,
    previous_evidence_fingerprint: str | None = None,
    engine_version: str = BACKTEST_ENGINE_VERSION,
) -> VersionedSafetyBacktestReport:
    """Evaluate immutable aggregate evidence and compare it with the last snapshot."""

    if created_at.tzinfo is None:
        raise ValueError("created_at must include a timezone")
    if not engine_version.strip() or len(engine_version) > 64:
        raise ValueError("invalid backtest engine version")

    report = evaluate_safety_governor(
        account_id,
        scan_profile,
        evidence_by_family,
    )
    normalized = _report_evidence(report)
    evidence_fingerprint = _fingerprint(
        scan_profile,
        engine_version,
        normalized,
    )
    current = report.overall

    previous_report: SafetyGovernorReport | None = None
    if previous_evidence_by_family is not None:
        previous_report = evaluate_safety_governor(
            account_id,
            scan_profile,
            previous_evidence_by_family,
        )

    if current.proposals == 0:
        trend = BacktestTrend.NO_EVIDENCE
    elif previous_report is None:
        trend = BacktestTrend.BASELINE
    else:
        previous = previous_report.overall
        false_delta = current.false_cleanup - previous.false_cleanup
        if evidence_fingerprint == previous_evidence_fingerprint:
            trend = BacktestTrend.UNCHANGED
        elif false_delta > 0:
            trend = BacktestTrend.PROTECTIVE_REGRESSION
        elif (
            false_delta < 0
            or (
                current.upper_false_cleanup_rate is not None
                and previous.upper_false_cleanup_rate is not None
                and current.upper_false_cleanup_rate
                < previous.upper_false_cleanup_rate - 1e-12
            )
        ):
            trend = BacktestTrend.IMPROVED_EVIDENCE
        else:
            trend = BacktestTrend.STABLE

    previous_overall = previous_report.overall if previous_report else None
    current_families = {band.name: band for band in report.semantic_families}
    previous_families = (
        {band.name: band for band in previous_report.semantic_families}
        if previous_report
        else {}
    )
    regressed_families = (
        tuple(
            sorted(
                name
                for name, band in current_families.items()
                if band.false_cleanup
                > previous_families.get(
                    name, _EMPTY_EVIDENCE_BAND
                ).false_cleanup
            )
        )
        if previous_report is not None
        else ()
    )
    upper_delta = None
    if (
        previous_overall is not None
        and current.upper_false_cleanup_rate is not None
        and previous_overall.upper_false_cleanup_rate is not None
    ):
        upper_delta = (
            current.upper_false_cleanup_rate
            - previous_overall.upper_false_cleanup_rate
        )

    return VersionedSafetyBacktestReport(
        engine_version=engine_version,
        run_id=f"{engine_version}:{evidence_fingerprint[:16]}",
        evidence_fingerprint=evidence_fingerprint,
        created_at=created_at,
        safety_report=report,
        trend=trend,
        previous_evidence_fingerprint=previous_evidence_fingerprint,
        conclusive_review_delta=(
            current.conclusive_reviews - previous_overall.conclusive_reviews
            if previous_overall
            else 0
        ),
        false_cleanup_delta=(
            current.false_cleanup - previous_overall.false_cleanup
            if previous_overall
            else 0
        ),
        upper_bound_delta=upper_delta,
        regressed_families=regressed_families,
    )


# A zero-only comparison sentinel avoids optional branches in the family diff.
@dataclass(frozen=True, slots=True)
class _EmptyEvidenceBand:
    false_cleanup: int = 0


_EMPTY_EVIDENCE_BAND = _EmptyEvidenceBand()
