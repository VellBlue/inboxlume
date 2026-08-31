from __future__ import annotations

import hashlib
import json
import math
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from importlib.resources import files
from typing import Callable, Mapping, Protocol

from .models import EmailRecord, ProviderKind
from .threat_signals import (
    SemanticThreatAssessment,
    SemanticThreatVerdict,
    ThreatIntent,
    assess_threat_signals,
    combine_threat_assessments,
)


THREAT_BACKTEST_ENGINE_VERSION = "threat-backtest-v1"
THREAT_CORPUS_VERSION = "synthetic-threat-corpus-v1"


class ThreatCorpusLanguage(StrEnum):
    ENGLISH = "en"
    ITALIAN = "it"
    MIXED = "mixed"


class ThreatScenario(StrEnum):
    BRAND_IMPERSONATION = "brand_impersonation"
    CREDENTIAL_LURE = "credential_lure"
    DELIVERY_FEE = "delivery_fee"
    FINANCIAL_FRAUD = "financial_fraud"
    MALWARE_LURE = "malware_lure"
    UNICODE_DECEPTION = "unicode_deception"
    LEGITIMATE_SECURITY = "legitimate_security"
    LEGITIMATE_TRANSACTION = "legitimate_transaction"
    LEGITIMATE_DELIVERY = "legitimate_delivery"
    PERSONAL_OR_SCHOOL = "personal_or_school"
    NEWSLETTER = "newsletter"
    NON_NATIVE_WRITING = "non_native_writing"


class SemanticThreatAnalyzer(Protocol):
    def assess_threat_semantics(
        self,
        message: EmailRecord,
    ) -> SemanticThreatAssessment: ...


@dataclass(frozen=True, slots=True)
class ThreatCorpusCase:
    case_id: str
    language: ThreatCorpusLanguage
    scenario: ThreatScenario
    expected_malicious: bool
    message: EmailRecord


@dataclass(frozen=True, slots=True)
class ThreatBacktestReport:
    analyzer: str
    corpus_fingerprint: str
    total_cases: int
    malicious_cases: int
    benign_cases: int
    true_protective_reviews: int
    false_protective_reviews: int
    missed_threats: int
    true_safe: int
    model_failures: int
    semantic_analyzer_available: bool
    precision: float | None
    recall: float
    false_positive_rate: float
    false_positive_upper_95: float
    language_metrics: Mapping[str, Mapping[str, int]]
    scenario_metrics: Mapping[str, Mapping[str, int]]
    diagnostic_passed: bool
    engine_version: str = THREAT_BACKTEST_ENGINE_VERSION
    corpus_version: str = THREAT_CORPUS_VERSION

    def as_dict(self) -> dict[str, object]:
        return {
            "type": "local_threat_backtest",
            "engine_version": self.engine_version,
            "corpus_version": self.corpus_version,
            "corpus_fingerprint": self.corpus_fingerprint,
            "analyzer": self.analyzer,
            "cases": {
                "total": self.total_cases,
                "malicious": self.malicious_cases,
                "benign": self.benign_cases,
            },
            "outcomes": {
                "true_protective_reviews": self.true_protective_reviews,
                "false_protective_reviews": self.false_protective_reviews,
                "missed_threats": self.missed_threats,
                "true_safe": self.true_safe,
                "model_failures": self.model_failures,
            },
            "metrics": {
                "precision": (
                    round(self.precision, 6) if self.precision is not None else None
                ),
                "recall": round(self.recall, 6),
                "false_positive_rate": round(self.false_positive_rate, 6),
                "false_positive_upper_95": round(
                    self.false_positive_upper_95,
                    6,
                ),
            },
            "languages": dict(self.language_metrics),
            "scenarios": dict(self.scenario_metrics),
            "semantic_analyzer_available": self.semantic_analyzer_available,
            "diagnostic_passed": self.diagnostic_passed,
            "diagnostic_thresholds": {
                "minimum_cases": 20,
                "minimum_malicious": 8,
                "minimum_benign": 8,
                "minimum_precision": 0.90,
                "minimum_recall": 0.80,
                "maximum_observed_false_positive_rate": 0.05,
                "requires_zero_model_failures": True,
            },
            "synthetic_corpus_only": True,
            "reads_mailbox": False,
            "uses_network": False,
            "changes_mailbox": False,
            "authorizes_actions": False,
            "stored_plaintext": False,
        }


def _uncertain_semantic(analyzer: str) -> SemanticThreatAssessment:
    return SemanticThreatAssessment(
        verdict=SemanticThreatVerdict.UNCERTAIN,
        intent=ThreatIntent.UNCERTAIN,
        impersonation=False,
        credential_request=False,
        money_request=False,
        urgency_pressure=False,
        link_action=False,
        plausible_legitimate_context=False,
        confidence=0.0,
        reason_codes=("insufficient_evidence",),
        analyzer=analyzer,
    )


def _wilson_upper(successes: int, trials: int, z: float = 1.959963984540054) -> float:
    if trials <= 0:
        return 1.0
    proportion = successes / trials
    denominator = 1.0 + z * z / trials
    centre = proportion + z * z / (2.0 * trials)
    spread = z * math.sqrt(
        proportion * (1.0 - proportion) / trials
        + z * z / (4.0 * trials * trials)
    )
    return min(1.0, (centre + spread) / denominator)


def _metric_bucket() -> Counter[str]:
    return Counter(
        {
            "cases": 0,
            "malicious": 0,
            "benign": 0,
            "protective_reviews": 0,
            "false_protective_reviews": 0,
            "missed_threats": 0,
        }
    )


def _update_bucket(
    bucket: Counter[str],
    *,
    malicious: bool,
    protected: bool,
) -> None:
    bucket["cases"] += 1
    bucket["malicious" if malicious else "benign"] += 1
    if protected:
        bucket["protective_reviews"] += 1
    if protected and not malicious:
        bucket["false_protective_reviews"] += 1
    if malicious and not protected:
        bucket["missed_threats"] += 1


def load_synthetic_threat_corpus() -> tuple[ThreatCorpusCase, ...]:
    """Load the packaged, inspectable corpus with a strict no-extra-fields schema."""

    resource = files("inboxlume").joinpath("threat_corpus_v1.json")
    raw_bytes = resource.read_bytes()
    raw = json.loads(raw_bytes)
    if not isinstance(raw, dict) or set(raw) != {"version", "cases"}:
        raise ValueError("invalid threat corpus envelope")
    if raw["version"] != THREAT_CORPUS_VERSION or not isinstance(raw["cases"], list):
        raise ValueError("invalid threat corpus version")
    expected = {
        "id",
        "language",
        "scenario",
        "malicious",
        "received_at",
        "unread",
        "sender",
        "subject",
        "body",
        "headers",
    }
    cases: list[ThreatCorpusCase] = []
    identifiers: set[str] = set()
    for item in raw["cases"]:
        if not isinstance(item, dict) or set(item) != expected:
            raise ValueError("invalid threat corpus case fields")
        case_id = str(item["id"])
        if (
            not case_id
            or len(case_id) > 64
            or case_id in identifiers
            or type(item["malicious"]) is not bool
            or type(item["unread"]) is not bool
            or not isinstance(item["headers"], dict)
            or any(
                not isinstance(value, str)
                for value in (
                    item["sender"],
                    item["subject"],
                    item["body"],
                    item["received_at"],
                )
            )
            or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in item["headers"].items()
            )
        ):
            raise ValueError("invalid threat corpus case")
        identifiers.add(case_id)
        received_at = datetime.fromisoformat(str(item["received_at"]))
        if received_at.tzinfo is None:
            raise ValueError("threat corpus timestamps must include a timezone")
        cases.append(
            ThreatCorpusCase(
                case_id=case_id,
                language=ThreatCorpusLanguage(str(item["language"])),
                scenario=ThreatScenario(str(item["scenario"])),
                expected_malicious=bool(item["malicious"]),
                message=EmailRecord(
                    account_id="synthetic_threat_backtest",
                    provider=ProviderKind.FIXTURE,
                    message_id=case_id,
                    received_at=received_at,
                    unread=bool(item["unread"]),
                    sender=str(item["sender"]),
                    subject=str(item["subject"]),
                    body_text=str(item["body"]),
                    headers={str(k): str(v) for k, v in item["headers"].items()},
                ),
            )
        )
    if len(cases) < 20:
        raise ValueError("threat corpus is too small")
    return tuple(cases)


def synthetic_threat_corpus_fingerprint() -> str:
    resource = files("inboxlume").joinpath("threat_corpus_v1.json")
    return hashlib.sha256(resource.read_bytes()).hexdigest()


def run_synthetic_threat_backtest(
    backend: SemanticThreatAnalyzer | None,
    *,
    progress: Callable[[int, int], None] | None = None,
) -> ThreatBacktestReport:
    """Evaluate synthetic messages in memory; never connect to an email provider."""

    cases = load_synthetic_threat_corpus()
    analyzer_method = getattr(backend, "assess_threat_semantics", None)
    analyzer_available = callable(analyzer_method)
    analyzer_name = type(backend).__name__ if backend is not None else "deterministic-only"
    true_protective = false_protective = missed = true_safe = model_failures = 0
    languages: dict[str, Counter[str]] = {}
    scenarios: dict[str, Counter[str]] = {}
    for case in cases:
        deterministic = assess_threat_signals(case.message)
        if callable(analyzer_method):
            try:
                semantic = analyzer_method(case.message)
            except (RuntimeError, TypeError, ValueError):
                model_failures += 1
                semantic = _uncertain_semantic("local-model-failure")
        else:
            semantic = _uncertain_semantic("deterministic-only")
        protected = combine_threat_assessments(
            deterministic,
            semantic,
        ).protective_review_recommended
        if case.expected_malicious and protected:
            true_protective += 1
        elif case.expected_malicious:
            missed += 1
        elif protected:
            false_protective += 1
        else:
            true_safe += 1
        language_bucket = languages.setdefault(case.language.value, _metric_bucket())
        scenario_bucket = scenarios.setdefault(case.scenario.value, _metric_bucket())
        _update_bucket(
            language_bucket,
            malicious=case.expected_malicious,
            protected=protected,
        )
        _update_bucket(
            scenario_bucket,
            malicious=case.expected_malicious,
            protected=protected,
        )
        if progress is not None:
            progress(
                true_protective + false_protective + missed + true_safe,
                len(cases),
            )

    malicious = true_protective + missed
    benign = false_protective + true_safe
    predicted = true_protective + false_protective
    precision = true_protective / predicted if predicted else None
    recall = true_protective / malicious if malicious else 0.0
    false_positive_rate = false_protective / benign if benign else 1.0
    diagnostic_passed = (
        analyzer_available
        and len(cases) >= 20
        and malicious >= 8
        and benign >= 8
        and precision is not None
        and precision >= 0.90
        and recall >= 0.80
        and false_positive_rate <= 0.05
        and model_failures == 0
    )
    return ThreatBacktestReport(
        analyzer=analyzer_name,
        corpus_fingerprint=synthetic_threat_corpus_fingerprint(),
        total_cases=len(cases),
        malicious_cases=malicious,
        benign_cases=benign,
        true_protective_reviews=true_protective,
        false_protective_reviews=false_protective,
        missed_threats=missed,
        true_safe=true_safe,
        model_failures=model_failures,
        semantic_analyzer_available=analyzer_available,
        precision=precision,
        recall=recall,
        false_positive_rate=false_positive_rate,
        false_positive_upper_95=_wilson_upper(false_protective, benign),
        language_metrics={
            key: dict(sorted(value.items())) for key, value in sorted(languages.items())
        },
        scenario_metrics={
            key: dict(sorted(value.items())) for key, value in sorted(scenarios.items())
        },
        diagnostic_passed=diagnostic_passed,
    )
