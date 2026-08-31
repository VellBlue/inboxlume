from __future__ import annotations

import unittest

from inboxlume.threat_backtest import (
    THREAT_BACKTEST_ENGINE_VERSION,
    THREAT_CORPUS_VERSION,
    load_synthetic_threat_corpus,
    run_synthetic_threat_backtest,
    synthetic_threat_corpus_fingerprint,
)
from inboxlume.threat_signals import (
    SemanticThreatAssessment,
    SemanticThreatVerdict,
    ThreatIntent,
)


class SyntheticOracle:
    def assess_threat_semantics(self, message):  # noqa: ANN001, ANN201
        malicious = message.message_id.startswith("threat-")
        return SemanticThreatAssessment(
            verdict=(
                SemanticThreatVerdict.LIKELY_PHISHING
                if malicious
                else SemanticThreatVerdict.BENIGN
            ),
            intent=(ThreatIntent.CREDENTIAL_THEFT if malicious else ThreatIntent.NONE),
            impersonation=malicious,
            credential_request=malicious,
            money_request=False,
            urgency_pressure=malicious,
            link_action=malicious,
            plausible_legitimate_context=not malicious,
            confidence=0.95,
            reason_codes=(
                ("credential_harvest_language",)
                if malicious
                else ("benign_context",)
            ),
            analyzer="synthetic-test-oracle",
        )


class FailingAnalyzer:
    def assess_threat_semantics(self, message):  # noqa: ANN001, ANN201
        raise RuntimeError("synthetic failure")


class ThreatBacktestTests(unittest.TestCase):
    def test_packaged_corpus_is_bilingual_balanced_and_reproducible(self) -> None:
        cases = load_synthetic_threat_corpus()
        languages = {case.language.value for case in cases}
        malicious = sum(case.expected_malicious for case in cases)

        self.assertGreaterEqual(len(cases), 20)
        self.assertGreaterEqual(malicious, 8)
        self.assertGreaterEqual(len(cases) - malicious, 8)
        self.assertEqual(languages, {"en", "it", "mixed"})
        self.assertEqual(len(synthetic_threat_corpus_fingerprint()), 64)

    def test_backtest_is_aggregate_non_authorising_and_contains_hard_negatives(self) -> None:
        report = run_synthetic_threat_backtest(SyntheticOracle())
        payload = report.as_dict()
        rendered = repr(payload)

        self.assertEqual(report.engine_version, THREAT_BACKTEST_ENGINE_VERSION)
        self.assertEqual(report.corpus_version, THREAT_CORPUS_VERSION)
        self.assertEqual(report.total_cases, 25)
        self.assertEqual(report.false_protective_reviews, 0)
        self.assertGreaterEqual(report.recall, 0.80)
        self.assertTrue(report.diagnostic_passed)
        self.assertGreater(report.false_positive_upper_95, 0.0)
        self.assertFalse(payload["reads_mailbox"])
        self.assertFalse(payload["uses_network"])
        self.assertFalse(payload["changes_mailbox"])
        self.assertFalse(payload["authorizes_actions"])
        self.assertFalse(payload["stored_plaintext"])
        self.assertNotIn("Urgent: account suspended", rendered)
        self.assertNotIn("Verify your account and password", rendered)
        self.assertNotIn("notice@example.invalid", rendered)

    def test_model_failure_falls_back_without_passing_the_diagnostic(self) -> None:
        report = run_synthetic_threat_backtest(FailingAnalyzer())

        self.assertEqual(report.model_failures, report.total_cases)
        self.assertFalse(report.diagnostic_passed)
        self.assertEqual(
            report.true_protective_reviews + report.missed_threats,
            report.malicious_cases,
        )

    def test_deterministic_only_run_is_visible_but_never_certified(self) -> None:
        report = run_synthetic_threat_backtest(None)

        self.assertFalse(report.semantic_analyzer_available)
        self.assertFalse(report.diagnostic_passed)
        self.assertEqual(report.analyzer, "deterministic-only")


if __name__ == "__main__":
    unittest.main()
