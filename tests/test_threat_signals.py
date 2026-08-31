from __future__ import annotations

import json
import unittest

from benchmarks.mlx_email_worker import _extract_threat_json
from inboxlume.classifier import OllamaClassifier
from inboxlume.threat_signals import (
    SemanticThreatAssessment,
    ThreatSemanticMode,
    semantic_followup_recommended,
    SemanticThreatVerdict,
    ThreatLevel,
    ThreatIntent,
    ThreatSignal,
    assess_threat_signals,
    combine_threat_assessments,
    parse_semantic_threat_mapping,
)

from tests.helpers import make_message


class ThreatSignalTests(unittest.TestCase):
    @staticmethod
    def semantic(
        verdict: str = "likely_phishing",
        confidence: float = 0.92,
    ) -> SemanticThreatAssessment:
        return parse_semantic_threat_mapping(
            {
                "verdict": verdict,
                "intent": "credential_theft" if verdict != "benign" else "none",
                "impersonation": verdict != "benign",
                "credential_request": verdict != "benign",
                "money_request": False,
                "urgency_pressure": verdict != "benign",
                "link_action": verdict != "benign",
                "plausible_legitimate_context": verdict == "benign",
                "confidence": confidence,
                "reason_codes": [
                    "credential_harvest_language"
                    if verdict != "benign"
                    else "benign_context"
                ],
            },
            analyzer="test-local-model",
        )

    def test_brand_impersonation_and_urgent_credentials_form_consensus(self) -> None:
        message = make_message(
            sender="Google Security <notice@example.invalid>",
            subject="Urgent: account suspended",
            body_text="Verify your account immediately: https://unrelated.invalid/login",
        )
        assessment = assess_threat_signals(message)
        self.assertIn(ThreatSignal.BRAND_DOMAIN_MISMATCH, assessment.signals)
        self.assertIn(ThreatSignal.URGENT_CREDENTIAL_REQUEST, assessment.signals)
        self.assertIn(ThreatSignal.INDEPENDENT_SIGNAL_CONSENSUS, assessment.signals)
        self.assertEqual(assessment.level, ThreatLevel.HIGH)
        self.assertTrue(assessment.protective_review_recommended)
        self.assertFalse(assessment.as_dict()["authorizes_cleanup"])

    def test_legitimate_brand_domain_is_not_called_impersonation(self) -> None:
        official_sender = "Google <no-reply@" + "accounts.google.com>"
        message = make_message(sender=official_sender)
        assessment = assess_threat_signals(message)
        self.assertNotIn(ThreatSignal.BRAND_DOMAIN_MISMATCH, assessment.signals)

    def test_authentication_header_is_used_only_when_provider_marks_it_trusted(self) -> None:
        message = make_message(
            headers={"Authentication-Results": "mx.example; dmarc=fail; dkim=fail; spf=fail"}
        )
        untrusted = assess_threat_signals(message)
        trusted = assess_threat_signals(
            message, trusted_authentication_results=True
        )
        self.assertNotIn(ThreatSignal.TRUSTED_DMARC_FAILURE, untrusted.signals)
        self.assertIn(ThreatSignal.TRUSTED_DMARC_FAILURE, trusted.signals)
        self.assertIn(ThreatSignal.TRUSTED_DKIM_FAILURE, trusted.signals)
        self.assertIn(ThreatSignal.TRUSTED_SPF_FAILURE, trusted.signals)

    def test_unicode_and_ip_link_anomalies_are_controlled_signals(self) -> None:
        message = make_message(
            sender="Paypаl <service@" + "xn--paypl-3ve.example.invalid>",  # Cyrillic 'a'.
            body_text="Open https://192.0.2.4/account",
        )
        assessment = assess_threat_signals(message)
        self.assertIn(ThreatSignal.MIXED_SCRIPT_SENDER, assessment.signals)
        self.assertIn(ThreatSignal.PUNYCODE_SENDER_DOMAIN, assessment.signals)
        self.assertIn(ThreatSignal.IP_LITERAL_LINK, assessment.signals)

    def test_courier_fee_request_is_evidence_not_cleanup_authority(self) -> None:
        message = make_message(
            sender="Courier <notice@example.invalid>",
            subject="Package awaiting delivery",
            body_text="A redelivery fee is due: https://delivery.invalid/pay",
        )
        assessment = assess_threat_signals(message)
        self.assertIn(ThreatSignal.COURIER_FEE_REQUEST, assessment.signals)
        self.assertFalse(assessment.as_dict()["authorizes_cleanup"])

    def test_report_contains_no_plaintext_identity_or_link(self) -> None:
        secret_domain = "private-threat-domain.invalid"
        message = make_message(
            sender=f"Google <notice@{secret_domain}>",
            body_text=f"Urgent password check https://{secret_domain}/login",
        )
        report = repr(assess_threat_signals(message).as_dict()).casefold()
        self.assertNotIn(secret_domain, report)
        self.assertNotIn("notice@", report)

    def test_semantic_model_alone_cannot_create_high_risk(self) -> None:
        deterministic = assess_threat_signals(make_message())
        combined = combine_threat_assessments(
            deterministic,
            self.semantic(confidence=0.99),
        )
        self.assertEqual(combined.level, ThreatLevel.ELEVATED)
        self.assertFalse(combined.independent_consensus)
        self.assertFalse(combined.protective_review_recommended)

    def test_semantic_confidence_rejects_non_finite_values(self) -> None:
        for value in (float("nan"), float("inf"), True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.semantic(confidence=value)

    def test_independent_semantic_and_identity_evidence_reaches_critical(self) -> None:
        deterministic = assess_threat_signals(
            make_message(sender="Google <notice@example.invalid>")
        )
        combined = combine_threat_assessments(deterministic, self.semantic())
        self.assertEqual(combined.level, ThreatLevel.CRITICAL)
        self.assertTrue(combined.independent_consensus)
        self.assertTrue(combined.protective_review_recommended)
        self.assertFalse(combined.as_dict()["authorizes_cleanup"])

    def test_benign_semantic_result_never_erases_deterministic_evidence(self) -> None:
        deterministic = assess_threat_signals(
            make_message(
                sender="Google <notice@example.invalid>",
                body_text="Open https://192.0.2.5/account",
            )
        )
        combined = combine_threat_assessments(
            deterministic,
            self.semantic("benign", 0.95),
        )
        self.assertGreaterEqual(combined.score, deterministic.score)

    def test_ollama_threat_contract_is_tool_free_and_strict(self) -> None:
        classifier = OllamaClassifier("qwen3-vl:8b")
        payload = classifier.threat_request_payload(make_message())
        self.assertNotIn("tools", payload)
        self.assertEqual(payload["think"], False)
        parsed = classifier.parse_threat_json(
            json.dumps(
                {
                    "verdict": "likely_scam",
                    "intent": "financial_fraud",
                    "impersonation": True,
                    "credential_request": False,
                    "money_request": True,
                    "urgency_pressure": True,
                    "link_action": False,
                    "plausible_legitimate_context": False,
                    "confidence": 0.91,
                    "reason_codes": ["unexpected_financial_request"],
                }
            )
        )
        self.assertEqual(parsed.verdict, SemanticThreatVerdict.LIKELY_SCAM)
        self.assertEqual(parsed.intent, ThreatIntent.FINANCIAL_FRAUD)
        with self.assertRaises(RuntimeError):
            classifier.parse_threat_json('{"verdict":"likely_scam"}')

    def test_mlx_worker_uses_the_same_strict_threat_vocabulary(self) -> None:
        parsed = _extract_threat_json(
            json.dumps(
                {
                    "verdict": "uncertain",
                    "intent": "uncertain",
                    "impersonation": False,
                    "credential_request": False,
                    "money_request": False,
                    "urgency_pressure": False,
                    "link_action": False,
                    "plausible_legitimate_context": False,
                    "confidence": 0.45,
                    "reason_codes": ["insufficient_evidence"],
                }
            )
        )
        self.assertEqual(parsed["type"], "threat")
        invalid = {key: value for key, value in parsed.items() if key != "type"}
        invalid["reason_codes"] = ["free_form_reason"]
        with self.assertRaises(ValueError):
            _extract_threat_json(json.dumps(invalid))


class SemanticFollowupGateTests(unittest.TestCase):
    WEAK = make_message(
        sender="Offers <offers@example.invalid>",
        headers={"Reply-To": "reply@example.test"},
        subject="Special offer",
        body_text="Promotion ending today.",
    )
    ALERT = make_message(
        sender="Google Security <notice@example.invalid>",
        subject="Urgent: account suspended",
        body_text="Verify your password immediately: https://192.0.2.8/login",
    )

    def _assess(self, message):  # noqa: ANN001
        return assess_threat_signals(message, trusted_authentication_results=False)

    def test_the_weak_case_really_is_a_signal_below_an_alert(self) -> None:
        weak = self._assess(self.WEAK)

        # The whole distinction rests on this: a signal, but not an alert.
        self.assertTrue(weak.signals)
        self.assertFalse(weak.protective_review_recommended)
        self.assertTrue(self._assess(self.ALERT).protective_review_recommended)

    def test_technical_only_never_asks_the_model(self) -> None:
        for message in (self.WEAK, self.ALERT):
            with self.subTest(message=message.message_id):
                self.assertFalse(
                    semantic_followup_recommended(
                        self._assess(message), ThreatSemanticMode.TECHNICAL_ONLY
                    )
                )

    def test_confirmed_asks_only_about_alerts(self) -> None:
        self.assertFalse(
            semantic_followup_recommended(
                self._assess(self.WEAK), ThreatSemanticMode.CONFIRMED_SEMANTIC
            )
        )
        self.assertTrue(
            semantic_followup_recommended(
                self._assess(self.ALERT), ThreatSemanticMode.CONFIRMED_SEMANTIC
            )
        )

    def test_targeted_asks_about_any_signal(self) -> None:
        for message in (self.WEAK, self.ALERT):
            with self.subTest(message=message.message_id):
                self.assertTrue(
                    semantic_followup_recommended(
                        self._assess(message), ThreatSemanticMode.TARGETED_SEMANTIC
                    )
                )

    def test_each_mode_is_a_subset_of_the_next(self) -> None:
        for message in (self.WEAK, self.ALERT):
            technical, confirmed, targeted = (
                semantic_followup_recommended(self._assess(message), mode)
                for mode in (
                    ThreatSemanticMode.TECHNICAL_ONLY,
                    ThreatSemanticMode.CONFIRMED_SEMANTIC,
                    ThreatSemanticMode.TARGETED_SEMANTIC,
                )
            )
            with self.subTest(message=message.message_id):
                self.assertLessEqual(technical, confirmed)
                self.assertLessEqual(confirmed, targeted)

    def test_the_mode_accepts_its_stored_string_form(self) -> None:
        self.assertTrue(
            semantic_followup_recommended(self._assess(self.ALERT), "confirmed_semantic")
        )


if __name__ == "__main__":
    unittest.main()
