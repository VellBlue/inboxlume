from __future__ import annotations

import unittest

from inboxlume.duration_estimator import (
    EstimateConfidence,
    ScanTimingSample,
    estimate_scan_duration,
    hardware_timing_key,
)
from inboxlume.local_models import HardwareProfile, LocalModelProfile
from inboxlume.models import ProviderKind
from inboxlume.settings import MessageDestination
from inboxlume.threat_signals import ThreatSemanticMode


APPLE_24 = HardwareProfile("Darwin", "arm64", 24.0)


class DurationEstimatorTests(unittest.TestCase):
    def test_zero_candidates_finishes_immediately_without_model_or_body_access(self) -> None:
        report = estimate_scan_duration(
            eligible_unprocessed=0,
            session_limit_reached=False,
            model_profile=LocalModelProfile.GEMMA26,
            hardware=APPLE_24,
            provider=ProviderKind.GMAIL,
            destination=MessageDestination.QUARANTINE,
            governor_enforced=False,
            action_fraction=0.5,
        )
        self.assertEqual(report.estimated_seconds, 0.0)
        self.assertEqual(report.confidence, EstimateConfidence.HIGH)
        self.assertFalse(report.as_dict()["read_bodies"])
        self.assertFalse(report.as_dict()["loads_model"])
        self.assertFalse(report.as_dict()["changes_mailbox"])

    def test_reference_estimate_accounts_for_model_hardware_and_options(self) -> None:
        baseline = estimate_scan_duration(
            eligible_unprocessed=50,
            session_limit_reached=True,
            model_profile=LocalModelProfile.QWEN8,
            hardware=APPLE_24,
            provider=ProviderKind.GMAIL,
            destination=MessageDestination.QUARANTINE,
            governor_enforced=False,
            action_fraction=0.3,
        )
        slower = estimate_scan_duration(
            eligible_unprocessed=50,
            session_limit_reached=True,
            model_profile=LocalModelProfile.GEMMA12,
            hardware=HardwareProfile("Linux", "x86_64", 8.0),
            provider=ProviderKind.YAHOO,
            destination=MessageDestination.TRASH,
            governor_enforced=True,
            action_fraction=0.8,
        )
        self.assertEqual(baseline.confidence, EstimateConfidence.LOW)
        self.assertIn("local_threat_technical", baseline.factors)
        self.assertIn("targeted_local_threat_semantics", baseline.factors)
        self.assertGreater(slower.estimated_seconds, baseline.estimated_seconds)
        self.assertGreater(slower.upper_seconds, slower.estimated_seconds)
        self.assertIn("memory_below_recommended", slower.factors)
        self.assertIn("different_reference_hardware", slower.factors)

    def test_matching_local_sessions_replace_the_reference_rate(self) -> None:
        report = estimate_scan_duration(
            eligible_unprocessed=100,
            session_limit_reached=False,
            model_profile=LocalModelProfile.GEMMA26,
            hardware=APPLE_24,
            provider=ProviderKind.GMAIL,
            destination=MessageDestination.QUARANTINE,
            governor_enforced=False,
            action_fraction=0.0,
            timing_samples=(
                ScanTimingSample(50, 75.0),
                ScanTimingSample(50, 80.0),
                ScanTimingSample(100, 155.0),
            ),
        )
        self.assertEqual(report.confidence, EstimateConfidence.HIGH)
        self.assertEqual(report.basis, "matching_local_sessions")
        self.assertEqual(report.timing_sample_count, 3)
        self.assertGreater(report.estimated_seconds, 150.0)
        self.assertLess(report.estimated_seconds, 170.0)

    def test_hardware_key_is_stable_and_contains_no_plain_hardware_text(self) -> None:
        first = hardware_timing_key(APPLE_24)
        second = hardware_timing_key(HardwareProfile("Darwin", "arm64", 24.2))
        self.assertEqual(first, second)
        self.assertEqual(len(first), 64)
        self.assertNotIn("darwin", first)
        self.assertNotIn("arm64", first)

    def test_technical_threat_screening_estimates_less_than_targeted_local_ai(self) -> None:
        common = {
            "eligible_unprocessed": 100,
            "session_limit_reached": False,
            "model_profile": LocalModelProfile.GEMMA26,
            "hardware": APPLE_24,
            "provider": ProviderKind.GMAIL,
            "destination": MessageDestination.QUARANTINE,
            "governor_enforced": False,
            "action_fraction": 0.0,
            "lumegraph_enabled": False,
            "obsolescence_proof_enabled": False,
        }
        technical = estimate_scan_duration(
            **common,
            threat_semantic_mode=ThreatSemanticMode.TECHNICAL_ONLY,
        )
        targeted = estimate_scan_duration(
            **common,
            threat_semantic_mode=ThreatSemanticMode.TARGETED_SEMANTIC,
        )

        self.assertLess(technical.estimated_seconds, targeted.estimated_seconds)
        self.assertNotIn("targeted_local_threat_semantics", technical.factors)

    def test_non_finite_or_boolean_quantities_are_rejected(self) -> None:
        common = {
            "eligible_unprocessed": 1,
            "session_limit_reached": False,
            "model_profile": LocalModelProfile.GEMMA26,
            "hardware": APPLE_24,
            "provider": ProviderKind.GMAIL,
            "destination": MessageDestination.QUARANTINE,
            "governor_enforced": False,
            "action_fraction": 0.5,
        }
        for field, value in (
            ("eligible_unprocessed", True),
            ("action_fraction", float("nan")),
            ("lifecycle_fraction", float("inf")),
            ("threat_semantic_fraction", True),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                estimate_scan_duration(**{**common, field: value})
        with self.assertRaises(ValueError):
            ScanTimingSample(True, 1.0)


class ConfirmedSemanticEstimateTests(unittest.TestCase):
    def _estimate(self, mode):  # noqa: ANN001
        return estimate_scan_duration(
            eligible_unprocessed=100,
            session_limit_reached=False,
            model_profile=LocalModelProfile.GEMMA26,
            hardware=APPLE_24,
            provider=ProviderKind.YAHOO,
            destination=MessageDestination.QUARANTINE,
            governor_enforced=False,
            action_fraction=0.5,
            threat_protection_enabled=True,
            threat_semantic_mode=mode,
        )

    def test_each_semantic_mode_keeps_its_own_sample_factor(self) -> None:
        confirmed = self._estimate(ThreatSemanticMode.CONFIRMED_SEMANTIC)
        targeted = self._estimate(ThreatSemanticMode.TARGETED_SEMANTIC)
        technical = self._estimate(ThreatSemanticMode.TECHNICAL_ONLY)

        # Mixing the samples of two modes would let one correct the other's
        # estimate with timings it never produced.
        self.assertIn("confirmed_local_threat_semantics", confirmed.factors)
        self.assertIn("targeted_local_threat_semantics", targeted.factors)
        self.assertNotIn("targeted_local_threat_semantics", confirmed.factors)
        self.assertNotIn("confirmed_local_threat_semantics", targeted.factors)
        self.assertNotIn("confirmed_local_threat_semantics", technical.factors)


if __name__ == "__main__":
    unittest.main()
