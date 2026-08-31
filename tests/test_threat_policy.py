from __future__ import annotations

import tempfile
import unittest
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from inboxlume.cli import _apply_threat_protection
from inboxlume.learning import PreferenceStore
from inboxlume.models import (
    Classification,
    EmailCategory,
    PolicyAction,
    PolicyDecision,
)
from inboxlume.pipeline import DryRunResult
from inboxlume.threat_signals import (
    SemanticThreatAssessment,
    SemanticThreatVerdict,
    ThreatIntent,
    ThreatSemanticMode,
)

from tests.helpers import make_message


NOW = datetime(2026, 8, 30, tzinfo=timezone.utc)
PROFILE = "gemma26-policy-v2"


class ThreatPolicyTests(unittest.TestCase):
    @staticmethod
    def _semantic_phishing() -> SemanticThreatAssessment:
        return SemanticThreatAssessment(
            SemanticThreatVerdict.LIKELY_PHISHING,
            ThreatIntent.CREDENTIAL_THEFT,
            True,
            True,
            False,
            True,
            True,
            False,
            0.95,
            ("credential_harvest_language",),
            "test-local-backend",
        )

    def test_high_threat_changes_cleanup_candidate_to_protective_review(self) -> None:
        secret = "private-phishing-source.invalid"
        message = make_message(
            sender=f"Google Security <notice@{secret}>",
            subject="Urgent: account suspended",
            body_text=f"Verify your password immediately: https://{secret}/login",
        )
        classification = Classification(
            EmailCategory.SPAM,
            0.98,
            ("test",),
            "test",
        )
        decision = PolicyDecision(PolicyAction.QUARANTINE, ("ordinary_cleanup",))
        result = DryRunResult(message, classification, decision, 180)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private.sqlite3"
            store = PreferenceStore(path, b"t" * 32)
            store.record_shadow_scan(message, classification, decision, PROFILE, NOW)
            protected, report = _apply_threat_protection(
                [result], None, store, message.account_id, PROFILE, NOW
            )

            self.assertEqual(protected[0].decision.action, PolicyAction.REVIEW)
            self.assertIn(
                "threat_protective_review",
                protected[0].decision.reason_codes,
            )
            self.assertTrue(
                store.threat_protects_message_id(
                    message.account_id,
                    message.provider,
                    message.message_id,
                    PROFILE,
                )
            )
            self.assertEqual(
                store.shadow_record_for_message_id(
                    message.account_id,
                    message.provider,
                    message.message_id,
                    PROFILE,
                ),
                ("spam", "review"),
            )
            self.assertEqual(report["protective_reviews_current_batch"], 1)
            self.assertFalse(report["authorizes_cleanup"])
            self.assertNotIn(secret.encode(), path.read_bytes())

    def test_targeted_mode_reopens_technical_only_and_stale_engine_rows(self) -> None:
        message = make_message(message_id="threat-mode-transition")
        classification = Classification(
            EmailCategory.ADVERTISING,
            0.99,
            ("test",),
            "test",
        )
        decision = PolicyDecision(PolicyAction.QUARANTINE, ("test",))
        result = DryRunResult(message, classification, decision, 180)
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "threat-mode.sqlite3"
            store = PreferenceStore(database, b"m" * 32)
            store.record_shadow_scan(message, classification, decision, PROFILE, NOW)
            _apply_threat_protection(
                [result],
                None,
                store,
                message.account_id,
                PROFILE,
                NOW,
                ThreatSemanticMode.TECHNICAL_ONLY,
            )
            membership = store.shadow_scan_membership_checker(
                message.account_id,
                message.provider,
                PROFILE,
            )
            self.assertTrue(membership(message.message_id))

            reset = store.reset_stale_threat_assessments(
                message.account_id,
                PROFILE,
                ThreatSemanticMode.TARGETED_SEMANTIC,
            )
            self.assertEqual(reset, 1)
            self.assertFalse(
                store.shadow_scan_membership_checker(
                    message.account_id,
                    message.provider,
                    PROFILE,
                )(message.message_id)
            )

            store.record_shadow_scan(message, classification, decision, PROFILE, NOW)
            _apply_threat_protection(
                [result],
                None,
                store,
                message.account_id,
                PROFILE,
                NOW,
                ThreatSemanticMode.TARGETED_SEMANTIC,
            )
            with closing(sqlite3.connect(database)) as connection:
                with connection:
                    connection.execute(
                        "UPDATE threat_assessment "
                        "SET engine_version = 'obsolete-engine'"
                    )
            self.assertEqual(
                store.reset_stale_threat_assessments(
                    message.account_id,
                    PROFILE,
                    ThreatSemanticMode.TARGETED_SEMANTIC,
                ),
                1,
            )
            self.assertFalse(
                store.shadow_scan_membership_checker(
                    message.account_id,
                    message.provider,
                    PROFILE,
                )(message.message_id)
            )

    def test_high_threat_never_weakens_an_existing_keep(self) -> None:
        message = make_message(
            sender="Google <notice@example.invalid>",
            subject="Urgent: account suspended",
            body_text="Verify your password immediately: https://192.0.2.8/login",
        )
        classification = Classification(
            EmailCategory.IMPORTANT,
            0.99,
            ("test",),
            "test",
        )
        keep = PolicyDecision(PolicyAction.KEEP, ("protected_category",))
        result = DryRunResult(message, classification, keep, 10)
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "keep.sqlite3", b"u" * 32)
            store.record_shadow_scan(message, classification, keep, PROFILE, NOW)
            protected, report = _apply_threat_protection(
                [result], None, store, message.account_id, PROFILE, NOW
            )

        self.assertEqual(protected[0].decision.action, PolicyAction.KEEP)
        self.assertEqual(report["protective_reviews_current_batch"], 0)

    def test_required_semantic_failure_forces_protective_review(self) -> None:
        message = make_message(
            sender="Offers <offers@example.invalid>",
            headers={"Reply-To": "reply@example.test"},
            subject="Special offer",
            body_text="Promotion ending today.",
        )
        classification = Classification(
            EmailCategory.ADVERTISING, 0.99, ("test",), "test"
        )
        result = DryRunResult(
            message,
            classification,
            PolicyDecision(PolicyAction.QUARANTINE, ("ordinary_cleanup",)),
            180,
        )
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "failure.sqlite3", b"x" * 32)
            protected, report = _apply_threat_protection(
                [result], None, store, message.account_id, PROFILE, NOW
            )

        self.assertEqual(protected[0].decision.action, PolicyAction.REVIEW)
        self.assertIn("threat_analysis_incomplete", protected[0].decision.reason_codes)
        self.assertEqual(report["semantic_failures_current_batch"], 1)

    def test_targeted_mode_calls_local_ai_only_after_a_technical_signal(self) -> None:
        class CountingBackend:
            def __init__(self) -> None:
                self.calls = 0

            def assess_threat_semantics(self, _message):  # noqa: ANN001
                self.calls += 1
                return ThreatPolicyTests._semantic_phishing()

        clear = make_message(
            sender="News <newsletter@example.invalid>",
            subject="Monthly update",
            body_text="A normal monthly update with no action requested.",
        )
        suspicious = make_message(
            sender="Google Security <notice@example.invalid>",
            subject="Urgent: account suspended",
            body_text="Verify your password immediately: https://192.0.2.8/login",
            message_id="targeted-suspicious",
        )
        classification = Classification(EmailCategory.SPAM, 0.98, ("test",), "test")
        decision = PolicyDecision(PolicyAction.QUARANTINE, ("ordinary_cleanup",))
        backend = CountingBackend()
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "targeted.sqlite3", b"v" * 32)
            protected, report = _apply_threat_protection(
                [
                    DryRunResult(clear, classification, decision, 180),
                    DryRunResult(suspicious, classification, decision, 180),
                ],
                backend,
                store,
                clear.account_id,
                PROFILE,
                NOW,
                ThreatSemanticMode.TARGETED_SEMANTIC,
            )

        self.assertEqual(backend.calls, 1)
        self.assertEqual(report["semantic_inferences_requested_current_batch"], 1)
        self.assertEqual(report["semantic_inferences_skipped_current_batch"], 1)
        self.assertEqual(protected[0].decision.action, PolicyAction.QUARANTINE)
        self.assertEqual(protected[1].decision.action, PolicyAction.REVIEW)

    @staticmethod
    def _semantic_benign() -> SemanticThreatAssessment:
        return SemanticThreatAssessment(
            SemanticThreatVerdict.BENIGN,
            ThreatIntent.NONE,
            False,
            False,
            False,
            False,
            False,
            True,
            0.95,
            ("benign_context",),
            "test-local-backend",
        )

    @staticmethod
    def _weak_signal_message():
        # One low-score anomaly, far below an alert: reply-to on another domain.
        return make_message(
            sender="Offers <offers@example.invalid>",
            headers={"Reply-To": "reply@example.test"},
            subject="Special offer",
            body_text="Promotion ending today.",
            message_id="confirmed-weak",
        )

    @staticmethod
    def _alert_message():
        return make_message(
            sender="Google Security <notice@example.invalid>",
            subject="Urgent: account suspended",
            body_text="Verify your password immediately: https://192.0.2.8/login",
            message_id="confirmed-alert",
        )

    def _run_both_modes(self, backend_factory):
        classification = Classification(EmailCategory.SPAM, 0.98, ("test",), "test")
        decision = PolicyDecision(PolicyAction.QUARANTINE, ("ordinary_cleanup",))
        outcomes = {}
        for mode in (
            ThreatSemanticMode.CONFIRMED_SEMANTIC,
            ThreatSemanticMode.TARGETED_SEMANTIC,
        ):
            weak = self._weak_signal_message()
            alert = self._alert_message()
            backend = backend_factory()
            with tempfile.TemporaryDirectory() as directory:
                store = PreferenceStore(
                    Path(directory) / f"{mode.value}.sqlite3", b"c" * 32
                )
                protected, report = _apply_threat_protection(
                    [
                        DryRunResult(weak, classification, decision, 180),
                        DryRunResult(alert, classification, decision, 180),
                    ],
                    backend,
                    store,
                    weak.account_id,
                    PROFILE,
                    NOW,
                    mode,
                )
            outcomes[mode] = (backend, protected, report)
        return outcomes

    def test_confirmed_mode_asks_the_local_ai_only_about_technical_alerts(self) -> None:
        class CountingBackend:
            def __init__(self) -> None:
                self.calls = 0

            def assess_threat_semantics(self, _message):  # noqa: ANN001
                self.calls += 1
                return ThreatPolicyTests._semantic_phishing()

        outcomes = self._run_both_modes(CountingBackend)
        confirmed_backend, confirmed, confirmed_report = outcomes[
            ThreatSemanticMode.CONFIRMED_SEMANTIC
        ]
        targeted_backend, _, targeted_report = outcomes[
            ThreatSemanticMode.TARGETED_SEMANTIC
        ]

        # A single low-score anomaly earns a second opinion in the targeted
        # mode but not in the confirmed one, which is the whole point.
        self.assertEqual(confirmed_backend.calls, 1)
        self.assertEqual(targeted_backend.calls, 2)
        self.assertEqual(
            confirmed_report["semantic_inferences_requested_current_batch"], 1
        )
        self.assertEqual(
            confirmed_report["semantic_inferences_skipped_current_batch"], 1
        )
        self.assertEqual(
            targeted_report["semantic_inferences_requested_current_batch"], 2
        )
        self.assertEqual(confirmed_report["semantic_mode"], "confirmed_semantic")
        # The alert still becomes a protective review; only the weak anomaly
        # is left to the technical layer.
        self.assertEqual(confirmed[0].decision.action, PolicyAction.QUARANTINE)
        self.assertEqual(confirmed[1].decision.action, PolicyAction.REVIEW)

    def test_confirmed_mode_never_asks_about_more_than_the_targeted_mode(self) -> None:
        class CountingBackend:
            def __init__(self) -> None:
                self.calls = 0

            def assess_threat_semantics(self, _message):  # noqa: ANN001
                self.calls += 1
                return ThreatPolicyTests._semantic_phishing()

        outcomes = self._run_both_modes(CountingBackend)

        self.assertLessEqual(
            outcomes[ThreatSemanticMode.CONFIRMED_SEMANTIC][0].calls,
            outcomes[ThreatSemanticMode.TARGETED_SEMANTIC][0].calls,
        )

    def test_a_benign_second_opinion_cannot_clear_a_technical_alert(self) -> None:
        class BenignBackend:
            def __init__(self) -> None:
                self.calls = 0

            def assess_threat_semantics(self, _message):  # noqa: ANN001
                self.calls += 1
                return ThreatPolicyTests._semantic_benign()

        alert = self._alert_message()
        classification = Classification(EmailCategory.SPAM, 0.98, ("test",), "test")
        decision = PolicyDecision(PolicyAction.QUARANTINE, ("ordinary_cleanup",))
        backend = BenignBackend()
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "benign.sqlite3", b"d" * 32)
            protected, report = _apply_threat_protection(
                [DryRunResult(alert, classification, decision, 180)],
                backend,
                store,
                alert.account_id,
                PROFILE,
                NOW,
                ThreatSemanticMode.CONFIRMED_SEMANTIC,
            )

        # The combination stays additive: a second opinion can raise a finding,
        # never withdraw one. Weakening this would let the model overrule the
        # technical layer.
        self.assertEqual(backend.calls, 1)
        self.assertEqual(protected[0].decision.action, PolicyAction.REVIEW)
        self.assertEqual(report["protective_reviews_current_batch"], 1)

    def test_raising_the_mode_reopens_what_the_weaker_mode_skipped(self) -> None:
        classification = Classification(EmailCategory.SPAM, 0.98, ("test",), "test")
        decision = PolicyDecision(PolicyAction.QUARANTINE, ("ordinary_cleanup",))
        weak = self._weak_signal_message()
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "reopen.sqlite3", b"e" * 32)
            store.record_shadow_scan(weak, classification, decision, PROFILE, NOW)
            _apply_threat_protection(
                [DryRunResult(weak, classification, decision, 180)],
                None,
                store,
                weak.account_id,
                PROFILE,
                NOW,
                ThreatSemanticMode.CONFIRMED_SEMANTIC,
            )

            # Staying on the same mode keeps the row: nothing new would be
            # learned by analysing it again.
            self.assertEqual(
                store.reset_stale_threat_assessments(
                    weak.account_id, PROFILE, ThreatSemanticMode.CONFIRMED_SEMANTIC
                ),
                0,
            )
            # Moving up must reopen it, otherwise a message the weaker mode
            # never sent to the model would keep a stale verdict forever.
            self.assertEqual(
                store.reset_stale_threat_assessments(
                    weak.account_id, PROFILE, ThreatSemanticMode.TARGETED_SEMANTIC
                ),
                1,
            )

    def test_a_technical_only_row_reopens_for_the_confirmed_mode_too(self) -> None:
        classification = Classification(EmailCategory.SPAM, 0.98, ("test",), "test")
        decision = PolicyDecision(PolicyAction.QUARANTINE, ("ordinary_cleanup",))
        alert = self._alert_message()
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "upgrade.sqlite3", b"f" * 32)
            store.record_shadow_scan(alert, classification, decision, PROFILE, NOW)
            _apply_threat_protection(
                [DryRunResult(alert, classification, decision, 180)],
                None,
                store,
                alert.account_id,
                PROFILE,
                NOW,
                ThreatSemanticMode.TECHNICAL_ONLY,
            )

            self.assertEqual(
                store.reset_stale_threat_assessments(
                    alert.account_id, PROFILE, ThreatSemanticMode.CONFIRMED_SEMANTIC
                ),
                1,
            )

    def test_technical_only_mode_never_calls_local_ai(self) -> None:
        class CountingBackend:
            def __init__(self) -> None:
                self.calls = 0

            def assess_threat_semantics(self, _message):  # noqa: ANN001
                self.calls += 1
                return ThreatPolicyTests._semantic_phishing()

        message = make_message(
            sender="Google Security <notice@example.invalid>",
            subject="Urgent: account suspended",
            body_text="Verify your password immediately: https://192.0.2.8/login",
        )
        classification = Classification(EmailCategory.SPAM, 0.98, ("test",), "test")
        decision = PolicyDecision(PolicyAction.QUARANTINE, ("ordinary_cleanup",))
        backend = CountingBackend()
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "technical.sqlite3", b"w" * 32)
            protected, report = _apply_threat_protection(
                [DryRunResult(message, classification, decision, 180)],
                backend,
                store,
                message.account_id,
                PROFILE,
                NOW,
                ThreatSemanticMode.TECHNICAL_ONLY,
            )

        self.assertEqual(backend.calls, 0)
        self.assertEqual(report["semantic_inferences_requested_current_batch"], 0)
        self.assertEqual(report["semantic_inferences_skipped_current_batch"], 1)
        self.assertEqual(protected[0].decision.action, PolicyAction.REVIEW)


if __name__ == "__main__":
    unittest.main()
