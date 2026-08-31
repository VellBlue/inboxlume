from __future__ import annotations

import unittest
from datetime import datetime, timezone

from inboxlume.config import AccountPolicy, LearningPolicy
from inboxlume.models import (
    Classification,
    EmailCategory,
    PolicyAction,
    PreferenceSnapshot,
    ProviderKind,
    RetentionSignal,
)
from inboxlume.policy import SafetyPolicyEngine

from tests.helpers import make_message


NOW = datetime(2026, 8, 29, tzinfo=timezone.utc)


def classification(
    category: EmailCategory,
    confidence: float = 0.99,
    retention: RetentionSignal = RetentionSignal.UNCERTAIN,
    retention_confidence: float = 0.0,
) -> Classification:
    return Classification(
        category,
        confidence,
        ("test",),
        "test",
        retention,
        retention_confidence,
    )


class PolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = AccountPolicy(
            account_id="gmail_personale",
            provider=ProviderKind.GMAIL,
            unread_age_days=90,
        )
        self.engine = SafetyPolicyEngine()

    def test_old_unread_banking_message_is_kept(self) -> None:
        decision = self.engine.decide(
            make_message(), classification(EmailCategory.BANKING), self.policy, NOW
        )
        self.assertEqual(decision.action, PolicyAction.KEEP)
        self.assertEqual(decision.reason_codes, ("banking_record_or_notice",))

    def test_banking_promotion_remains_eligible_by_its_content(self) -> None:
        decision = self.engine.decide(
            make_message(
                sender="Example Bank <offers@example.invalid>",
                subject="Offerta estiva sulla nuova carta",
                body_text="Promozione commerciale. Disiscriviti quando vuoi.",
                headers={"List-Unsubscribe": "<https://example.invalid/u>"},
            ),
            classification(
                EmailCategory.ADVERTISING,
                0.99,
                RetentionSignal.DISCARD_CANDIDATE,
                0.99,
            ),
            self.policy,
            NOW,
        )
        self.assertEqual(decision.action, PolicyAction.QUARANTINE)

    def test_local_model_fallback_can_never_authorize_cleanup(self) -> None:
        fallback = Classification(
            EmailCategory.ADVERTISING,
            0.99,
            ("generic_promotion", "local_model_fallback"),
            "heuristic:v2",
            RetentionSignal.UNCERTAIN,
            0.0,
        )
        decision = self.engine.decide(
            make_message(),
            fallback,
            self.policy,
            NOW,
            PreferenceSnapshot(
                score=0.0,
                observations=20,
                dont_keep_similarity=0.99,
                dont_keep_similar_examples=20,
            ),
        )
        self.assertEqual(decision.action, PolicyAction.REVIEW)
        self.assertEqual(decision.reason_codes, ("local_model_unavailable",))

    def test_unread_and_high_risk_access_alerts_are_kept(self) -> None:
        unread = self.engine.decide(
            make_message(
                subject="New sign-in detected",
                body_text="A new login to your account was detected.",
            ),
            classification(EmailCategory.SECURITY, 0.99),
            self.policy,
            NOW,
        )
        high_risk_read = self.engine.decide(
            make_message(
                unread=False,
                subject="Accesso non riconosciuto",
                body_text="Se non sei stato tu, proteggi subito l'account.",
            ),
            classification(EmailCategory.ADVERTISING, 0.99),
            self.policy,
            NOW,
        )
        self.assertEqual(unread.action, PolicyAction.KEEP)
        self.assertEqual(unread.reason_codes, ("unread_access_alert",))
        self.assertEqual(high_risk_read.action, PolicyAction.KEEP)
        self.assertEqual(high_risk_read.reason_codes, ("high_risk_access_alert",))

        for subject in (
            "Your password was changed",
            "Your password has been reset",
            "La tua password è stata modificata",
            "La tua password è stata reimpostata",
            "Your password has changed",
            "Your password was updated",
            "We reset your password",
            "Password change complete",
            "Two-factor authentication disabled",
            "Recovery email changed",
        ):
            with self.subTest(subject=subject):
                changed = self.engine.decide(
                    make_message(subject=subject, body_text="Change completed."),
                    classification(
                        EmailCategory.ADVERTISING,
                        0.99,
                        RetentionSignal.DISCARD_CANDIDATE,
                        0.99,
                    ),
                    self.policy,
                    NOW,
                )
                self.assertEqual(changed.action, PolicyAction.KEEP)
                self.assertEqual(changed.reason_codes, ("high_risk_access_alert",))

        for subject, body in (
            ("Login from a new location", "We noticed a login from a new location."),
            ("Sign-in from Chrome", "We noticed a sign-in to your account."),
            ("Recent account access", "Your account was accessed from a new device."),
        ):
            with self.subTest(subject=subject):
                routine = self.engine.decide(
                    make_message(subject=subject, body_text=body),
                    classification(
                        EmailCategory.ADVERTISING,
                        0.99,
                        RetentionSignal.DISCARD_CANDIDATE,
                        0.99,
                    ),
                    self.policy,
                    NOW,
                )
                self.assertEqual(routine.action, PolicyAction.KEEP)
                self.assertEqual(routine.reason_codes, ("unread_access_alert",))

    def test_generic_credential_and_login_copy_is_not_a_security_event(self) -> None:
        examples = (
            (
                "Password manager sale",
                "Updated pricing and tips for safer passwords.",
            ),
            (
                "Simplify your login",
                "Discover faster sign-in features on every device.",
            ),
            (
                "MFA software offer",
                "Save on authentication tools for your team.",
            ),
        )
        for subject, body in examples:
            with self.subTest(subject=subject):
                decision = self.engine.decide(
                    make_message(subject=subject, body_text=body),
                    classification(
                        EmailCategory.ADVERTISING,
                        0.99,
                        RetentionSignal.DISCARD_CANDIDATE,
                        0.99,
                    ),
                    self.policy,
                    NOW,
                )
                self.assertEqual(decision.action, PolicyAction.QUARANTINE)

    def test_only_old_read_routine_access_alert_can_be_quarantined(self) -> None:
        recent = self.engine.decide(
            make_message(
                unread=False,
                received_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
                subject="New sign-in detected",
                body_text="A new login to your account was detected.",
            ),
            classification(EmailCategory.SECURITY, 0.99),
            self.policy,
            NOW,
        )
        old = self.engine.decide(
            make_message(
                unread=False,
                received_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                subject="New sign-in detected",
                body_text="A new login to your account was detected.",
            ),
            classification(EmailCategory.SECURITY, 0.99),
            self.policy,
            NOW,
        )
        self.assertEqual(recent.action, PolicyAction.KEEP)
        self.assertEqual(old.action, PolicyAction.QUARANTINE)
        self.assertEqual(
            old.reason_codes,
            ("expired_read_routine_access_alert",),
        )

    def test_receipts_and_completed_operations_are_kept_in_any_category(self) -> None:
        examples = (
            ("Ricevuta bonifico", "Bonifico eseguito correttamente."),
            ("Ricevuta universitaria", "Ricevuta di pagamento della tassa universitaria."),
            ("Ricarica confermata", "Ricarica telefonica effettuata."),
            (
                "Fattura elettronica disponibile",
                "Documento fiscale relativo al tuo acquisto.",
            ),
            ("Your invoice", "Tax document for your recent purchase."),
            ("Your monthly bank statement is ready", "Download your bank statement."),
            ("Documento bancario disponibile", "Il documento del conto è pronto."),
            ("Order confirmation #A123", "Your purchase has been confirmed."),
            ("Conferma ordine", "Il tuo acquisto è confermato."),
            ("Booking confirmation #B456", "Your hotel reservation is confirmed."),
            ("Conferma prenotazione", "La prenotazione è confermata."),
            ("Payment received", "We have received your payment of EUR 125.00."),
            ("Your payment was processed", "Payment processed on 12 August."),
            ("Bonifico ricevuto", "Hai ricevuto un bonifico di 250 euro."),
            ("Wire transfer completed", "Your wire transfer has completed."),
            ("Mobile top up successful", "Your mobile top up was successful."),
            ("Recharge confirmation", "Your mobile recharge is confirmed."),
            ("Purchase complete", "Your purchase is complete. Order #123."),
            ("University fee paid", "Your university fee was paid successfully."),
        )
        for subject, body in examples:
            with self.subTest(subject=subject):
                decision = self.engine.decide(
                    make_message(subject=subject, body_text=body),
                    classification(
                        EmailCategory.ADVERTISING,
                        0.99,
                        RetentionSignal.DISCARD_CANDIDATE,
                        0.99,
                    ),
                    self.policy,
                    NOW,
                )
                self.assertEqual(decision.action, PolicyAction.KEEP)
                self.assertEqual(decision.reason_codes, ("transaction_record",))

        very_old_read = self.engine.decide(
            make_message(
                unread=False,
                received_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
                subject="Ricevuta ricarica",
                body_text="Ricarica telefonica completata.",
            ),
            classification(
                EmailCategory.ADVERTISING,
                0.99,
                RetentionSignal.DISCARD_CANDIDATE,
                0.99,
            ),
            self.policy,
            NOW,
        )
        self.assertEqual(very_old_read.action, PolicyAction.KEEP)

    def test_transaction_words_without_completed_operation_do_not_protect_marketing(self) -> None:
        examples = (
            (
                "Complete your purchase",
                "Return to your cart and complete your purchase for 20% off.",
            ),
            (
                "Successful summer offers",
                "Choose a payment plan for your next purchase.",
            ),
            (
                "New payment options",
                "Compare payment options before your next order.",
            ),
        )
        for subject, body in examples:
            with self.subTest(subject=subject):
                decision = self.engine.decide(
                    make_message(subject=subject, body_text=body),
                    classification(
                        EmailCategory.ADVERTISING,
                        0.99,
                        RetentionSignal.DISCARD_CANDIDATE,
                        0.99,
                    ),
                    self.policy,
                    NOW,
                )
                self.assertEqual(decision.action, PolicyAction.QUARANTINE)

    def test_old_high_confidence_ad_is_only_proposed_for_quarantine(self) -> None:
        decision = self.engine.decide(
            make_message(),
            classification(
                EmailCategory.ADVERTISING,
                0.96,
                RetentionSignal.DISCARD_CANDIDATE,
                0.97,
            ),
            self.policy,
            NOW,
        )
        self.assertEqual(decision.action, PolicyAction.QUARANTINE)
        self.assertFalse(decision.changes_mailbox)
        self.assertTrue(decision.dry_run)

    def test_mailbox_important_flag_always_keeps_message(self) -> None:
        decision = self.engine.decide(
            make_message(flags=frozenset({"IMPORTANT"})),
            classification(EmailCategory.ADVERTISING),
            self.policy,
            NOW,
        )
        self.assertEqual(decision.action, PolicyAction.KEEP)

    def test_message_sent_to_self_is_always_kept(self) -> None:
        decision = self.engine.decide(
            make_message(
                sender="Owner <owner@example.invalid>",
                headers={
                    "To": "Archive <owner@example.invalid>",
                    "List-Unsubscribe": "<https://example.invalid/unsubscribe>",
                },
                has_attachment=True,
            ),
            classification(
                EmailCategory.SPAM,
                0.99,
                RetentionSignal.DISCARD_CANDIDATE,
                0.99,
            ),
            self.policy,
            NOW,
        )
        self.assertEqual(decision.action, PolicyAction.KEEP)
        self.assertEqual(decision.reason_codes, ("self_sent_message",))

    def test_different_sender_and_recipient_are_not_self_sent(self) -> None:
        decision = self.engine.decide(
            make_message(
                sender="Promotion <sender@example.invalid>",
                headers={"To": "Owner <owner@example.invalid>"},
            ),
            classification(
                EmailCategory.ADVERTISING,
                0.99,
                RetentionSignal.DISCARD_CANDIDATE,
                0.99,
            ),
            self.policy,
            NOW,
        )
        self.assertEqual(decision.action, PolicyAction.QUARANTINE)

    def test_young_unread_message_is_kept(self) -> None:
        decision = self.engine.decide(
            make_message(received_at=datetime(2026, 8, 20, tzinfo=timezone.utc)),
            classification(EmailCategory.SPAM),
            self.policy,
            NOW,
        )
        self.assertEqual(decision.action, PolicyAction.KEEP)

    def test_attachment_requires_review(self) -> None:
        decision = self.engine.decide(
            make_message(has_attachment=True),
            classification(EmailCategory.ADVERTISING),
            self.policy,
            NOW,
        )
        self.assertEqual(decision.action, PolicyAction.REVIEW)

    def test_old_read_one_time_code_is_quarantine_candidate(self) -> None:
        decision = self.engine.decide(
            make_message(unread=False),
            classification(EmailCategory.ONE_TIME_CODE, 0.97),
            self.policy,
            NOW,
        )
        self.assertEqual(decision.action, PolicyAction.QUARANTINE)
        self.assertEqual(decision.reason_codes, ("expired_read_one_time_code",))
        self.assertFalse(decision.changes_mailbox)

    def test_recent_or_uncertain_read_one_time_code_is_not_quarantined(self) -> None:
        recent = self.engine.decide(
            make_message(
                unread=False,
                received_at=datetime(2026, 8, 25, tzinfo=timezone.utc),
            ),
            classification(EmailCategory.ONE_TIME_CODE, 0.97),
            self.policy,
            NOW,
        )
        uncertain = self.engine.decide(
            make_message(unread=False),
            classification(EmailCategory.ONE_TIME_CODE, 0.80),
            self.policy,
            NOW,
        )
        self.assertEqual(recent.action, PolicyAction.KEEP)
        self.assertEqual(uncertain.action, PolicyAction.REVIEW)

    def test_protected_old_read_one_time_code_is_kept(self) -> None:
        decision = self.engine.decide(
            make_message(unread=False, flags=frozenset({"IMPORTANT"})),
            classification(EmailCategory.ONE_TIME_CODE, 0.99),
            self.policy,
            NOW,
        )
        self.assertEqual(decision.action, PolicyAction.KEEP)

    def test_category_or_sender_learning_alone_does_not_decide(self) -> None:
        learning_policy = AccountPolicy(
            account_id="gmail_personale",
            provider=ProviderKind.GMAIL,
            unread_age_days=90,
            learning=LearningPolicy(enabled=True, minimum_observations=3, protect_score=0.72),
        )
        broad_preference = self.engine.decide(
            make_message(),
            classification(EmailCategory.ADVERTISING),
            learning_policy,
            NOW,
            PreferenceSnapshot(0.90, 4),
        )
        self.assertEqual(broad_preference.action, PolicyAction.REVIEW)

    def test_similar_content_can_protect_or_propose_discard(self) -> None:
        learning_policy = AccountPolicy(
            account_id="gmail_personale",
            provider=ProviderKind.GMAIL,
            unread_age_days=90,
            learning=LearningPolicy(enabled=True),
        )
        protected = self.engine.decide(
            make_message(),
            classification(EmailCategory.ADVERTISING),
            learning_policy,
            NOW,
            PreferenceSnapshot(0.5, 1, keep_similarity=0.91),
        )
        discarded = self.engine.decide(
            make_message(),
            classification(EmailCategory.ADVERTISING, 0.97),
            learning_policy,
            NOW,
            PreferenceSnapshot(0.5, 1, dont_keep_similarity=0.94),
        )
        self.assertEqual(protected.action, PolicyAction.KEEP)
        self.assertEqual(discarded.action, PolicyAction.QUARANTINE)

    def test_conflicting_similar_examples_require_review(self) -> None:
        learning_policy = AccountPolicy(
            account_id="gmail_personale",
            provider=ProviderKind.GMAIL,
            unread_age_days=90,
            learning=LearningPolicy(enabled=True),
        )
        decision = self.engine.decide(
            make_message(),
            classification(
                EmailCategory.SOCIAL,
                0.99,
                RetentionSignal.DISCARD_CANDIDATE,
                0.99,
            ),
            learning_policy,
            NOW,
            PreferenceSnapshot(
                0.5,
                2,
                keep_similarity=0.90,
                dont_keep_similarity=0.91,
            ),
        )
        self.assertEqual(decision.action, PolicyAction.REVIEW)

    def test_recent_opening_behavior_can_only_protect_similar_content(self) -> None:
        learning_policy = AccountPolicy(
            account_id="gmail_personale",
            provider=ProviderKind.GMAIL,
            unread_age_days=30,
            learning=LearningPolicy(enabled=True, minimum_observations=3),
        )
        decision = self.engine.decide(
            make_message(),
            classification(
                EmailCategory.ADVERTISING,
                0.99,
                RetentionSignal.DISCARD_CANDIDATE,
                0.99,
            ),
            learning_policy,
            NOW,
            PreferenceSnapshot(
                0.5,
                0,
                recent_content_score=0.80,
                recent_content_evidence=3.0,
                recent_content_examples=3,
            ),
        )
        self.assertEqual(decision.action, PolicyAction.KEEP)
        self.assertEqual(decision.reason_codes, ("similar_content_opened_recently",))

    def test_recent_behavior_conflicting_with_explicit_discard_requires_review(self) -> None:
        learning_policy = AccountPolicy(
            account_id="gmail_personale",
            provider=ProviderKind.GMAIL,
            unread_age_days=30,
            learning=LearningPolicy(enabled=True, minimum_observations=3),
        )
        decision = self.engine.decide(
            make_message(),
            classification(EmailCategory.ADVERTISING, 0.99),
            learning_policy,
            NOW,
            PreferenceSnapshot(
                0.5,
                0,
                dont_keep_similarity=0.90,
                recent_content_score=0.80,
                recent_content_evidence=3.0,
                recent_content_examples=3,
            ),
        )
        self.assertEqual(decision.action, PolicyAction.REVIEW)

    def test_action_vocabulary_has_no_mailbox_mutation(self) -> None:
        forbidden = {"delete", "empty_trash", "sent", "send", "trash", "spam"}
        self.assertTrue(forbidden.isdisjoint(action.value for action in PolicyAction))


if __name__ == "__main__":
    unittest.main()
