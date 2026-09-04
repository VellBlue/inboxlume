from __future__ import annotations

import tempfile
import unittest
import sqlite3
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import inboxlume.config as config_module
from inboxlume.classifier import HeuristicClassifier
from inboxlume.config import load_policies, policy_safety_fingerprint
from inboxlume.learning import PreferenceStore
from inboxlume.models import (
    Classification,
    EmailCategory,
    PolicyAction,
    PolicyDecision,
    ProviderKind,
)
from inboxlume.pipeline import (
    prepare_automatic_quarantine_candidates,
    prepare_automatic_quarantine_ids,
    prepare_mature_quarantine_candidates,
    prepare_quarantine_shadow_review,
    prepare_quiz,
    prepare_verified_quarantine_candidates,
    prepare_verified_quarantine_ids,
    run_dry_scan,
    run_shadow_scan,
)
from inboxlume.proof_of_obsolescence import (
    ClosureWitness,
    ObsolescenceProof,
    ProofDestination,
    ProofStatus,
)
from inboxlume.providers.contracts import READ_ONLY_CAPABILITIES
from inboxlume.threat_signals import (
    SemanticThreatAssessment,
    SemanticThreatVerdict,
    ThreatIntent,
    assess_threat_signals,
    combine_threat_assessments,
)

from tests.helpers import make_message


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 8, 29, tzinfo=timezone.utc)


def record_completed_threat_assessment(
    store: PreferenceStore,
    message,
    profile: str,
) -> None:  # noqa: ANN001
    semantic = SemanticThreatAssessment(
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
        "test",
    )
    store.record_threat_assessment(
        message,
        profile,
        combine_threat_assessments(assess_threat_signals(message), semantic),
        NOW,
        protective_review=False,
    )


class FakeMailbox:
    capabilities = READ_ONLY_CAPABILITIES

    def __init__(
        self,
        messages,
        read_otp_messages=(),
        read_access_messages=(),
    ):  # noqa: ANN001
        self.messages = list(messages)
        self.read_otp_messages = list(read_otp_messages)
        self.read_access_messages = list(read_access_messages)
        self.before = None
        self.otp_before = None
        self.access_before = None
        self.limit = None

    def iter_inbox_unread_before(self, before, limit):  # noqa: ANN001
        self.before = before
        self.limit = limit
        yield from self.messages[:limit]

    def iter_inbox_read_one_time_code_candidates_before(self, before, limit):  # noqa: ANN001
        self.otp_before = before
        yield from self.read_otp_messages[:limit]

    def iter_inbox_read_routine_access_alert_candidates_before(  # noqa: ANN001
        self,
        before,
        limit,
        skip_message_id=None,
        search_limit=None,
        oldest_first=False,
    ):
        self.access_before = before
        messages = list(self.read_access_messages)
        if oldest_first:
            messages.reverse()
        yielded = 0
        for message in messages:
            if skip_message_id is not None and skip_message_id(message.message_id):
                continue
            yield message
            yielded += 1
            if yielded >= limit:
                return

    def iter_inbox_quiz_sample(  # noqa: ANN001
        self, limit, old_unread_before=None, skip_message_id=None, search_limit=None
    ):
        self.limit = limit
        self.before = old_unread_before
        messages = (
            message for message in self.messages
            if skip_message_id is None or not skip_message_id(message.message_id)
        )
        yield from list(messages)[:limit]


class CountingClassifier:
    def __init__(self) -> None:
        self.calls = 0

    def classify(self, message):  # noqa: ANN001
        self.calls += 1
        return Classification(EmailCategory.UNCERTAIN, 0.3, ("test",), "test")


class InterruptingClassifier(CountingClassifier):
    def classify(self, message):  # noqa: ANN001
        self.calls += 1
        if self.calls == 2:
            raise KeyboardInterrupt
        return Classification(EmailCategory.UNCERTAIN, 0.3, ("test",), "test")


class ProgressiveFakeMailbox(FakeMailbox):
    def iter_inbox_unread_before(  # noqa: ANN001
        self,
        before,
        limit,
        skip_message_id=None,
        search_limit=None,
        oldest_first=False,
    ):
        yielded = 0
        messages = self.messages[:search_limit]
        if oldest_first:
            messages = list(reversed(messages))
        for message in messages:
            if skip_message_id is not None and skip_message_id(message.message_id):
                continue
            yield message
            yielded += 1
            if yielded >= limit:
                return
    def iter_inbox_read_one_time_code_candidates_before(  # noqa: ANN001
        self,
        before,
        limit,
        skip_message_id=None,
        search_limit=None,
        oldest_first=False,
    ):
        yield from ()

    def iter_inbox_matching_candidate_ids(  # noqa: ANN001
        self,
        unread_before,
        read_otp_before,
        read_access_before,
        limit,
        search_limit,
        include_message_id,
    ):
        yielded = 0
        for message in self.messages[:search_limit]:
            if not include_message_id(message.message_id, message.unread):
                continue
            yield message.message_id
            yielded += 1
            if yielded >= limit:
                return


class FakeQuarantineMailbox:
    capabilities = READ_ONLY_CAPABILITIES

    class Transport:
        folder = "InboxLume-Quarantena"

    transport = Transport()

    def __init__(self, messages):  # noqa: ANN001
        self.messages = list(messages)

    def iter_quarantine_review_messages(self, search_limit):  # noqa: ANN001
        yield from self.messages[:search_limit]


class DryRunPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = load_policies(ROOT / "config/accounts.example.json")[
            "gmail_personale"
        ]
        self.policy_fingerprint = policy_safety_fingerprint(self.policy)

    def test_report_omits_email_content_and_never_changes_mailbox(self) -> None:
        mailbox = FakeMailbox(
            [
                make_message(
                    message_id="promo",
                    sender="Negozio <promo@example.invalid>",
                    subject="Newsletter e offerta",
                    body_text="Sconto e promozione. Disiscriviti.",
                )
            ]
        )
        results = run_dry_scan(
            self.policy,
            mailbox,
            HeuristicClassifier(),
            NOW,
            limit=1,
        )
        report = results[0].as_dict()
        self.assertEqual(report["suggested_action"], "review")
        self.assertFalse(report["changes_mailbox"])
        self.assertTrue(report["dry_run"])
        for private_field in ("sender", "subject", "body", "body_text", "headers"):
            self.assertNotIn(private_field, report)
        self.assertEqual(mailbox.limit, 1)
        self.assertEqual((NOW - mailbox.before).days, self.policy.unread_age_days)

    def test_read_one_time_code_rule_is_reached_by_dry_scan(self) -> None:
        mailbox = FakeMailbox(
            [],
            read_otp_messages=[
                make_message(
                    message_id="read-otp",
                    unread=False,
                    subject="Codice di verifica Google: 123456",
                    body_text="Il tuo codice monouso è 123456",
                )
            ],
        )
        results = run_dry_scan(
            self.policy,
            mailbox,
            HeuristicClassifier(),
            NOW,
            limit=5,
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].decision.action.value, "quarantine")
        self.assertEqual((NOW - mailbox.otp_before).days, 7)
        self.assertFalse(results[0].decision.changes_mailbox)

    def test_old_read_routine_access_alert_is_a_scan_candidate(self) -> None:
        mailbox = FakeMailbox(
            [],
            read_access_messages=[
                make_message(
                    message_id="read-login",
                    unread=False,
                    received_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                    subject="New sign-in detected",
                    body_text="A new device login was detected.",
                )
            ],
        )
        results = run_dry_scan(
            self.policy,
            mailbox,
            HeuristicClassifier(),
            NOW,
            limit=5,
        )

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].decision.action, PolicyAction.QUARANTINE)
        self.assertEqual((NOW - mailbox.access_before).days, 90)

    def test_rejects_provider_with_extra_or_missing_capabilities(self) -> None:
        mailbox = FakeMailbox([])
        mailbox.capabilities = frozenset()
        with self.assertRaises(ValueError):
            run_dry_scan(
                self.policy,
                mailbox,
                HeuristicClassifier(),
                NOW,
                limit=1,
            )

    def test_quiz_selection_uses_inbox_contract_and_hashed_store(self) -> None:
        messages = [
            make_message(message_id="1", sender="a@example.invalid"),
            make_message(message_id="2", sender="b@example.invalid"),
        ]
        mailbox = FakeMailbox(messages)
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "quiz.sqlite3", b"p" * 32)
            selected = prepare_quiz(
                self.policy,
                mailbox,
                HeuristicClassifier(),
                store,
                quiz_limit=2,
                sample_limit=2,
            )
        self.assertEqual(len(selected), 2)
        self.assertEqual(mailbox.limit, 2)

    def test_quiz_does_not_reclassify_already_answered_messages(self) -> None:
        messages = [
            make_message(message_id="answered", sender="a@example.invalid"),
            make_message(message_id="new", sender="b@example.invalid"),
        ]
        mailbox = FakeMailbox(messages)
        classifier = CountingClassifier()
        previous_classification = Classification(
            EmailCategory.UNCERTAIN, 0.3, ("test",), "test"
        )
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "quiz.sqlite3", b"p" * 32)
            store.record_quiz_answer(
                messages[0],
                previous_classification,
                "unsure",
                None,
            )
            selected = prepare_quiz(
                self.policy,
                mailbox,
                classifier,
                store,
                quiz_limit=1,
                sample_limit=2,
                now=NOW,
            )
        self.assertEqual([item.message.message_id for item in selected], ["new"])
        self.assertEqual(classifier.calls, 1)

    def test_quiz_searches_past_answered_messages_to_fill_requested_limit(self) -> None:
        messages = [
            make_message(message_id=f"quiz-{index}", sender=f"s{index}@example.invalid")
            for index in range(4)
        ]
        mailbox = FakeMailbox(messages)
        classification = Classification(
            EmailCategory.UNCERTAIN, 0.3, ("test",), "test"
        )
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "quiz.sqlite3", b"z" * 32)
            for message in messages[:2]:
                store.record_quiz_answer(message, classification, "unsure", None)
            selected = prepare_quiz(
                self.policy,
                mailbox,
                HeuristicClassifier(),
                store,
                quiz_limit=2,
                sample_limit=2,
                now=NOW,
            )

        self.assertEqual(
            [candidate.message.message_id for candidate in selected],
            ["quiz-2", "quiz-3"],
        )

    def test_shadow_scan_advances_without_storing_plaintext(self) -> None:
        messages = [
            make_message(message_id="first", sender="private-one@example.invalid"),
            make_message(message_id="second", sender="private-two@example.invalid"),
        ]
        mailbox = ProgressiveFakeMailbox(messages)
        classifier = CountingClassifier()
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "shadow.sqlite3"
            store = PreferenceStore(database, b"s" * 32)
            first = run_shadow_scan(
                self.policy,
                mailbox,
                classifier,
                NOW,
                limit=2,
                search_limit=2,
                preference_store=store,
                scan_profile="gemma26-policy-v1",
            )
            second = run_shadow_scan(
                self.policy,
                mailbox,
                classifier,
                NOW,
                limit=2,
                search_limit=2,
                preference_store=store,
                scan_profile="gemma26-policy-v1",
            )
            summary = store.shadow_scan_summary(
                self.policy.account_id,
                "gemma26-policy-v1",
            )
            raw_database = database.read_bytes()
        self.assertEqual(len(first), 2)
        self.assertEqual(second, [])
        self.assertEqual(summary["processed_total"], 2)
        self.assertNotIn(b"private-one@example.invalid", raw_database)
        self.assertNotIn(b"first", raw_database)

    def test_shadow_scan_honors_oldest_first_and_reports_progress(self) -> None:
        messages = [
            make_message(message_id=f"ordered-{index}") for index in range(3)
        ]
        mailbox = ProgressiveFakeMailbox(messages)
        progress: list[tuple[int, int]] = []
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "ordered.sqlite3", b"o" * 32)
            results = run_shadow_scan(
                self.policy,
                mailbox,
                CountingClassifier(),
                NOW,
                limit=2,
                search_limit=3,
                preference_store=store,
                scan_profile="gemma26-policy-v2",
                oldest_first=True,
                progress=lambda processed, limit: progress.append((processed, limit)),
            )

        self.assertEqual(
            [result.message.message_id for result in results],
            ["ordered-2", "ordered-1"],
        )
        self.assertEqual(progress, [(1, 2), (2, 2)])

    def test_interrupted_shadow_scan_does_not_commit_partial_ids(self) -> None:
        mailbox = ProgressiveFakeMailbox(
            [make_message(message_id="partial-one"), make_message(message_id="partial-two")]
        )
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "cancel.sqlite3", b"c" * 32)
            with self.assertRaises(KeyboardInterrupt):
                run_shadow_scan(
                    self.policy,
                    mailbox,
                    InterruptingClassifier(),
                    NOW,
                    limit=2,
                    search_limit=2,
                    preference_store=store,
                    scan_profile="gemma26-policy-v2",
                )
            summary = store.shadow_scan_summary(
                self.policy.account_id,
                "gemma26-policy-v2",
            )

        self.assertEqual(summary["processed_total"], 0)

    def test_shadow_batch_database_failure_rolls_back_the_whole_batch(self) -> None:
        first = make_message(message_id="atomic-one")
        second = make_message(message_id="atomic-two")
        decision = PolicyDecision(PolicyAction.REVIEW, ("test",))
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "atomic.sqlite3", b"a" * 32)
            with closing(store._connect()) as connection:
                with connection:
                    connection.execute(
                        """
                        CREATE TRIGGER reject_spam_shadow BEFORE INSERT ON shadow_scan
                        WHEN NEW.category = 'spam'
                        BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END
                        """
                    )
            with self.assertRaises(sqlite3.IntegrityError):
                store.record_shadow_scan_batch(
                    [
                        (
                            first,
                            Classification(
                                EmailCategory.ADVERTISING, 0.9, ("test",), "test"
                            ),
                            decision,
                        ),
                        (
                            second,
                            Classification(EmailCategory.SPAM, 0.9, ("test",), "test"),
                            decision,
                        ),
                    ],
                    "atomic-profile",
                    NOW,
                    self.policy_fingerprint,
                    processing_complete=True,
                )
            summary = store.shadow_scan_summary(
                self.policy.account_id, "atomic-profile"
            )

        self.assertEqual(summary["processed_total"], 0)
        self.assertEqual(summary["retryable_incomplete"], 0)

    def test_incomplete_shadow_rows_are_retried_and_not_counted_complete(self) -> None:
        message = make_message(message_id="retry-incomplete")
        mailbox = ProgressiveFakeMailbox([message])
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "retry.sqlite3", b"r" * 32)
            first = run_shadow_scan(
                self.policy,
                mailbox,
                CountingClassifier(),
                NOW,
                1,
                1,
                store,
                "retry-profile",
                defer_completion=True,
            )
            incomplete = store.shadow_scan_summary(
                self.policy.account_id, "retry-profile"
            )
            second = run_shadow_scan(
                self.policy,
                mailbox,
                CountingClassifier(),
                NOW,
                1,
                1,
                store,
                "retry-profile",
            )
            complete = store.shadow_scan_summary(
                self.policy.account_id, "retry-profile"
            )

        self.assertEqual(len(first), 1)
        self.assertEqual(incomplete["processed_total"], 0)
        self.assertEqual(incomplete["retryable_incomplete"], 1)
        self.assertEqual(len(second), 1)
        self.assertEqual(complete["processed_total"], 1)
        self.assertEqual(complete["retryable_incomplete"], 0)

    def test_policy_fingerprint_change_reprocesses_a_complete_row(self) -> None:
        message = make_message(message_id="policy-rescan")
        mailbox = ProgressiveFakeMailbox([message])
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "policy.sqlite3", b"p" * 32)
            store.record_shadow_scan(
                message,
                Classification(EmailCategory.ADVERTISING, 0.99, ("old",), "old"),
                PolicyDecision(PolicyAction.QUARANTINE, ("old",)),
                "policy-profile",
                NOW,
                "0" * 64,
            )
            results = run_shadow_scan(
                self.policy,
                mailbox,
                CountingClassifier(),
                NOW,
                1,
                1,
                store,
                "policy-profile",
            )
            record = store.shadow_record_for_message_id(
                self.policy.account_id,
                self.policy.provider,
                message.message_id,
                "policy-profile",
            )

        self.assertEqual(len(results), 1)
        self.assertEqual(record, ("uncertain", "review"))

    def test_policy_engine_version_is_part_of_the_safety_fingerprint(self) -> None:
        current = policy_safety_fingerprint(self.policy)
        with mock.patch.object(
            config_module,
            "SAFETY_POLICY_ENGINE_VERSION",
            "future-policy-engine",
        ):
            future = policy_safety_fingerprint(self.policy)

        self.assertNotEqual(current, future)

    def test_missing_threat_ledger_reopens_completed_shadow_rows(self) -> None:
        message = make_message(message_id="legacy-without-threat-ledger")
        profile = "gemma26-policy-v2"
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "missing-threat.sqlite3"
            key = b"h" * 32
            store = PreferenceStore(database, key, self.policy.account_id)
            store.record_shadow_scan(
                message,
                Classification(EmailCategory.ADVERTISING, 0.99, ("test",), "test"),
                PolicyDecision(PolicyAction.QUARANTINE, ("test",)),
                profile,
                NOW,
                self.policy_fingerprint,
            )
            with closing(sqlite3.connect(database)) as connection:
                with connection:
                    connection.execute("DROP TABLE threat_assessment")

            migrated = PreferenceStore(database, key, self.policy.account_id)
            with closing(sqlite3.connect(database)) as connection:
                state = connection.execute(
                    "SELECT processing_complete FROM shadow_scan"
                ).fetchone()
                threat_table = connection.execute(
                    "SELECT 1 FROM sqlite_master "
                    "WHERE type = 'table' AND name = 'threat_assessment'"
                ).fetchone()
            membership = migrated.shadow_scan_membership_checker(
                self.policy.account_id,
                self.policy.provider,
                profile,
                self.policy_fingerprint,
            )
            is_member = membership(message.message_id)

        self.assertEqual(state, (0,))
        self.assertIsNotNone(threat_table)
        self.assertFalse(is_member)

    def test_legacy_shadow_rows_without_hard_protection_fail_closed_until_rescan(self) -> None:
        message = make_message(message_id="legacy-protected-review")
        classification = Classification(
            EmailCategory.ADVERTISING, 0.99, ("test",), "test"
        )
        decision = PolicyDecision(PolicyAction.REVIEW, ("protected_keyword",))
        profile = "gemma26-policy-v2"
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "legacy-shadow.sqlite3"
            key = b"m" * 32
            store = PreferenceStore(database, key, self.policy.account_id)
            store.record_shadow_scan(
                message,
                classification,
                decision,
                profile,
                NOW,
                self.policy_fingerprint,
            )
            store.record_quiz_answer(
                message,
                classification,
                "dont_keep",
                None,
                NOW,
            )
            record_completed_threat_assessment(store, message, profile)

            # Rebuild just this table as the immediately preceding schema: it
            # already knew fingerprints and completion, but not hard_protected.
            with closing(sqlite3.connect(database)) as connection:
                with connection:
                    connection.execute(
                        "ALTER TABLE shadow_scan RENAME TO shadow_scan_with_hard"
                    )
                    connection.execute(
                        """
                        CREATE TABLE shadow_scan (
                            account_id TEXT NOT NULL,
                            message_hash TEXT NOT NULL,
                            scan_profile TEXT NOT NULL,
                            scanned_at TEXT NOT NULL,
                            category TEXT NOT NULL,
                            suggested_action TEXT NOT NULL,
                            reason_codes TEXT,
                            policy_fingerprint TEXT,
                            processing_complete INTEGER NOT NULL DEFAULT 0,
                            PRIMARY KEY (account_id, message_hash, scan_profile)
                        )
                        """
                    )
                    connection.execute(
                        """
                        INSERT INTO shadow_scan(
                            account_id, message_hash, scan_profile, scanned_at,
                            category, suggested_action, reason_codes,
                            policy_fingerprint, processing_complete
                        )
                        SELECT account_id, message_hash, scan_profile, scanned_at,
                               category, suggested_action, reason_codes,
                               policy_fingerprint, processing_complete
                        FROM shadow_scan_with_hard
                        """
                    )
                    connection.execute("DROP TABLE shadow_scan_with_hard")

            migrated = PreferenceStore(database, key, self.policy.account_id)
            with closing(sqlite3.connect(database)) as connection:
                migrated_state = connection.execute(
                    "SELECT processing_complete, hard_protected FROM shadow_scan"
                ).fetchone()
            membership = migrated.shadow_scan_membership_checker(
                self.policy.account_id,
                self.policy.provider,
                profile,
                self.policy_fingerprint,
            )
            selected = prepare_automatic_quarantine_ids(
                self.policy,
                ProgressiveFakeMailbox([message]),
                migrated,
                NOW,
                5,
                10,
                profile,
            )

        self.assertEqual(migrated_state, (0, 1))
        self.assertFalse(membership(message.message_id))
        self.assertEqual(selected, [])

    def test_operational_selector_requires_shadow_and_explicit_dont_keep(self) -> None:
        verified = make_message(message_id="verified")
        protected = make_message(message_id="protected")
        mailbox = ProgressiveFakeMailbox([verified, protected])
        classification = Classification(
            EmailCategory.ADVERTISING,
            0.99,
            ("test",),
            "test",
        )
        decision = PolicyDecision(PolicyAction.QUARANTINE, ("test",))
        profile = "gemma26-policy-v2"
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "pilot.sqlite3", b"v" * 32)
            for message in (verified, protected):
                store.record_shadow_scan(
                    message,
                    classification,
                    decision,
                    profile,
                    NOW,
                    self.policy_fingerprint,
                )
                record_completed_threat_assessment(store, message, profile)
            store.record_quiz_answer(verified, classification, "dont_keep", None)
            store.record_quiz_answer(protected, classification, "keep", None)

            selected = prepare_verified_quarantine_ids(
                self.policy,
                mailbox,
                store,
                NOW,
                limit=5,
                search_limit=10,
                scan_profile=profile,
            )
            candidates = prepare_verified_quarantine_candidates(
                self.policy,
                mailbox,
                store,
                NOW,
                limit=5,
                search_limit=10,
                scan_profile=profile,
            )
            store.record_quarantine_pilot_execution(
                self.policy.account_id,
                self.policy.provider,
                "verified",
                profile,
                NOW,
                "applied",
            )
            selected_after_execution = prepare_verified_quarantine_ids(
                self.policy,
                mailbox,
                store,
                NOW,
                limit=5,
                search_limit=10,
                scan_profile=profile,
            )

        self.assertEqual(selected, ["verified"])
        self.assertEqual(
            [(candidate.message_id, candidate.expected_unread) for candidate in candidates],
            [("verified", True)],
        )
        self.assertEqual(selected_after_execution, [])

    def test_the_whole_batch_path_accepts_the_largest_saveable_batch(self) -> None:
        """Every bound a scan batch passes through has to admit the ceiling.

        The batch ceiling was raised in the settings, the policy files and the
        GUI, but four validations below them kept their own literal 500. A
        scheduled run then died partway through, after reading hundreds of
        messages and before changing anything, which is the most expensive
        place to fail and the least visible.
        """

        from inboxlume.providers.gmail import GmailReadOnlyMailbox
        from inboxlume.providers.yahoo import YahooReadOnlyMailbox
        from inboxlume.settings import (
            MAX_RECOVERY_SEARCH_LIMIT,
            MAX_SCAN_BATCH_SIZE,
        )

        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "ceiling.sqlite3", b"c" * 32)
            self.assertEqual(
                prepare_automatic_quarantine_candidates(
                    self.policy,
                    ProgressiveFakeMailbox([]),
                    store,
                    NOW,
                    limit=MAX_SCAN_BATCH_SIZE,
                    search_limit=MAX_RECOVERY_SEARCH_LIMIT,
                    scan_profile="gemma26-policy-v2",
                ),
                [],
            )

        # The provider selection is the layer under it. Validation runs before
        # the transport is touched, so an unconstructed mailbox reaches it: at
        # the ceiling the size check has to pass and let the call fail on the
        # missing transport instead.
        for mailbox_class in (YahooReadOnlyMailbox, GmailReadOnlyMailbox):
            with self.subTest(provider=mailbox_class.__name__):
                selection = object.__new__(mailbox_class).iter_inbox_matching_candidate_ids(
                    NOW,
                    NOW,
                    NOW,
                    MAX_SCAN_BATCH_SIZE,
                    MAX_RECOVERY_SEARCH_LIMIT,
                    lambda message_id, unread: True,
                )
                with self.assertRaises(AttributeError):
                    next(selection)

                refused = object.__new__(mailbox_class).iter_inbox_matching_candidate_ids(
                    NOW,
                    NOW,
                    NOW,
                    MAX_SCAN_BATCH_SIZE + 1,
                    MAX_RECOVERY_SEARCH_LIMIT,
                    lambda message_id, unread: True,
                )
                with self.assertRaises(ValueError):
                    next(refused)

                # The duration estimate counts how much of a configured batch
                # is still waiting, so a batch it refuses to count leaves the
                # estimate broken for exactly the batches worth estimating.
                counter = object.__new__(mailbox_class)
                with self.assertRaises(AttributeError):
                    counter.count_inbox_unprocessed_candidate_ids(
                        NOW,
                        NOW,
                        NOW,
                        lambda message_id: False,
                        maximum=MAX_SCAN_BATCH_SIZE,
                    )
                with self.assertRaises(ValueError):
                    counter.count_inbox_unprocessed_candidate_ids(
                        NOW,
                        NOW,
                        NOW,
                        lambda message_id: False,
                        maximum=MAX_SCAN_BATCH_SIZE + 1,
                    )

    def test_automatic_selector_needs_no_quiz_but_respects_protect(self) -> None:
        automatic = make_message(message_id="automatic")
        protected = make_message(message_id="protected-automatic")
        mailbox = ProgressiveFakeMailbox([automatic, protected])
        classification = Classification(
            EmailCategory.ADVERTISING, 0.99, ("test",), "test"
        )
        decision = PolicyDecision(PolicyAction.QUARANTINE, ("test",))
        profile = "gemma26-policy-v2"
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "automatic.sqlite3", b"q" * 32)
            store.record_shadow_scan(
                automatic, classification, decision, profile, NOW, self.policy_fingerprint
            )
            store.record_shadow_scan(
                protected, classification, decision, profile, NOW, self.policy_fingerprint
            )
            record_completed_threat_assessment(store, automatic, profile)
            record_completed_threat_assessment(store, protected, profile)
            store.record_quiz_answer(protected, classification, "keep", None)
            selected = prepare_automatic_quarantine_ids(
                self.policy,
                mailbox,
                store,
                NOW,
                limit=5,
                search_limit=10,
                scan_profile=profile,
            )
            blocked_by_family_gate = prepare_automatic_quarantine_ids(
                self.policy,
                mailbox,
                store,
                NOW,
                limit=5,
                search_limit=10,
                scan_profile=profile,
                allowed_categories=frozenset({"spam"}),
            )
            candidates = prepare_automatic_quarantine_candidates(
                self.policy,
                mailbox,
                store,
                NOW,
                limit=5,
                search_limit=10,
                scan_profile=profile,
            )

        self.assertEqual(selected, ["automatic"])
        self.assertEqual(blocked_by_family_gate, [])
        self.assertEqual(
            [(candidate.message_id, candidate.expected_unread) for candidate in candidates],
            [("automatic", True)],
        )

    def test_recovery_candidates_preserve_read_and_unread_expectations(self) -> None:
        unread = make_message(message_id="recovered-unread", unread=True)
        read = make_message(message_id="recovered-read", unread=False)
        mailbox = ProgressiveFakeMailbox([unread, read])
        classification = Classification(
            EmailCategory.ADVERTISING, 0.99, ("test",), "test"
        )
        profile = "gemma26-policy-v2"
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "candidate-state.sqlite3", b"c" * 32)
            for message in (unread, read):
                message_classification = (
                    classification
                    if message.unread
                    else Classification(
                        EmailCategory.ONE_TIME_CODE,
                        0.99,
                        ("test",),
                        "test",
                    )
                )
                reasons = (
                    ("test",)
                    if message.unread
                    else ("expired_read_one_time_code",)
                )
                store.record_shadow_scan(
                    message,
                    message_classification,
                    PolicyDecision(PolicyAction.QUARANTINE, reasons),
                    profile,
                    NOW,
                    self.policy_fingerprint,
                )
                record_completed_threat_assessment(store, message, profile)

            candidates = prepare_automatic_quarantine_candidates(
                self.policy,
                mailbox,
                store,
                NOW,
                limit=5,
                search_limit=10,
                scan_profile=profile,
            )

        self.assertEqual(
            [(candidate.message_id, candidate.expected_unread) for candidate in candidates],
            [("recovered-unread", True), ("recovered-read", False)],
        )

    def test_recovery_fails_closed_when_threat_assessment_did_not_commit(self) -> None:
        incomplete = make_message(message_id="incomplete-threat-boundary")
        mailbox = ProgressiveFakeMailbox([incomplete])
        classification = Classification(
            EmailCategory.ADVERTISING, 0.99, ("test",), "test"
        )
        profile = "gemma26-policy-v2"
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "incomplete.sqlite3", b"i" * 32)
            store.record_shadow_scan(
                incomplete,
                classification,
                PolicyDecision(PolicyAction.QUARANTINE, ("test",)),
                profile,
                NOW,
                self.policy_fingerprint,
            )

            automatic = prepare_automatic_quarantine_ids(
                self.policy, mailbox, store, NOW, 5, 10, profile
            )
            store.record_quiz_answer(incomplete, classification, "dont_keep", None)
            verified = prepare_verified_quarantine_ids(
                self.policy, mailbox, store, NOW, 5, 10, profile
            )
            store.record_quarantine_pilot_execution(
                self.policy.account_id,
                self.policy.provider,
                incomplete.message_id,
                profile,
                NOW - timedelta(days=3),
                "applied",
            )
            mature = prepare_mature_quarantine_candidates(
                self.policy, mailbox, store, NOW, 5, 10, profile
            )

        self.assertEqual(automatic, [])
        self.assertEqual(verified, [])
        self.assertEqual(mature, [])

    def test_disabled_threat_attestation_is_explicit_and_reset_on_reenable(self) -> None:
        message = make_message(message_id="threat-disabled-retry")
        mailbox = ProgressiveFakeMailbox([message])
        classification = Classification(
            EmailCategory.ADVERTISING, 0.99, ("test",), "test"
        )
        profile = "gemma26-policy-v2"
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "disabled.sqlite3", b"d" * 32)
            store.record_shadow_scan(
                message,
                classification,
                PolicyDecision(PolicyAction.QUARANTINE, ("test",)),
                profile,
                NOW,
                self.policy_fingerprint,
            )
            store.record_disabled_threat_assessment_batch([message], profile, NOW)

            fail_closed = prepare_automatic_quarantine_ids(
                self.policy, mailbox, store, NOW, 5, 10, profile
            )
            disabled_retry = prepare_automatic_quarantine_ids(
                self.policy,
                mailbox,
                store,
                NOW,
                5,
                10,
                profile,
                allow_disabled_threat_assessment=True,
            )
            reset = store.reset_disabled_threat_assessments(
                self.policy.account_id, profile
            )
            membership = store.shadow_scan_membership_checker(
                self.policy.account_id,
                self.policy.provider,
                profile,
                self.policy_fingerprint,
            )

        self.assertEqual(fail_closed, [])
        self.assertEqual(disabled_retry, [message.message_id])
        self.assertEqual(reset, 1)
        self.assertFalse(membership(message.message_id))

    def test_recovery_rejects_a_read_proposal_that_became_unread(self) -> None:
        recorded = make_message(message_id="access-race", unread=False)
        current = make_message(message_id="access-race", unread=True)
        mailbox = ProgressiveFakeMailbox([current])
        classification = Classification(
            EmailCategory.SECURITY, 0.99, ("test",), "test"
        )
        profile = "gemma26-policy-v2"
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "read-race.sqlite3", b"s" * 32)
            store.record_shadow_scan(
                recorded,
                classification,
                PolicyDecision(
                    PolicyAction.QUARANTINE,
                    ("expired_read_routine_access_alert",),
                ),
                profile,
                NOW,
                self.policy_fingerprint,
            )
            record_completed_threat_assessment(store, recorded, profile)

            selected = prepare_automatic_quarantine_ids(
                self.policy, mailbox, store, NOW, 5, 10, profile
            )

        self.assertEqual(selected, [])

    def test_recovery_rejects_a_proposal_from_an_old_policy(self) -> None:
        message = make_message(
            message_id="stale-policy",
            subject="Project Phoenix newsletter",
        )
        mailbox = ProgressiveFakeMailbox([message])
        classification = Classification(
            EmailCategory.ADVERTISING, 0.99, ("test",), "test"
        )
        profile = "gemma26-policy-v2"
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "policy-race.sqlite3", b"p" * 32)
            store.record_shadow_scan(
                message,
                classification,
                PolicyDecision(PolicyAction.QUARANTINE, ("test",)),
                profile,
                NOW,
                self.policy_fingerprint,
            )
            record_completed_threat_assessment(store, message, profile)
            changed_policy = replace(
                self.policy,
                protected_keywords=frozenset({"project phoenix"}),
            )

            selected = prepare_automatic_quarantine_ids(
                changed_policy, mailbox, store, NOW, 5, 10, profile
            )

        self.assertEqual(selected, [])

    def test_explicit_discard_promotes_only_cleanup_review(self) -> None:
        advertising = make_message(message_id="reviewed-advertising")
        protected = make_message(message_id="reviewed-banking")
        mailbox = ProgressiveFakeMailbox([advertising, protected])
        profile = "gemma26-policy-v2"
        review = PolicyDecision(PolicyAction.REVIEW, ("borderline",))
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "review.sqlite3", b"r" * 32)
            advertising_classification = Classification(
                EmailCategory.ADVERTISING, 0.79, ("test",), "test"
            )
            protected_classification = Classification(
                EmailCategory.BANKING, 0.79, ("test",), "test"
            )
            store.record_shadow_scan(
                advertising,
                advertising_classification,
                review,
                profile,
                NOW,
                self.policy_fingerprint,
            )
            store.record_shadow_scan(
                protected,
                protected_classification,
                review,
                profile,
                NOW,
                self.policy_fingerprint,
            )
            record_completed_threat_assessment(store, advertising, profile)
            record_completed_threat_assessment(store, protected, profile)
            store.record_quiz_answer(
                advertising, advertising_classification, "dont_keep", None
            )
            store.record_quiz_answer(
                protected, protected_classification, "dont_keep", None
            )

            selected = prepare_automatic_quarantine_ids(
                self.policy, mailbox, store, NOW, 5, 10, profile
            )

        self.assertEqual(selected, ["reviewed-advertising"])

    def test_protected_review_never_becomes_cleanup_or_governor_evidence(self) -> None:
        message = make_message(message_id="protected-review")
        mailbox = ProgressiveFakeMailbox([message])
        classification = Classification(
            EmailCategory.ADVERTISING, 0.99, ("test",), "test"
        )
        profile = "gemma26-policy-v2"
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "hard-review.sqlite3", b"h" * 32)
            store.record_shadow_scan(
                message,
                classification,
                PolicyDecision(PolicyAction.REVIEW, ("protected_keyword",)),
                profile,
                NOW,
                self.policy_fingerprint,
            )
            record_completed_threat_assessment(store, message, profile)
            store.record_quiz_answer(message, classification, "dont_keep", None)

            selected = prepare_automatic_quarantine_ids(
                self.policy, mailbox, store, NOW, 5, 10, profile
            )
            evidence = store.shadow_quarantine_evidence_by_category(
                self.policy.account_id, profile
            )

        self.assertEqual(selected, [])
        self.assertEqual(evidence, {})

    def test_yahoo_quarantine_folder_excludes_unlinked_manual_messages(self) -> None:
        policy = load_policies(ROOT / "config/accounts.example.json")[
            "yahoo_personale"
        ]
        message = make_message(
            account_id=policy.account_id,
            provider=ProviderKind.YAHOO,
            message_id="888:3",
            sender="Offerte <private@example.invalid>",
            subject="Offerta privata",
            body_text="Testo privato",
        )
        profile = "gemma26-policy-v2"
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "yahoo.sqlite3"
            store = PreferenceStore(database, b"y" * 32)
            candidates = prepare_quarantine_shadow_review(
                policy,
                FakeQuarantineMailbox([message]),
                store,
                NOW,
                5,
                10,
                profile,
            )
            summary = store.shadow_quarantine_label_summary(
                policy.account_id,
                profile,
            )
            database_bytes = database.read_bytes()

        self.assertEqual(len(candidates), 0)
        self.assertEqual(summary["unreviewed"], 0)
        self.assertNotIn(b"private@example.invalid", database_bytes)
        self.assertNotIn(b"Testo privato", database_bytes)

    def test_a_moved_proposal_stays_reviewable_after_its_uid_changes(self) -> None:
        policy = load_policies(ROOT / "config/accounts.example.json")[
            "yahoo_personale"
        ]
        profile = "gemma26-policy-v2"
        identity = "<moved-proposal@example.invalid>"
        in_inbox = make_message(
            account_id=policy.account_id,
            provider=ProviderKind.YAHOO,
            message_id="777:41",
            headers={"Message-ID": identity},
            subject="Promozione",
            body_text="Testo promozionale.",
        )
        # A move gives the message a new UID in the destination folder, so the
        # scan's identity no longer matches anything the review can see.
        after_move = make_message(
            account_id=policy.account_id,
            provider=ProviderKind.YAHOO,
            message_id="999:7",
            headers={"Message-ID": identity},
            subject="Promozione",
            body_text="Testo promozionale.",
        )
        classification = Classification(
            EmailCategory.ADVERTISING, 0.96, ("test",), "test"
        )
        quarantine = PolicyDecision(PolicyAction.QUARANTINE, ("ordinary_cleanup",))
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "moved.sqlite3"
            store = PreferenceStore(database, b"z" * 32)
            store.record_shadow_scan(
                in_inbox,
                classification,
                quarantine,
                profile,
                NOW,
                policy_safety_fingerprint(policy),
            )

            self.assertIsNone(
                store.shadow_record_for_message_id(
                    policy.account_id,
                    ProviderKind.YAHOO,
                    after_move.message_id,
                    profile,
                )
            )

            candidates = prepare_quarantine_shadow_review(
                policy,
                FakeQuarantineMailbox([after_move]),
                store,
                NOW,
                5,
                10,
                profile,
            )
            database_bytes = database.read_bytes()

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].message.message_id, "999:7")
        # The identity is evidence, not text: it must never be stored readable.
        self.assertNotIn(identity.encode(), database_bytes)

    def test_a_proposal_already_answered_is_not_asked_again(self) -> None:
        policy = load_policies(ROOT / "config/accounts.example.json")[
            "yahoo_personale"
        ]
        profile = "gemma26-policy-v2"
        identity = "<already-answered@example.invalid>"
        in_inbox = make_message(
            account_id=policy.account_id,
            provider=ProviderKind.YAHOO,
            message_id="777:42",
            headers={"Message-ID": identity},
            subject="Promozione",
            body_text="Testo promozionale.",
        )
        after_move = make_message(
            account_id=policy.account_id,
            provider=ProviderKind.YAHOO,
            message_id="999:9",
            headers={"Message-ID": identity},
            subject="Promozione",
            body_text="Testo promozionale.",
        )
        classification = Classification(
            EmailCategory.ADVERTISING, 0.96, ("test",), "test"
        )
        quarantine = PolicyDecision(PolicyAction.QUARANTINE, ("ordinary_cleanup",))
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "answered.sqlite3", b"q" * 32)
            store.record_shadow_scan(
                in_inbox,
                classification,
                quarantine,
                profile,
                NOW,
                policy_safety_fingerprint(policy),
            )
            store.record_quiz_answer(in_inbox, classification, "keep", None)

            candidates = prepare_quarantine_shadow_review(
                policy,
                FakeQuarantineMailbox([after_move]),
                store,
                NOW,
                5,
                10,
                profile,
            )

        # The answer was recorded against the Inbox identity, so relocating by
        # Message-ID must carry that answer across the move as well.
        self.assertEqual(candidates, [])

    def test_a_message_never_proposed_stays_out_of_the_review(self) -> None:
        policy = load_policies(ROOT / "config/accounts.example.json")[
            "yahoo_personale"
        ]
        stranger = make_message(
            account_id=policy.account_id,
            provider=ProviderKind.YAHOO,
            message_id="999:8",
            headers={"Message-ID": "<never-proposed@example.invalid>"},
            subject="Estraneo",
            body_text="Messaggio mai proposto.",
        )
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "stranger.sqlite3", b"k" * 32)
            candidates = prepare_quarantine_shadow_review(
                policy,
                FakeQuarantineMailbox([stranger]),
                store,
                NOW,
                5,
                10,
                "gemma26-policy-v2",
            )

        # Relocating by Message-ID must not turn a manually filed message into
        # InboxLume evidence.
        self.assertEqual(candidates, [])

    def test_verified_obsolescence_recovers_review_only_for_quarantine(self) -> None:
        message = make_message(message_id="obsolete-review")
        mailbox = ProgressiveFakeMailbox([message])
        classification = Classification(
            EmailCategory.ADVERTISING, 0.96, ("test",), "test"
        )
        review = PolicyDecision(PolicyAction.REVIEW, ("ordinary_review",))
        proof = ObsolescenceProof(
            ProofStatus.VERIFIED,
            ClosureWitness.MULTI_SIGNAL_CONSENSUS,
            ProofDestination.QUARANTINE,
            ("model_discard", "repeated_corrections", "current_regime_agrees"),
            9,
        )
        profile = "gemma26-policy-v2"
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "proof.sqlite3", b"o" * 32)
            store.record_shadow_scan(
                message, classification, review, profile, NOW, self.policy_fingerprint
            )
            record_completed_threat_assessment(store, message, profile)
            store.record_obsolescence_proof(message, profile, proof, NOW)
            ordinary = prepare_automatic_quarantine_ids(
                self.policy, mailbox, store, NOW, 5, 10, profile
            )
            proof_enabled = prepare_automatic_quarantine_ids(
                self.policy,
                mailbox,
                store,
                NOW,
                5,
                10,
                profile,
                include_verified_obsolescence=True,
            )

        self.assertEqual(ordinary, [])
        self.assertEqual(proof_enabled, ["obsolete-review"])

    def test_finalization_selector_requires_three_days_and_can_run_only_once(self) -> None:
        message = make_message(message_id="mature")
        mailbox = ProgressiveFakeMailbox([message])
        classification = Classification(
            EmailCategory.ADVERTISING,
            0.99,
            ("test",),
            "test",
        )
        decision = PolicyDecision(PolicyAction.QUARANTINE, ("test",))
        profile = "gemma26-policy-v2"
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "final.sqlite3", b"f" * 32)
            store.record_shadow_scan(
                message, classification, decision, profile, NOW, self.policy_fingerprint
            )
            record_completed_threat_assessment(store, message, profile)
            store.record_quarantine_pilot_execution(
                self.policy.account_id,
                self.policy.provider,
                message.message_id,
                profile,
                NOW - timedelta(days=3),
                "applied",
            )

            selected = prepare_mature_quarantine_candidates(
                self.policy,
                mailbox,
                store,
                NOW,
                limit=5,
                search_limit=10,
                scan_profile=profile,
            )
            store.record_quarantine_finalization(
                self.policy.account_id,
                self.policy.provider,
                message.message_id,
                profile,
                NOW,
                "moved_to_trash",
            )
            selected_after_finalization = prepare_mature_quarantine_candidates(
                self.policy,
                mailbox,
                store,
                NOW,
                limit=5,
                search_limit=10,
                scan_profile=profile,
            )

        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0].message_id, "mature")
        self.assertTrue(selected[0].expected_unread)
        self.assertEqual(selected_after_finalization, [])

    def test_finalization_selector_preserves_expected_read_state(self) -> None:
        message = make_message(message_id="mature-read-otp", unread=False)
        mailbox = ProgressiveFakeMailbox([message])
        classification = Classification(
            EmailCategory.ONE_TIME_CODE,
            0.99,
            ("test",),
            "test",
        )
        decision = PolicyDecision(
            PolicyAction.QUARANTINE,
            ("expired_read_one_time_code",),
        )
        profile = "gemma26-policy-v2"
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "mature-read.sqlite3", b"m" * 32)
            store.record_shadow_scan(
                message,
                classification,
                decision,
                profile,
                NOW,
                self.policy_fingerprint,
            )
            record_completed_threat_assessment(store, message, profile)
            store.record_quarantine_pilot_execution(
                self.policy.account_id,
                self.policy.provider,
                message.message_id,
                profile,
                NOW - timedelta(days=3),
                "applied",
            )

            selected = prepare_mature_quarantine_candidates(
                self.policy,
                mailbox,
                store,
                NOW,
                limit=5,
                search_limit=10,
                scan_profile=profile,
            )

        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0].message_id, "mature-read-otp")
        self.assertFalse(selected[0].expected_unread)

    def test_finalization_selector_excludes_quarantine_younger_than_three_days(self) -> None:
        message = make_message(message_id="too-recent")
        mailbox = ProgressiveFakeMailbox([message])
        classification = Classification(
            EmailCategory.ADVERTISING,
            0.99,
            ("test",),
            "test",
        )
        decision = PolicyDecision(PolicyAction.QUARANTINE, ("test",))
        profile = "gemma26-policy-v2"
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "recent.sqlite3", b"r" * 32)
            store.record_shadow_scan(
                message, classification, decision, profile, NOW, self.policy_fingerprint
            )
            record_completed_threat_assessment(store, message, profile)
            store.record_quiz_answer(message, classification, "dont_keep", None)
            store.record_quarantine_pilot_execution(
                self.policy.account_id,
                self.policy.provider,
                message.message_id,
                profile,
                NOW - timedelta(days=3) + timedelta(seconds=1),
                "applied",
            )
            selected = prepare_mature_quarantine_candidates(
                self.policy,
                mailbox,
                store,
                NOW,
                limit=5,
                search_limit=10,
                scan_profile=profile,
            )

        self.assertEqual(selected, [])

    def test_optional_quiz_protect_cancels_mature_finalization(self) -> None:
        message = make_message(message_id="protected-after-quarantine")
        mailbox = ProgressiveFakeMailbox([message])
        classification = Classification(
            EmailCategory.ADVERTISING, 0.99, ("test",), "test"
        )
        decision = PolicyDecision(PolicyAction.QUARANTINE, ("test",))
        profile = "gemma26-policy-v2"
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "protected.sqlite3", b"p" * 32)
            store.record_shadow_scan(
                message, classification, decision, profile, NOW, self.policy_fingerprint
            )
            record_completed_threat_assessment(store, message, profile)
            store.record_quarantine_pilot_execution(
                self.policy.account_id,
                self.policy.provider,
                message.message_id,
                profile,
                NOW - timedelta(days=3),
                "applied",
            )
            store.record_quiz_answer(message, classification, "keep", None)
            selected = prepare_mature_quarantine_candidates(
                self.policy,
                mailbox,
                store,
                NOW,
                limit=5,
                search_limit=10,
                scan_profile=profile,
            )

        self.assertEqual(selected, [])


if __name__ == "__main__":
    unittest.main()
