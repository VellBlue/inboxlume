from __future__ import annotations

import unittest
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from inboxlume.classifier import HeuristicClassifier
from inboxlume.cli import (
    _apply_shadow_quarantine_candidates,
    _apply_shadow_quarantine_results,
    _build_classifier,
    evaluate_jsonl,
    gmail_calibration_quiz,
    gmail_shadow_run,
    main,
    summarize_dry_run,
    yahoo_shadow_run,
)
from inboxlume.learning import PreferenceStore
from inboxlume.models import (
    Classification,
    EmailCategory,
    PolicyAction,
    PolicyDecision,
    ProviderKind,
)
from inboxlume.pipeline import DryRunResult, InboxMutationCandidate
from inboxlume.providers.contracts import READ_ONLY_CAPABILITIES
from inboxlume.providers.gmail_quarantine import (
    QuarantineOutcome,
    QuarantineResult,
)

from tests.helpers import make_message


ROOT = Path(__file__).resolve().parents[1]


class FakeSecretStore:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get(self, service: str, account: str) -> str | None:
        return self.values.get((service, account))

    def set(self, service: str, account: str, secret: str) -> None:
        self.values[(service, account)] = secret


class FakeMailbox:
    capabilities = READ_ONLY_CAPABILITIES

    def __init__(self, messages):  # noqa: ANN001
        self.messages = list(messages)

    def iter_inbox_unread_before(self, before, limit):  # noqa: ANN001
        yield from self.messages[:limit]

    def iter_inbox_read_one_time_code_candidates_before(self, before, limit):  # noqa: ANN001
        yield from ()

    def iter_inbox_quiz_sample(  # noqa: ANN001
        self, limit, old_unread_before=None, skip_message_id=None, search_limit=None
    ):
        messages = (
            message for message in self.messages
            if skip_message_id is None or not skip_message_id(message.message_id)
        )
        yield from list(messages)[:limit]


class FakeQuarantineExecutor:
    def __init__(self) -> None:
        self.candidates: list[tuple[str, bool]] = []

    def apply_label_quarantine(
        self,
        message_id: str,
        expected_unread: bool,
    ) -> QuarantineResult:
        self.candidates.append((message_id, expected_unread))
        return QuarantineResult(QuarantineOutcome.APPLIED)


class CliTests(unittest.TestCase):
    def test_gemma12_backend_uses_the_controlled_mlx_worker(self) -> None:
        with patch("inboxlume.cli.MlxWorkerClassifier") as worker:
            classifier, local = _build_classifier("gemma12", "qwen3-vl:8b")

        worker.assert_called_once_with("gemma12")
        self.assertIs(local, worker.return_value)
        self.assertIs(classifier.local_model, worker.return_value)

    def test_automatic_quarantine_uses_model_decision_without_quiz(self) -> None:
        quarantine = make_message(message_id="automatic-quarantine")
        keep = make_message(message_id="automatic-keep")
        classification = Classification(
            EmailCategory.ADVERTISING, 0.99, ("test",), "test"
        )
        results = [
            DryRunResult(
                quarantine,
                classification,
                PolicyDecision(PolicyAction.QUARANTINE, ("test",)),
                90,
            ),
            DryRunResult(
                keep,
                classification,
                PolicyDecision(PolicyAction.KEEP, ("test",)),
                90,
            ),
        ]
        executor = FakeQuarantineExecutor()
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "auto.sqlite3", b"a" * 32)
            summary = _apply_shadow_quarantine_results(
                results,
                store,
                "gmail_personale",
                ProviderKind.GMAIL,
                "gemma26-policy-v2",
                datetime(2026, 8, 30, tzinfo=timezone.utc),
                executor.apply_label_quarantine,
            )
            retry = _apply_shadow_quarantine_results(
                results,
                store,
                "gmail_personale",
                ProviderKind.GMAIL,
                "gemma26-policy-v2",
                datetime(2026, 8, 30, tzinfo=timezone.utc),
                executor.apply_label_quarantine,
            )

        self.assertEqual(
            executor.candidates,
            [("automatic-quarantine", quarantine.unread)],
        )
        self.assertEqual(summary["applied"], 1)
        self.assertEqual(retry["selected"], 0)

    def test_operational_governor_filters_before_mailbox_mutation(self) -> None:
        message = make_message(message_id="governor-blocked")
        result = DryRunResult(
            message,
            Classification(
                EmailCategory.ADVERTISING,
                0.99,
                ("test",),
                "test",
            ),
            PolicyDecision(PolicyAction.QUARANTINE, ("test",)),
            90,
        )
        executor = FakeQuarantineExecutor()
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "governed.sqlite3", b"g" * 32)
            summary = _apply_shadow_quarantine_results(
                [result],
                store,
                "gmail_personale",
                ProviderKind.GMAIL,
                "gemma26-policy-v2",
                datetime(2026, 8, 30, tzinfo=timezone.utc),
                executor.apply_label_quarantine,
                allowed_categories=frozenset(),
            )

        self.assertEqual(summary["selected"], 0)
        self.assertEqual(executor.candidates, [])

    def test_recovered_candidates_reach_executor_with_expected_read_state(self) -> None:
        executor = FakeQuarantineExecutor()
        candidates = [
            InboxMutationCandidate("recovered-unread", True),
            InboxMutationCandidate("recovered-read", False),
        ]
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "recovered.sqlite3", b"r" * 32)
            summary = _apply_shadow_quarantine_candidates(
                candidates,
                store,
                "gmail_personale",
                ProviderKind.GMAIL,
                "gemma26-policy-v2",
                datetime(2026, 8, 30, tzinfo=timezone.utc),
                executor.apply_label_quarantine,
            )

        self.assertEqual(executor.candidates, [
            ("recovered-unread", True),
            ("recovered-read", False),
        ])
        self.assertEqual(summary["applied"], 2)

    def test_dry_run_summary_is_aggregate_only(self) -> None:
        results = [
            {
                "message_id": "private-one",
                "category": "advertising",
                "suggested_action": "quarantine",
            },
            {
                "message_id": "private-two",
                "category": "advertising",
                "suggested_action": "review",
            },
        ]
        summary = summarize_dry_run(results)
        self.assertEqual(summary["categories"], {"advertising": 2})
        self.assertEqual(summary["suggested_actions"], {"quarantine": 1, "review": 1})
        self.assertNotIn("message_id", summary)
        self.assertNotIn("private-one", str(summary))

    def test_gmail_dry_run_requires_explicit_body_confirmation(self) -> None:
        errors = StringIO()
        with redirect_stderr(errors):
            status = main(
                [
                    "gmail-dry-run",
                    "--config",
                    str(ROOT / "config/accounts.example.json"),
                    "--account",
                    "gmail_personale",
                ]
            )
        self.assertEqual(status, 2)
        self.assertIn("--confirm-read-bodies", errors.getvalue())

    def test_gmail_dry_run_stdout_omits_provider_id_and_exact_timestamp(self) -> None:
        output = StringIO()
        private_id = "provider-private-identifier"
        exact_time = "2026-08-30T11:22:33+00:00"
        result = {
            "account_id": "gmail_personale",
            "message_id": private_id,
            "received_at": exact_time,
            "age_days": 90,
            "category": "advertising",
            "retention": "uncertain",
            "suggested_action": "review",
            "dry_run": True,
            "changes_mailbox": False,
        }
        with (
            patch("inboxlume.cli.gmail_dry_run", return_value=[result]),
            redirect_stdout(output),
        ):
            status = main(
                [
                    "gmail-dry-run",
                    "--config",
                    str(ROOT / "config/accounts.example.json"),
                    "--account",
                    "gmail_personale",
                    "--confirm-read-bodies",
                ]
            )

        self.assertEqual(status, 0)
        self.assertNotIn(private_id, output.getvalue())
        self.assertNotIn(exact_time, output.getvalue())
        self.assertIn('"result_number": 1', output.getvalue())

    def test_gmail_shadow_run_requires_explicit_body_confirmation(self) -> None:
        errors = StringIO()
        with redirect_stderr(errors):
            status = main(
                [
                    "gmail-shadow-run",
                    "--config",
                    str(ROOT / "config/accounts.example.json"),
                    "--account",
                    "gmail_personale",
                ]
            )
        self.assertEqual(status, 2)
        self.assertIn("--confirm-read-bodies", errors.getvalue())

    def test_yahoo_shadow_run_requires_explicit_body_confirmation(self) -> None:
        errors = StringIO()
        with redirect_stderr(errors):
            status = main(
                [
                    "yahoo-shadow-run",
                    "--config",
                    str(ROOT / "config/accounts.example.json"),
                    "--account",
                    "yahoo_personale",
                ]
            )
        self.assertEqual(status, 2)
        self.assertIn("--confirm-read-bodies", errors.getvalue())

    def test_direct_trash_requires_provider_mutation_flag(self) -> None:
        for command, account in (
            ("gmail-shadow-run", "gmail_personale"),
            ("yahoo-shadow-run", "yahoo_personale"),
        ):
            with self.subTest(command=command):
                errors = StringIO()
                with redirect_stderr(errors):
                    status = main(
                        [
                            command,
                            "--config",
                            str(ROOT / "config/accounts.example.json"),
                            "--account",
                            account,
                            "--confirm-read-bodies",
                            "--direct-to-trash",
                        ]
                    )
                self.assertEqual(status, 2)
                self.assertIn("richiede", errors.getvalue())

    def test_legacy_shadow_commands_cannot_bypass_direct_trash_model_gate(self) -> None:
        cases = (
            ("gmail-shadow-run", "gmail_personale", "--apply-shadow-labels"),
            ("yahoo-shadow-run", "yahoo_personale", "--apply-shadow-quarantine"),
        )
        for command, account, apply_flag in cases:
            with self.subTest(command=command):
                errors = StringIO()
                runner_name = (
                    "inboxlume.cli.gmail_shadow_run"
                    if command.startswith("gmail")
                    else "inboxlume.cli.yahoo_shadow_run"
                )
                with (
                    patch(
                        "inboxlume.cli.calibration_answer_counts",
                        return_value={"keep": 3, "dont_keep": 37, "unsure": 0},
                    ),
                    patch(runner_name) as runner,
                    redirect_stderr(errors),
                ):
                    status = main(
                        [
                            command,
                            "--config",
                            str(ROOT / "config/accounts.example.json"),
                            "--account",
                            account,
                            "--backend",
                            "heuristic",
                            "--confirm-read-bodies",
                            apply_flag,
                            "--direct-to-trash",
                        ]
                    )
                self.assertEqual(status, 2)
                self.assertIn("Gemma 26B", errors.getvalue())
                runner.assert_not_called()

    def test_public_shadow_runners_enforce_direct_trash_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for runner, account in (
                (gmail_shadow_run, "gmail_personale"),
                (yahoo_shadow_run, "yahoo_personale"),
            ):
                with self.subTest(account=account), self.assertRaisesRegex(
                    ValueError, "Gemma 26B"
                ):
                    runner(
                        ROOT / "config" / "accounts.example.json",
                        account,
                        "heuristic",
                        "qwen3-vl:8b",
                        datetime(2026, 8, 30, tzinfo=timezone.utc),
                        1,
                        1,
                        Path(directory) / f"{account}.sqlite3",
                        FakeSecretStore(),
                        direct_to_trash=True,
                    )

    def test_quarantine_pilot_requires_explicit_mutation_flag(self) -> None:
        errors = StringIO()
        with redirect_stderr(errors):
            status = main(
                [
                    "gmail-quarantine-pilot",
                    "--config",
                    str(ROOT / "config/accounts.example.json"),
                    "--account",
                    "gmail_personale",
                ]
            )
        self.assertEqual(status, 2)
        self.assertIn("--apply-verified-labels", errors.getvalue())

    def test_quarantine_finalization_requires_explicit_mutation_flag(self) -> None:
        errors = StringIO()
        with redirect_stderr(errors):
            status = main(
                [
                    "gmail-finalize-quarantine",
                    "--config",
                    str(ROOT / "config/accounts.example.json"),
                    "--account",
                    "gmail_personale",
                ]
            )
        self.assertEqual(status, 2)
        self.assertIn("--move-mature-quarantine", errors.getvalue())

    def test_fixture_run_is_dry_and_preserves_protected_messages(self) -> None:
        results = evaluate_jsonl(
            ROOT / "config" / "accounts.example.json",
            "gmail_personale",
            ROOT / "examples" / "messages.example.jsonl",
            "heuristic",
            "qwen3-vl:8b",
            datetime(2026, 8, 29, tzinfo=timezone.utc),
        )
        by_id = {item["message_id"]: item for item in results}
        # La sola euristica di categoria non è sufficiente per la quarantena.
        self.assertEqual(by_id["promo-001"]["suggested_action"], "review")
        self.assertEqual(by_id["school-001"]["suggested_action"], "review")
        self.assertEqual(by_id["otp-001"]["suggested_action"], "review")
        self.assertTrue(all(item["dry_run"] for item in results))
        self.assertTrue(all(not item["changes_mailbox"] for item in results))

    def test_interactive_quiz_records_only_local_answers(self) -> None:
        message = make_message(
            message_id="private-message-id",
            sender="Persona <private@example.invalid>",
            subject="Oggetto privato",
            body_text="Corpo privato",
        )
        answers = iter(["t"])
        output: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "preferences.sqlite3"
            counts = gmail_calibration_quiz(
                ROOT / "config/accounts.example.json",
                "gmail_personale",
                "heuristic",
                "qwen3-vl:8b",
                quiz_limit=1,
                sample_limit=1,
                state_db=database,
                input_fn=lambda _: next(answers),
                output_fn=output.append,
                secret_store=FakeSecretStore(),
                mailbox=FakeMailbox([message]),
                classifier=HeuristicClassifier(),
            )
            database_bytes = database.read_bytes()
        self.assertEqual(counts["keep"], 1)
        self.assertIn("Oggetto privato", "\n".join(output))
        self.assertNotIn(b"private@example.invalid", database_bytes)
        self.assertNotIn(b"Corpo privato", database_bytes)


if __name__ == "__main__":
    unittest.main()
