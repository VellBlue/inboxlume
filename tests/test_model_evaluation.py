from __future__ import annotations

import unittest
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from datetime import datetime, timezone

from inboxlume.config import AccountPolicy
from benchmarks.mlx_email_worker import (
    _extract_json,
    _extract_lifecycle_json,
    _lifecycle_prompt,
    _prompt,
    _threat_prompt,
)
from inboxlume.model_evaluation import (
    MlxWorkerClassifier,
    evaluate_classifier,
    mlx_worker_path,
)
from unittest.mock import patch
from inboxlume.models import (
    Classification,
    EmailCategory,
    ProviderKind,
    RetentionSignal,
)

from tests.helpers import make_message


NOW = datetime(2026, 8, 29, tzinfo=timezone.utc)


class StaticClassifier:
    def classify(self, message):  # noqa: ANN001
        categories = {
            "keep-ad": EmailCategory.ADVERTISING,
            "discard-spam": EmailCategory.SPAM,
            "unsure-bank": EmailCategory.BANKING,
        }
        return Classification(
            categories[message.message_id],
            0.99,
            ("test",),
            "local:test",
            RetentionSignal.DISCARD_CANDIDATE,
            0.99,
        )


class ModelEvaluationTests(unittest.TestCase):
    @staticmethod
    def _synthetic_worker(source: str) -> MlxWorkerClassifier:
        classifier = object.__new__(MlxWorkerClassifier)
        classifier.model_name = "gemma12"
        classifier.process = subprocess.Popen(
            [sys.executable, "-c", source],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            start_new_session=True,
        )
        classifier._start_pipe_readers()
        return classifier

    def test_reports_only_aggregate_safety_and_interest_metrics(self) -> None:
        policy = AccountPolicy(
            account_id="gmail_personale",
            provider=ProviderKind.GMAIL,
            unread_age_days=90,
        )
        labeled = [
            (make_message(message_id="keep-ad"), "keep"),
            (make_message(message_id="discard-spam"), "dont_keep"),
            (make_message(message_id="unsure-bank"), "unsure"),
        ]
        summary = evaluate_classifier(
            "test",
            StaticClassifier(),
            labeled,
            policy,
            NOW,
        )
        self.assertEqual(summary["evaluated"], 2)
        self.assertEqual(summary["ignored_unsure"], 1)
        self.assertEqual(summary["false_cleanup_on_keep"], 1)
        self.assertEqual(summary["cleanup_matches_on_dont_keep"], 1)
        self.assertEqual(summary["policy_quarantine_on_keep"], 1)
        self.assertNotIn("message_id", summary)
        self.assertNotIn("keep-ad", str(summary))

    def test_frozen_worker_path_uses_the_bundled_mlx_asset(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.object(
            sys, "_MEIPASS", directory, create=True
        ):
            self.assertEqual(
                mlx_worker_path(),
                Path(directory) / "benchmarks" / "mlx_email_worker.py",
            )

    def test_installed_worker_path_uses_the_wheel_data_asset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            worker = root / "benchmarks" / "mlx_email_worker.py"
            worker.parent.mkdir()
            worker.write_text("# synthetic installed worker\n", encoding="utf-8")
            with patch.object(sys, "prefix", str(root)):
                self.assertEqual(mlx_worker_path(), worker)

    def test_mlx_response_timeout_terminates_the_worker_group(self) -> None:
        classifier = self._synthetic_worker("import time; time.sleep(30)")
        with self.assertRaisesRegex(RuntimeError, "timeout"):
            classifier._read_response(0.1)
        self.assertIsNotNone(classifier.process.poll())
        classifier.close()

    def test_mlx_stderr_is_drained_without_deadlock(self) -> None:
        response = json.dumps({"type": "ready", "model": "gemma12"})
        classifier = self._synthetic_worker(
            "import sys; "
            "sys.stderr.write('x' * 2000000); sys.stderr.flush(); "
            f"print({response!r}, flush=True)"
        )
        try:
            self.assertEqual(classifier._read_response(5).get("type"), "ready")
        finally:
            classifier.close()

    def test_mlx_ready_line_does_not_wait_for_a_full_stdout_buffer(self) -> None:
        response = json.dumps({"type": "ready", "model": "gemma12"})
        classifier = self._synthetic_worker(
            "import time; "
            f"print({response!r}, flush=True); "
            "time.sleep(30)"
        )
        try:
            self.assertEqual(classifier._read_response(1).get("type"), "ready")
        finally:
            classifier.close()

    def test_mlx_blocked_input_is_timed_out_and_worker_is_killed(self) -> None:
        classifier = self._synthetic_worker("import time; time.sleep(30)")
        try:
            with self.assertRaisesRegex(RuntimeError, "timeout input"):
                classifier._request_response(
                    {"body": "x" * 350_000},
                    write_timeout_seconds=0.1,
                    response_timeout_seconds=0.1,
                )
            self.assertIsNotNone(classifier.process.poll())
        finally:
            classifier.close()

    def test_mlx_rejects_oversize_request_before_writing(self) -> None:
        classifier = self._synthetic_worker("import time; time.sleep(30)")
        try:
            with self.assertRaisesRegex(RuntimeError, "richiesta.*limite"):
                classifier._request_response({"body": "x" * 500_000})
        finally:
            classifier.close()

    def test_mlx_worker_rejects_boolean_confidences(self) -> None:
        with self.assertRaises(ValueError):
            _extract_json(
                '{"category":"advertising","confidence":1,'
                '"retention":"discard_candidate","retention_confidence":true,'
                '"reason_codes":[]}'
            )
        with self.assertRaises(ValueError):
            _extract_lifecycle_json(
                '{"kind":"order","state":"completed",'
                '"utility":{"operational":false,"evidentiary":false,'
                '"personal":false,"security":false},"date_relation":"past",'
                '"condition":"completed_condition","confidence":true,'
                '"reason_codes":["completion_language"]}',
                "order",
            )


class WorkerPromptContractTests(unittest.TestCase):
    """The prompt must state every constraint the parser refuses to relax.

    A local model that answers well but formats a number or a flag the way the
    prompt left unspecified is discarded as a model failure, so the guarantee
    silently degrades to the deterministic signals alone.
    """

    def _sample(self) -> dict[str, str]:
        return {
            "sender": "avvisi@example.com",
            "subject": "Conferma richiesta",
            "body": "Testo sintetico di prova.",
            "now_date": "2026-08-31",
        }

    def test_every_prompt_states_the_confidence_range_it_enforces(self) -> None:
        prompts = {
            "classification": _prompt(self._sample()),
            "lifecycle": _lifecycle_prompt(self._sample(), "invoice"),
            "threat": _threat_prompt(self._sample()),
        }
        for name, prompt in prompts.items():
            with self.subTest(prompt=name):
                self.assertIn("0..1", prompt)

    def test_the_rated_scale_is_ruled_out_where_the_model_reached_for_it(self) -> None:
        for name, prompt in (
            ("lifecycle", _lifecycle_prompt(self._sample(), "invoice")),
            ("threat", _threat_prompt(self._sample())),
        ):
            with self.subTest(prompt=name):
                self.assertIn("never a 1-to-5 rating", prompt)

    def test_boolean_fields_are_requested_as_json_literals(self) -> None:
        threat = _threat_prompt(self._sample())
        lifecycle = _lifecycle_prompt(self._sample(), "invoice")
        for name, prompt in (("threat", threat), ("lifecycle", lifecycle)):
            with self.subTest(prompt=name):
                self.assertIn("JSON literal true or false", prompt)
                self.assertIn("never a string or a number", prompt)

    def test_threat_prompt_names_each_boolean_the_parser_requires(self) -> None:
        prompt = _threat_prompt(self._sample())
        for field in (
            "impersonation",
            "credential_request",
            "money_request",
            "urgency_pressure",
            "link_action",
            "plausible_legitimate_context",
        ):
            with self.subTest(field=field):
                self.assertIn(field, prompt)

    def test_lifecycle_prompt_keeps_its_two_vocabularies_separate(self) -> None:
        prompt = _lifecycle_prompt(self._sample(), "invoice")
        condition_at = prompt.find("Condition must be one of")
        utility_at = prompt.find("Utility must be an object")
        self.assertGreater(condition_at, 0)
        self.assertGreater(utility_at, condition_at)


if __name__ == "__main__":
    unittest.main()
