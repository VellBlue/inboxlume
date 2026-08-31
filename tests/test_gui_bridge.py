from __future__ import annotations

import io
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from inboxlume.classifier import HeuristicClassifier
from inboxlume.gui_bridge import run_quiz_bridge, run_shadow_review_bridge
from inboxlume.learning import PreferenceStore, load_or_create_hmac_key
from inboxlume.models import (
    Classification,
    EmailCategory,
    PolicyAction,
    PolicyDecision,
    ProviderKind,
)
from inboxlume.providers.contracts import READ_ONLY_CAPABILITIES

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

    def iter_inbox_shadow_review_sample(  # noqa: ANN001
        self,
        unread_before,
        read_otp_before,
        read_access_before,
        limit,
        search_limit,
        record_for_id,
    ):
        yielded = 0
        for message in self.messages[:search_limit]:
            record = record_for_id(message.message_id)
            if record is None:
                continue
            yield message, record[0], record[1]
            yielded += 1
            if yielded >= limit:
                return


class GuiBridgeTests(unittest.TestCase):
    def test_yahoo_quiz_uses_separate_account_and_database(self) -> None:
        message = make_message(
            account_id="yahoo_personale",
            provider=ProviderKind.YAHOO,
            message_id="777:11",
            subject="Newsletter Yahoo",
        )
        secret_store = FakeSecretStore()
        output_stream = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "yahoo_preferences.sqlite3"
            counts = run_quiz_bridge(
                ROOT / "config/accounts.example.json",
                "yahoo_personale",
                backend="heuristic",
                ollama_model="qwen3-vl:8b",
                quiz_limit=1,
                sample_limit=1,
                state_db=database,
                input_stream=io.StringIO('{"answer":"dont_keep"}\n'),
                output_stream=output_stream,
                secret_store=secret_store,
                mailbox=FakeMailbox([message]),
                classifier=HeuristicClassifier(),
            )

        self.assertEqual(counts["dont_keep"], 1)
        self.assertTrue(database.name.startswith("yahoo_"))

    def test_shadow_review_uses_existing_proposals_without_model_or_plaintext(self) -> None:
        message = make_message(
            message_id="shadow-private-id",
            sender="Privato <shadow@example.invalid>",
            subject="Offerta privata",
            body_text="Testo privato",
        )
        secret_store = FakeSecretStore()
        output_stream = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "preferences.sqlite3"
            store = PreferenceStore(
                database,
                load_or_create_hmac_key(secret_store, "gmail_personale"),
            )
            store.record_shadow_scan(
                message,
                Classification(EmailCategory.ADVERTISING, 0.99, ("test",), "test"),
                PolicyDecision(PolicyAction.QUARANTINE, ("test",)),
                "gemma26-policy-v1",
                datetime(2026, 8, 29, tzinfo=timezone.utc),
            )
            counts = run_shadow_review_bridge(
                ROOT / "config/accounts.example.json",
                "gmail_personale",
                quiz_limit=1,
                search_limit=10,
                scan_profile="gemma26-policy-v1",
                state_db=database,
                input_stream=io.StringIO('{"answer":"keep"}\n'),
                output_stream=output_stream,
                secret_store=secret_store,
                mailbox=FakeMailbox([message]),
            )
            database_bytes = database.read_bytes()
        events = [json.loads(line) for line in output_stream.getvalue().splitlines()]
        self.assertEqual(counts["keep"], 1)
        self.assertEqual(events[0]["category"], "advertising")
        self.assertNotIn("confidence", events[0])
        self.assertEqual(events[-1]["validation"]["keep"], 1)
        self.assertNotIn(b"shadow@example.invalid", database_bytes)
        self.assertNotIn(b"Testo privato", database_bytes)

    def test_shadow_review_includes_cleanup_boundary_but_not_protected_review(self) -> None:
        advertising = make_message(message_id="borderline-advertising")
        banking = make_message(message_id="borderline-banking")
        secret_store = FakeSecretStore()
        output_stream = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "preferences.sqlite3"
            store = PreferenceStore(
                database,
                load_or_create_hmac_key(secret_store, "gmail_personale"),
            )
            review = PolicyDecision(PolicyAction.REVIEW, ("borderline",))
            for message, category in (
                (advertising, EmailCategory.ADVERTISING),
                (banking, EmailCategory.BANKING),
            ):
                store.record_shadow_scan(
                    message,
                    Classification(category, 0.79, ("test",), "test"),
                    review,
                    "gemma26-policy-v1",
                    datetime(2026, 8, 29, tzinfo=timezone.utc),
                )
            counts = run_shadow_review_bridge(
                ROOT / "config/accounts.example.json",
                "gmail_personale",
                quiz_limit=2,
                search_limit=10,
                scan_profile="gemma26-policy-v1",
                state_db=database,
                input_stream=io.StringIO('{"answer":"dont_keep"}\n'),
                output_stream=output_stream,
                secret_store=secret_store,
                mailbox=FakeMailbox([advertising, banking]),
            )

        events = [json.loads(line) for line in output_stream.getvalue().splitlines()]
        candidates = [event for event in events if event["type"] == "candidate"]
        self.assertEqual(counts["dont_keep"], 1)
        self.assertEqual([event["category"] for event in candidates], ["advertising"])

    def test_streams_candidates_and_persists_no_plaintext(self) -> None:
        messages = [
            make_message(
                message_id="one",
                sender="Privato <one@example.invalid>",
                subject="Primo oggetto privato",
                body_text="Primo corpo privato",
            ),
            make_message(
                message_id="two",
                sender="Privato <two@example.invalid>",
                subject="Secondo oggetto privato",
                body_text="Secondo corpo privato",
            ),
        ]
        input_stream = io.StringIO('{"answer":"keep"}\n{"answer":"dont_keep"}\n')
        output_stream = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "preferences.sqlite3"
            counts = run_quiz_bridge(
                ROOT / "config/accounts.example.json",
                "gmail_personale",
                "heuristic",
                "qwen3-vl:8b",
                quiz_limit=2,
                sample_limit=2,
                state_db=database,
                input_stream=input_stream,
                output_stream=output_stream,
                secret_store=FakeSecretStore(),
                mailbox=FakeMailbox(messages),
                classifier=HeuristicClassifier(),
            )
            database_bytes = database.read_bytes()

        events = [json.loads(line) for line in output_stream.getvalue().splitlines()]
        self.assertEqual([event["type"] for event in events], ["candidate", "candidate", "summary"])
        self.assertEqual(counts["keep"], 1)
        self.assertEqual(counts["dont_keep"], 1)
        self.assertIn("Primo corpo privato", events[0]["preview"])
        self.assertNotIn(b"one@example.invalid", database_bytes)
        self.assertNotIn(b"Primo corpo privato", database_bytes)

    def test_quit_preserves_previous_answers_and_emits_summary(self) -> None:
        messages = [make_message(message_id="one"), make_message(message_id="two")]
        input_stream = io.StringIO('{"answer":"keep"}\n{"answer":"quit"}\n')
        output_stream = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            counts = run_quiz_bridge(
                ROOT / "config/accounts.example.json",
                "gmail_personale",
                "heuristic",
                "qwen3-vl:8b",
                quiz_limit=2,
                sample_limit=2,
                state_db=Path(directory) / "preferences.sqlite3",
                input_stream=input_stream,
                output_stream=output_stream,
                secret_store=FakeSecretStore(),
                mailbox=FakeMailbox(messages),
                classifier=HeuristicClassifier(),
            )
        self.assertEqual(counts["presented"], 1)
        self.assertTrue(counts["stopped"])
        self.assertEqual(json.loads(output_stream.getvalue().splitlines()[-1])["type"], "summary")


if __name__ == "__main__":
    unittest.main()
