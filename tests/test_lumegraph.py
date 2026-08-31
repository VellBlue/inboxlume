from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from inboxlume.classifier import OllamaClassifier
from inboxlume.learning import PreferenceStore
from inboxlume.lumegraph import (
    HeuristicLifecycleExtractor,
    LifecycleState,
    UtilityKind,
    lifecycle_candidate_kind,
    lifecycle_relation_materials,
)
from inboxlume.lumegraph_runtime import run_lumegraph_shadow
from inboxlume.models import Classification, EmailCategory

from tests.helpers import make_message


NOW = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
UNCERTAIN = Classification(EmailCategory.OTHER, 0.5, ("test",), "test")


class LumeGraphTests(unittest.TestCase):
    def test_bilingual_prefilter_covers_complete_utility_cycles(self) -> None:
        examples = {
            UtilityKind.ONE_TIME_CODE: "Il tuo codice monouso è 123456",
            UtilityKind.ORDER: "Ordine confermato",
            UtilityKind.SHIPMENT: "Your package is out for delivery",
            UtilityKind.RESERVATION: "Prenotazione hotel confermata",
            UtilityKind.INVOICE: "Nuova fattura disponibile",
            UtilityKind.PAYMENT: "Payment receipt for your transaction",
            UtilityKind.SECURITY_FLOW: "Your password changed",
        }
        for expected, subject in examples.items():
            with self.subTest(kind=expected):
                message = make_message(subject=subject)
                self.assertEqual(
                    lifecycle_candidate_kind(message, UNCERTAIN),
                    expected,
                )

    def test_fallback_keeps_evidentiary_and_security_utility_separate(self) -> None:
        extractor = HeuristicLifecycleExtractor()
        payment = make_message(
            subject="Payment confirmation",
            body_text="Your payment completed successfully.",
        )
        payment_result = extractor.extract_lifecycle(
            payment,
            UtilityKind.PAYMENT,
            NOW,
        )
        self.assertEqual(payment_result.state, LifecycleState.COMPLETED)
        self.assertTrue(payment_result.utility.evidentiary)

        otp = make_message(
            received_at=NOW - timedelta(days=9),
            unread=False,
            subject="Codice monouso",
        )
        otp_result = extractor.extract_lifecycle(
            otp,
            UtilityKind.ONE_TIME_CODE,
            NOW,
        )
        self.assertEqual(otp_result.state, LifecycleState.EXPIRED)
        self.assertFalse(otp_result.utility.security)
        self.assertFalse(otp_result.utility.evidentiary)

    def test_graph_links_hmac_references_without_storing_email_plaintext(self) -> None:
        first = make_message(
            message_id="private-first-id",
            subject="Shipment update",
            body_text="Shipped. Tracking number: ZX-12345",
        )
        second = make_message(
            message_id="private-second-id",
            received_at=NOW,
            subject="Delivered",
            body_text="Package delivered. Tracking number: ZX-12345",
        )
        self.assertEqual(
            lifecycle_relation_materials(first, UtilityKind.SHIPMENT),
            ("reference:zx-12345",),
        )
        results = [
            SimpleNamespace(message=first, classification=UNCERTAIN),
            SimpleNamespace(message=second, classification=UNCERTAIN),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "preferences.sqlite3"
            store = PreferenceStore(path, b"l" * 32)
            summary = run_lumegraph_shadow(
                results,
                None,
                store,
                first.account_id,
                "gemma26-policy-v2",
                NOW,
            )
            self.assertEqual(summary["run_nodes"], 2)
            self.assertEqual(summary["run_transitions"], 1)
            ledger = summary["ledger"]
            self.assertEqual(ledger["nodes_total"], 2)  # type: ignore[index]
            self.assertEqual(ledger["transitions_total"], 1)  # type: ignore[index]
            raw = path.read_bytes().lower()
            for secret in (
                b"private-first-id",
                b"private-second-id",
                b"zx-12345",
                b"shipment update",
                b"package delivered",
            ):
                self.assertNotIn(secret, raw)

    def test_model_failure_falls_back_without_authorising_any_action(self) -> None:
        class FailingBackend:
            def extract_lifecycle(self, *args, **kwargs):  # noqa: ANN002, ANN003
                raise RuntimeError("synthetic failure")

        message = make_message(subject="Ordine confermato", message_id="order-2")
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "p.sqlite3", b"f" * 32)
            summary = run_lumegraph_shadow(
                [SimpleNamespace(message=message, classification=UNCERTAIN)],
                FailingBackend(),
                store,
                message.account_id,
                "gemma26-policy-v2",
                NOW,
            )
        self.assertEqual(summary["run_nodes"], 1)
        self.assertEqual(summary["model_failures"], 1)
        self.assertFalse(summary["authorizes_policy"])
        self.assertFalse(summary["authorizes_actions"])
        self.assertFalse(summary["changes_mailbox"])

    def test_ollama_lifecycle_output_is_strict_and_separate(self) -> None:
        classifier = OllamaClassifier("qwen3-vl:8b")
        payload = classifier.lifecycle_request_payload(
            make_message(subject="Booking changed"),
            UtilityKind.RESERVATION,
            NOW,
        )
        self.assertNotIn("tools", payload)
        self.assertEqual(payload["think"], False)
        content = (
            '{"kind":"reservation","state":"replaced",'
            '"utility":{"operational":false,"evidentiary":true,'
            '"personal":true,"security":false},'
            '"date_relation":"future","condition":"external_action_pending",'
            '"confidence":0.93,'
            '"reason_codes":["reservation_language","replacement_language"]}'
        )
        parsed = classifier.parse_lifecycle_json(
            content,
            UtilityKind.RESERVATION,
        )
        self.assertEqual(parsed.state, LifecycleState.REPLACED)
        with self.assertRaises(RuntimeError):
            classifier.parse_lifecycle_json(
                content.replace('"reservation"', '"shipment"', 1),
                UtilityKind.RESERVATION,
            )
        with self.assertRaises(RuntimeError):
            classifier.parse_lifecycle_json(
                content.replace('"confidence":0.93', '"confidence":NaN'),
                UtilityKind.RESERVATION,
            )


if __name__ == "__main__":
    unittest.main()
