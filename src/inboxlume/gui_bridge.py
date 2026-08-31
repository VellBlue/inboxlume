from __future__ import annotations

import argparse
import json
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

from .classifier import Classifier
from .cli import LOCAL_BACKEND_CHOICES, _build_classifier, _unload_local_backend
from .config import load_policies
from .config import AccountPolicy
from .credential_store import SystemCredentialStore
from .learning import PreferenceStore, load_or_create_hmac_key
from .models import ProviderKind
from .pipeline import (
    prepare_quarantine_shadow_review,
    prepare_quiz,
    prepare_shadow_review,
)
from .providers.contracts import ReadOnlyMailbox
from .providers.gmail import GmailReadOnlyMailbox
from .providers.google_oauth import (
    GoogleAccessTokenProvider,
    SecretStore,
)
from .providers.yahoo import (
    YAHOO_QUARANTINE_FOLDER,
    YahooImapError,
    YahooReadOnlyMailbox,
)
from .quiz import CalibrationQuiz, QuizAnswer
from .sanitizer import normalize_plain_text


def _write_event(stream: TextIO, event: dict[str, Any]) -> None:
    stream.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
    stream.flush()


def _candidate_event(candidate, position: int, total: int) -> dict[str, Any]:  # noqa: ANN001
    message = candidate.message
    event = {
        "type": "candidate",
        "position": position,
        "total": total,
        "sender": normalize_plain_text(message.sender, max_chars=320),
        "subject": normalize_plain_text(message.subject, max_chars=500),
        "received_at": message.received_at.astimezone().isoformat(timespec="minutes"),
        "unread": message.unread,
        "category": candidate.classification.category.value,
        "preview": normalize_plain_text(message.body_text, max_chars=1_200),
    }
    if not candidate.classification.classifier.startswith("shadow:"):
        event["confidence"] = round(candidate.classification.confidence, 4)
    else:
        # This candidate was already proposed by a completed local scan.  The
        # UI uses this marker to present a targeted Quarantine review instead
        # of implying that it is another general calibration example.
        event["review_kind"] = "quarantine_proposal"
    return event


def _read_answer(stream: TextIO) -> QuizAnswer | None:
    line = stream.readline()
    if not line:
        return None
    try:
        raw = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ValueError("comando GUI non valido") from exc
    if not isinstance(raw, dict) or set(raw) != {"answer"}:
        raise ValueError("comando GUI non valido")
    value = raw["answer"]
    if value == "quit":
        return None
    try:
        return QuizAnswer(str(value))
    except ValueError as exc:
        raise ValueError("risposta GUI non valida") from exc


def _policy_and_mailbox(
    config_path: Path,
    account_id: str,
    keychain: SecretStore,
    policy_override: AccountPolicy | None = None,
) -> tuple[Any, ReadOnlyMailbox]:
    if policy_override is None:
        policies = load_policies(config_path)
        try:
            policy = policies[account_id]
        except KeyError as exc:
            raise ValueError(f"account non configurato: {account_id}") from exc
    else:
        policy = policy_override
        if policy.account_id != account_id:
            raise ValueError("policy GUI non corrispondente all'account")
    if policy.provider is ProviderKind.GMAIL:
        mailbox: ReadOnlyMailbox = GmailReadOnlyMailbox(
            account_id,
            GoogleAccessTokenProvider(account_id, store=keychain),
        )
    elif policy.provider is ProviderKind.YAHOO:
        mailbox = YahooReadOnlyMailbox.from_secret_store(account_id, keychain)
    else:
        raise ValueError("provider GUI non supportato")
    return policy, mailbox


def _close_mailbox(mailbox: ReadOnlyMailbox) -> None:
    close = getattr(mailbox, "close", None)
    if callable(close):
        close()


def run_quiz_bridge(
    config_path: Path,
    account_id: str,
    backend: str,
    ollama_model: str,
    quiz_limit: int,
    sample_limit: int,
    state_db: Path,
    input_stream: TextIO,
    output_stream: TextIO,
    secret_store: SecretStore | None = None,
    mailbox: ReadOnlyMailbox | None = None,
    classifier: Classifier | None = None,
    policy_override: AccountPolicy | None = None,
) -> dict[str, Any]:
    """Protocollo JSONL locale: un candidato in uscita, una risposta in entrata."""

    keychain = secret_store or SystemCredentialStore()
    if mailbox is None:
        policy, actual_mailbox = _policy_and_mailbox(
            config_path, account_id, keychain, policy_override
        )
        owns_mailbox = True
    else:
        policy = policy_override or load_policies(config_path)[account_id]
        actual_mailbox = mailbox
        owns_mailbox = False
    preferences = PreferenceStore(
        state_db,
        load_or_create_hmac_key(keychain, account_id, state_db),
        account_id,
    )
    local_backend = None
    if classifier is None:
        classifier, local_backend = _build_classifier(backend, ollama_model)

    counts: dict[str, Any] = {
        "keep": 0,
        "dont_keep": 0,
        "unsure": 0,
        "presented": 0,
        "stopped": False,
    }
    try:
        candidates = prepare_quiz(
            policy,
            actual_mailbox,
            classifier,
            preferences,
            quiz_limit,
            sample_limit,
        )
        quiz = CalibrationQuiz(preferences)
        for position, candidate in enumerate(candidates, start=1):
            _write_event(output_stream, _candidate_event(candidate, position, len(candidates)))
            answer = _read_answer(input_stream)
            if answer is None:
                counts["stopped"] = True
                break
            quiz.answer(candidate, answer)
            counts[answer.value] = int(counts[answer.value]) + 1
            counts["presented"] = int(counts["presented"]) + 1

        calibration_counts = preferences.quiz_answer_counts(account_id)
        counts["calibration_total"] = sum(calibration_counts.values())
        counts["calibration_counts"] = calibration_counts
        _write_event(output_stream, {"type": "summary", **counts})
        return counts
    finally:
        _unload_local_backend(local_backend)
        if owns_mailbox:
            _close_mailbox(actual_mailbox)


def run_shadow_review_bridge(
    config_path: Path,
    account_id: str,
    quiz_limit: int,
    search_limit: int,
    scan_profile: str,
    state_db: Path,
    input_stream: TextIO,
    output_stream: TextIO,
    secret_store: SecretStore | None = None,
    mailbox: ReadOnlyMailbox | None = None,
    policy_override: AccountPolicy | None = None,
) -> dict[str, int | bool]:
    keychain = secret_store or SystemCredentialStore()
    if mailbox is None:
        policy, actual_mailbox = _policy_and_mailbox(
            config_path, account_id, keychain, policy_override
        )
        owns_mailbox = True
    else:
        policy = policy_override or load_policies(config_path)[account_id]
        actual_mailbox = mailbox
        owns_mailbox = False
    preferences = PreferenceStore(
        state_db,
        load_or_create_hmac_key(keychain, account_id, state_db),
        account_id,
    )
    review_now = datetime.now(timezone.utc)
    try:
        candidates = []
        # Yahoo moves applied proposals out of INBOX, so review the dedicated
        # reversible folder first.  Remaining slots are then filled with
        # cleanup-boundary candidates that are still in Inbox.
        if policy.provider is ProviderKind.YAHOO and owns_mailbox:
            try:
                quarantine_mailbox = YahooReadOnlyMailbox.from_secret_store(
                    account_id,
                    keychain,
                    folder=YAHOO_QUARANTINE_FOLDER,
                )
            except YahooImapError:
                # A first run may not have created the folder yet.  Review is
                # still valid and simply has no moved proposals to present.
                pass
            else:
                try:
                    candidates.extend(
                        prepare_quarantine_shadow_review(
                            policy,
                            quarantine_mailbox,
                            preferences,
                            review_now,
                            quiz_limit,
                            search_limit,
                            scan_profile,
                        )
                    )
                finally:
                    _close_mailbox(quarantine_mailbox)
        remaining = quiz_limit - len(candidates)
        if remaining:
            candidates.extend(
                prepare_shadow_review(
                    policy,
                    actual_mailbox,
                    preferences,
                    review_now,
                    remaining,
                    search_limit,
                    scan_profile,
                )
            )
    finally:
        if owns_mailbox:
            _close_mailbox(actual_mailbox)
    counts: dict[str, int | bool] = {
        "keep": 0,
        "dont_keep": 0,
        "unsure": 0,
        "presented": 0,
        "stopped": False,
    }
    quiz = CalibrationQuiz(preferences)
    for position, candidate in enumerate(candidates, start=1):
        _write_event(output_stream, _candidate_event(candidate, position, len(candidates)))
        answer = _read_answer(input_stream)
        if answer is None:
            counts["stopped"] = True
            break
        quiz.answer(candidate, answer)
        counts[answer.value] = int(counts[answer.value]) + 1
        counts["presented"] = int(counts["presented"]) + 1

    _write_event(
        output_stream,
        {
            "type": "summary",
            **counts,
            "validation": preferences.shadow_quarantine_label_summary(
                account_id,
                scan_profile,
            ),
        },
    )
    return counts


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="inboxlume-gui-bridge",
        description="Bridge locale JSONL per quiz Inbox Gmail/Yahoo separati.",
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--account", required=True)
    parser.add_argument("--mode", choices=("quiz", "shadow-review"), default="quiz")
    parser.add_argument(
        "--backend",
        choices=LOCAL_BACKEND_CHOICES,
        default="ollama",
    )
    parser.add_argument("--ollama-model", default="qwen3-vl:8b")
    parser.add_argument("--limit", type=int, default=12)
    parser.add_argument("--sample-limit", type=int, default=60)
    parser.add_argument("--search-limit", type=int, default=500)
    parser.add_argument("--scan-profile", default="gemma26-policy-v2")
    parser.add_argument("--state-db", type=Path, required=True)
    parser.add_argument("--confirm-read-bodies", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.confirm_read_bodies:
        _write_event(
            sys.stdout,
            {
                "type": "error",
                "message": "manca la conferma esplicita per leggere i corpi Inbox",
            },
        )
        return 2
    def stop_on_terminate(signum, frame):  # noqa: ANN001, ARG001
        raise KeyboardInterrupt

    previous_handler = signal.signal(signal.SIGTERM, stop_on_terminate)
    try:
        if args.mode == "shadow-review":
            run_shadow_review_bridge(
                args.config,
                args.account,
                args.limit,
                args.search_limit,
                args.scan_profile,
                args.state_db,
                sys.stdin,
                sys.stdout,
            )
        else:
            run_quiz_bridge(
                args.config,
                args.account,
                args.backend,
                args.ollama_model,
                args.limit,
                args.sample_limit,
                args.state_db,
                sys.stdin,
                sys.stdout,
            )
    except KeyboardInterrupt:
        return 130
    except (OSError, RuntimeError, ValueError) as exc:
        _write_event(sys.stdout, {"type": "error", "message": str(exc)})
        return 2
    finally:
        signal.signal(signal.SIGTERM, previous_handler)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
