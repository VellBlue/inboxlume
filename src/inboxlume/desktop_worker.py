from __future__ import annotations

import argparse
import json
import signal
import sys
import time
from collections import Counter
from contextlib import nullcontext
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, TextIO

from .cli import (
    LOCAL_BACKEND_CHOICES,
    _build_classifier,
    _unload_local_backend,
    gmail_shadow_run,
    yahoo_shadow_run,
)
from .credential_store import SystemCredentialStore
from .diagnostics import (
    append_diagnostic,
    diagnostic_for_terminal_status,
    diagnostic_from_summary,
    diagnostic_path,
)
from .direct_trash_guard import (
    require_direct_trash_authority,
    require_direct_trash_model,
)
from .gui_bridge import run_quiz_bridge, run_shadow_review_bridge
from .local_models import model_spec, profile_for_backend, scan_profile_for_model
from .models import ProviderKind
from .operation_lock import AccountOperationLock, account_operation_lock_path
from .runtime import calibration_answer_counts, runtime_policy
from .settings import (
    RECOMMENDED_INITIAL_DONT_KEEP_ANSWERS,
    RECOMMENDED_INITIAL_KEEP_ANSWERS,
    RECOMMENDED_INITIAL_QUIZ_ANSWERS,
    ScanOrder,
)
from .threat_backtest import run_synthetic_threat_backtest


UNLIMITED_SCAN_CHUNK_SIZE = 500


WORKER_FAILURE_MESSAGES: dict[str, str] = {
    "operation_already_running": (
        "Another InboxLume operation is already running for this account. "
        "Wait for it to finish and retry."
    ),
    "local_model_runtime": (
        "The local model runtime did not become ready. Restart InboxLume from "
        "its launcher and retry; if the problem persists, rebuild the supported "
        "Python environment."
    ),
    "local_state_key": (
        "The local preference key is unavailable or does not match the existing "
        "database. Mailbox actions were blocked."
    ),
    "credential_unavailable": (
        "The protected account credentials are unavailable. Reconnect the "
        "account locally and retry."
    ),
    "provider_connection": (
        "The provider connection stopped before the operation completed. Check "
        "the account connection and retry."
    ),
    "invalid_configuration": (
        "The saved local configuration is invalid. Save the preferences again "
        "and retry."
    ),
    "local_io": (
        "A required local file or runtime resource is unavailable. Restart "
        "InboxLume from its launcher and retry."
    ),
    "invalid_local_text": (
        "A local criterion could not be encoded safely. The operation was stopped."
    ),
    "local_runtime": (
        "The local operation did not complete. Restart InboxLume from its "
        "launcher and retry."
    ),
}


def worker_failure_code(error: BaseException) -> str:
    """Map an exception to a stable, privacy-safe operational category."""

    detail = str(error).casefold()
    module = type(error).__module__.split(".", 1)[0].casefold()
    if isinstance(error, UnicodeError):
        return "invalid_local_text"
    if "già in esecuzione" in detail or "already running" in detail:
        return "operation_already_running"
    if "chiave hmac" in detail or "preference key" in detail:
        return "local_state_key"
    if "credenzial" in detail or "keychain" in detail or "portachiavi" in detail:
        return "credential_unavailable"
    if any(
        marker in detail
        for marker in (
            " mlx",
            "mlx ",
            "gemma",
            "modello locale",
            "local model",
            "metal/gpu",
        )
    ):
        return "local_model_runtime"
    if isinstance(error, (ConnectionError, TimeoutError)) or module in {
        "imaplib",
        "socket",
        "ssl",
        "urllib",
        "http",
    }:
        return "provider_connection"
    if isinstance(error, OSError):
        return "local_io"
    if isinstance(error, ValueError):
        return "invalid_configuration"
    return "local_runtime"


def write_event(stream: TextIO, event: dict[str, Any]) -> None:
    stream.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
    stream.flush()


def _merged_unlimited_summary(
    summaries: list[dict[str, Any]],
) -> dict[str, Any]:
    """Merge aggregate-only chunk summaries without exposing message data."""
    if not summaries:
        raise ValueError("la sessione senza limite non ha prodotto un riepilogo")
    merged = dict(summaries[-1])
    merged["newly_processed"] = sum(
        int(summary.get("newly_processed", 0)) for summary in summaries
    )
    for field in (
        "run_categories",
        "run_content_assessments",
        "run_suggested_actions",
    ):
        values: Counter[str] = Counter()
        for summary in summaries:
            raw = summary.get(field)
            if isinstance(raw, dict):
                values.update({str(key): int(value) for key, value in raw.items()})
        merged[field] = dict(sorted(values.items()))

    automatic = dict(merged.get("automatic_quarantine") or {})
    automatic["selected"] = sum(
        int((summary.get("automatic_quarantine") or {}).get("selected", 0))
        for summary in summaries
        if isinstance(summary.get("automatic_quarantine"), dict)
    )
    automatic["applied"] = sum(
        int((summary.get("automatic_quarantine") or {}).get("applied", 0))
        for summary in summaries
        if isinstance(summary.get("automatic_quarantine"), dict)
    )
    outcomes: Counter[str] = Counter()
    for summary in summaries:
        raw_automatic = summary.get("automatic_quarantine")
        if not isinstance(raw_automatic, dict):
            continue
        raw_outcomes = raw_automatic.get("outcomes")
        if isinstance(raw_outcomes, dict):
            outcomes.update(
                {str(key): int(value) for key, value in raw_outcomes.items()}
            )
    automatic["outcomes"] = dict(sorted(outcomes.items()))
    merged["automatic_quarantine"] = automatic
    governor = dict(merged.get("safety_governor") or {})
    governor["blocked_current_batch"] = sum(
        int((summary.get("safety_governor") or {}).get("blocked_current_batch", 0))
        for summary in summaries
        if isinstance(summary.get("safety_governor"), dict)
    )
    governor["authorized_direct_trash_candidates_current_batch"] = sum(
        int(
            (summary.get("safety_governor") or {}).get(
                "authorized_direct_trash_candidates_current_batch", 0
            )
        )
        for summary in summaries
        if isinstance(summary.get("safety_governor"), dict)
    )
    merged["safety_governor"] = governor
    threat = dict(merged.get("threat_protection") or {})
    for field in (
        "assessed_current_batch",
        "protective_reviews_current_batch",
        "semantic_inferences_requested_current_batch",
        "semantic_inferences_skipped_current_batch",
        "semantic_failures_current_batch",
    ):
        threat[field] = sum(
            int((summary.get("threat_protection") or {}).get(field, 0))
            for summary in summaries
            if isinstance(summary.get("threat_protection"), dict)
        )
    for field in ("current_levels", "current_intents", "current_signals"):
        counts: Counter[str] = Counter()
        for summary in summaries:
            raw_threat = summary.get("threat_protection")
            if not isinstance(raw_threat, dict):
                continue
            raw_counts = raw_threat.get(field)
            if isinstance(raw_counts, dict):
                counts.update(
                    {str(key): int(value) for key, value in raw_counts.items()}
                )
        threat[field] = dict(sorted(counts.items()))
    merged["threat_protection"] = threat
    threat_marker = dict(merged.get("threat_marker") or {})
    for field in ("selected", "applied", "visible"):
        threat_marker[field] = sum(
            int((summary.get("threat_marker") or {}).get(field, 0))
            for summary in summaries
            if isinstance(summary.get("threat_marker"), dict)
        )
    marker_outcomes: Counter[str] = Counter()
    for summary in summaries:
        raw_marker = summary.get("threat_marker")
        if not isinstance(raw_marker, dict):
            continue
        raw_outcomes = raw_marker.get("outcomes")
        if isinstance(raw_outcomes, dict):
            marker_outcomes.update(
                {str(key): int(value) for key, value in raw_outcomes.items()}
            )
    threat_marker["outcomes"] = dict(sorted(marker_outcomes.items()))
    merged["threat_marker"] = threat_marker
    lumegraph = dict(merged.get("lumegraph") or {})
    for field in (
        "run_nodes",
        "run_transitions",
        "model_inferences",
        "fallback_nodes",
        "model_failures",
    ):
        lumegraph[field] = sum(
            int((summary.get("lumegraph") or {}).get(field, 0))
            for summary in summaries
            if isinstance(summary.get("lumegraph"), dict)
        )
    lumegraph["available"] = all(
        (summary.get("lumegraph") or {}).get("available") is not False
        for summary in summaries
        if isinstance(summary.get("lumegraph"), dict)
    )
    merged["lumegraph"] = lumegraph
    proof = dict(merged.get("proof_of_obsolescence") or {})
    for field in (
        "verified_current_batch",
        "promoted_to_quarantine_current_batch",
        "confirmed_ordinary_current_batch",
        "withheld_from_direct_trash_current_batch",
    ):
        proof[field] = sum(
            int((summary.get("proof_of_obsolescence") or {}).get(field, 0))
            for summary in summaries
            if isinstance(summary.get("proof_of_obsolescence"), dict)
        )
    proof_witnesses: Counter[str] = Counter()
    for summary in summaries:
        raw_proof = summary.get("proof_of_obsolescence")
        if not isinstance(raw_proof, dict):
            continue
        raw_witnesses = raw_proof.get("current_witnesses")
        if isinstance(raw_witnesses, dict):
            proof_witnesses.update(
                {str(key): int(value) for key, value in raw_witnesses.items()}
            )
    proof["current_witnesses"] = dict(sorted(proof_witnesses.items()))
    merged["proof_of_obsolescence"] = proof
    behavior = dict(merged.get("behavior_feedback") or {})
    behavior_signals: Counter[str] = Counter()
    behavior_statuses: set[str] = set()
    for summary in summaries:
        raw_behavior = summary.get("behavior_feedback")
        if not isinstance(raw_behavior, dict):
            continue
        behavior_statuses.add(str(raw_behavior.get("status", "unknown")))
        raw_signals = raw_behavior.get("new_signals")
        if isinstance(raw_signals, dict):
            behavior_signals.update(
                {str(key): int(value) for key, value in raw_signals.items()}
            )
    behavior["new_signals"] = dict(sorted(behavior_signals.items()))
    if len(behavior_statuses) > 1:
        behavior["status"] = "mixed_batches"
    merged["behavior_feedback"] = behavior
    merged["read_bodies"] = any(
        bool(summary.get("read_bodies")) for summary in summaries
    )
    merged["stored_plaintext"] = any(
        bool(summary.get("stored_plaintext")) for summary in summaries
    )
    merged["changes_mailbox"] = any(
        bool(summary.get("changes_mailbox")) for summary in summaries
    )
    merged["unlimited_session"] = True
    merged["internal_batches"] = len(summaries)
    merged["exhausted"] = True
    return merged


def _common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--account", required=True)
    parser.add_argument("--provider", choices=("gmail", "yahoo"), required=True)
    parser.add_argument("--state-db", type=Path, required=True)
    parser.add_argument("--unread-days", type=int, required=True)
    parser.add_argument("--otp-days", type=int, required=True)
    parser.add_argument("--confirm-read-bodies", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="inboxlume-desktop-worker",
        description="Worker locale one-shot della GUI multipiattaforma.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan")
    _common_arguments(scan)
    scan.add_argument("--backend", choices=LOCAL_BACKEND_CHOICES, default="gemma26")
    scan.add_argument("--ollama-model", default="qwen3-vl:8b")
    scan.add_argument("--limit", type=int, required=True)
    scan.add_argument("--search-limit", type=int, default=0)
    scan.add_argument(
        "--scan-order",
        choices=tuple(item.value for item in ScanOrder),
        default=ScanOrder.NEWEST_FIRST.value,
    )
    scan.add_argument("--destination", choices=("quarantine", "trash"), required=True)
    scan.add_argument("--apply-safe-actions", action="store_true")
    scan.add_argument("--enforce-safety-governor", action="store_true")
    scan.add_argument(
        "--skip-threat-protection",
        action="store_true",
        help="skip the optional local phishing/scam analysis for this scan",
    )
    scan.add_argument(
        "--threat-semantic-mode",
        choices=("technical_only", "targeted_semantic"),
        default="targeted_semantic",
        help="run no second model pass, or run it only after technical suspicion",
    )
    scan.add_argument(
        "--skip-lumegraph",
        action="store_true",
        help="skip the optional local LumeGraph analysis for this scan",
    )
    scan.add_argument(
        "--skip-obsolescence-proof",
        action="store_true",
        help="skip the optional Proof of Obsolescence step for this scan",
    )

    quiz = commands.add_parser("quiz")
    _common_arguments(quiz)
    quiz.add_argument("--backend", choices=LOCAL_BACKEND_CHOICES, default="gemma26")
    quiz.add_argument("--ollama-model", default="qwen3-vl:8b")
    quiz.add_argument("--limit", type=int, required=True)
    quiz.add_argument("--sample-limit", type=int, required=True)

    review = commands.add_parser("shadow-review")
    _common_arguments(review)
    review.add_argument("--backend", choices=LOCAL_BACKEND_CHOICES, default="gemma26")
    review.add_argument("--ollama-model", default="qwen3-vl:8b")
    review.add_argument("--limit", type=int, required=True)
    review.add_argument("--search-limit", type=int, default=500)

    threat_backtest = commands.add_parser("threat-backtest")
    threat_backtest.add_argument(
        "--backend",
        choices=LOCAL_BACKEND_CHOICES,
        default="gemma26",
    )
    threat_backtest.add_argument("--ollama-model", default="qwen3-vl:8b")
    return parser


def execute_scan(
    args: argparse.Namespace,
    output_stream: TextIO,
    *,
    secret_store: Any | None = None,
    gmail_runner: Callable[..., dict[str, Any]] = gmail_shadow_run,
    yahoo_runner: Callable[..., dict[str, Any]] = yahoo_shadow_run,
) -> dict[str, Any]:
    setattr(args, "_worker_stage", "startup")
    setattr(args, "_mailbox_mutation_started", False)
    setattr(args, "_worker_processed", 0)
    lock = (
        nullcontext()
        if bool(getattr(args, "operation_lock_held", False))
        else AccountOperationLock(
            account_operation_lock_path(args.state_db, args.account)
        )
    )
    with lock:
        return _execute_scan_locked(
            args,
            output_stream,
            secret_store=secret_store,
            gmail_runner=gmail_runner,
            yahoo_runner=yahoo_runner,
        )


def _execute_scan_locked(
    args: argparse.Namespace,
    output_stream: TextIO,
    *,
    secret_store: Any | None = None,
    gmail_runner: Callable[..., dict[str, Any]] = gmail_shadow_run,
    yahoo_runner: Callable[..., dict[str, Any]] = yahoo_shadow_run,
) -> dict[str, Any]:
    if not args.confirm_read_bodies:
        raise ValueError("manca la conferma locale per leggere i corpi Inbox")
    if not args.apply_safe_actions:
        raise ValueError("manca la conferma per applicare le sole azioni sicure")
    if not 0 <= args.limit <= 500:
        raise ValueError(
            "il lotto deve essere 0 (tutte le email idonee) oppure tra 1 e 500"
        )
    if args.limit == 0 and args.search_limit != 0:
        raise ValueError(
            "la sessione per tutte le email idonee richiede search-limit 0"
        )

    provider = ProviderKind(args.provider)
    args.state_db.parent.mkdir(parents=True, exist_ok=True)
    policy = runtime_policy(
        args.config,
        args.account,
        provider,
        unread_age_days=args.unread_days,
        read_one_time_code_age_days=args.otp_days,
    )
    profile = profile_for_backend(args.backend, args.ollama_model)
    if profile is not None:
        spec = model_spec(profile)
        policy = replace(
            policy,
            review_confidence=max(policy.review_confidence, spec.review_confidence),
            # Quarantine and provider Trash are both recoverable destinations.
            # Destination-specific authority is enforced separately below.
            quarantine_confidence=max(
                spec.review_confidence,
                spec.quarantine_confidence,
            ),
        )
    store = secret_store or SystemCredentialStore()
    if args.destination == "trash":
        require_direct_trash_model(args.backend, args.ollama_model)
        calibration = calibration_answer_counts(
            args.state_db,
            args.account,
            store,
        )
        require_direct_trash_authority(
            args.backend,
            args.ollama_model,
            calibration,
        )
    started_at = time.monotonic()
    setattr(args, "_worker_stage", "classification")
    write_event(
        output_stream,
        {
            "type": "phase",
            "phase": "classification",
            "message": "The local model is classifying the batch…",
        },
    )

    def progress(processed: int, limit: int) -> None:
        setattr(
            args,
            "_worker_processed",
            max(int(getattr(args, "_worker_processed", 0)), processed),
        )
        write_event(
            output_stream,
            {"type": "progress", "processed": processed, "limit": limit},
        )

    def phase(message: str) -> None:
        phase_code = {
            "Checking phishing and scam signals locally…": "threat_protection",
            "Building LumeGraph closure evidence locally…": "lumegraph",
            "Applying Proof of Obsolescence checks…": "obsolescence_proof",
            "Applying permitted mailbox actions…": "mailbox_actions",
        }.get(message, "post_scan")
        setattr(args, "_worker_stage", phase_code)
        if phase_code == "mailbox_actions":
            # This receipt is flushed before the first provider mutation.  A
            # later crash must therefore be presented as an outcome to verify;
            # failures before it can safely report that no mailbox action began.
            setattr(args, "_mailbox_mutation_started", True)
        write_event(
            output_stream,
            {"type": "phase", "phase": phase_code, "message": message},
        )

    common = {
        "config_path": args.config,
        "account_id": args.account,
        "backend": args.backend,
        "ollama_model": args.ollama_model,
        "now": datetime.now(timezone.utc),
        "search_limit": args.search_limit,
        "state_db": args.state_db,
        "secret_store": store,
        "direct_to_trash": args.destination == "trash",
        "policy_override": policy,
        "oldest_first": args.scan_order == ScanOrder.OLDEST_FIRST.value,
        "phase": phase,
        "threat_protection_enabled": not bool(
            getattr(args, "skip_threat_protection", False)
        ),
        "threat_semantic_mode": getattr(
            args,
            "threat_semantic_mode",
            "targeted_semantic",
        ),
        "lumegraph_enabled": not bool(getattr(args, "skip_lumegraph", False)),
        "obsolescence_proof_enabled": not bool(
            getattr(args, "skip_obsolescence_proof", False)
        ),
    }

    def run_once(
        chunk_limit: int,
        chunk_progress: Callable[[int, int], None],
    ) -> dict[str, Any]:
        arguments = {
            **common,
            "limit": chunk_limit,
            "progress": chunk_progress,
        }
        if provider is ProviderKind.GMAIL:
            return gmail_runner(
                **arguments,
                apply_quarantine_labels=True,
                governor_enforced=args.enforce_safety_governor,
            )
        return yahoo_runner(
            **arguments,
            apply_quarantine=True,
            governor_enforced=args.enforce_safety_governor,
        )

    if args.limit:
        summary = run_once(args.limit, progress)
    else:
        summaries: list[dict[str, Any]] = []
        processed_total = 0
        while True:
            processed_before = processed_total

            def unlimited_progress(
                processed: int,
                _chunk_limit: int,
                *,
                offset: int = processed_before,
            ) -> None:
                progress(offset + processed, 0)

            chunk_summary = run_once(
                UNLIMITED_SCAN_CHUNK_SIZE,
                unlimited_progress,
            )
            summaries.append(chunk_summary)
            chunk_processed = int(chunk_summary.get("newly_processed", 0))
            processed_total += chunk_processed
            if chunk_processed < UNLIMITED_SCAN_CHUNK_SIZE:
                break
        summary = _merged_unlimited_summary(summaries)
    summary = dict(summary)
    summary["elapsed_seconds"] = round(time.monotonic() - started_at, 3)
    try:
        append_diagnostic(
            diagnostic_path(args.state_db),
            diagnostic_from_summary(
                summary,
                trigger=str(getattr(args, "trigger", "manual")),
                provider=provider.value,
                destination=args.destination,
                governor_requested=bool(args.enforce_safety_governor),
            ),
        )
    except (OSError, RuntimeError, ValueError):
        summary["diagnostic_recorded"] = False
        summary["diagnostic_error_code"] = "local_diagnostic_unavailable"
    else:
        summary["diagnostic_recorded"] = True
    write_event(output_stream, summary)
    return summary


def execute_quiz(
    args: argparse.Namespace,
    input_stream: TextIO,
    output_stream: TextIO,
    *,
    secret_store: Any | None = None,
) -> dict[str, Any]:
    lock = (
        nullcontext()
        if bool(getattr(args, "operation_lock_held", False))
        else AccountOperationLock(
            account_operation_lock_path(args.state_db, args.account)
        )
    )
    with lock:
        return _execute_quiz_locked(
            args,
            input_stream,
            output_stream,
            secret_store=secret_store,
        )


def _execute_quiz_locked(
    args: argparse.Namespace,
    input_stream: TextIO,
    output_stream: TextIO,
    *,
    secret_store: Any | None = None,
) -> dict[str, Any]:
    if not args.confirm_read_bodies:
        raise ValueError("manca la conferma locale per mostrare il quiz")
    if not 1 <= args.limit <= 500 or not args.limit <= args.sample_limit <= 500:
        raise ValueError("limiti quiz non validi")
    provider = ProviderKind(args.provider)
    args.state_db.parent.mkdir(parents=True, exist_ok=True)
    policy = runtime_policy(
        args.config,
        args.account,
        provider,
        unread_age_days=args.unread_days,
        read_one_time_code_age_days=args.otp_days,
    )
    write_event(
        output_stream,
        {
            "type": "phase",
            "phase": "quiz",
            "message": "Preparazione locale di esempi diversi…",
        },
    )
    return run_quiz_bridge(
        args.config,
        args.account,
        args.backend,
        args.ollama_model,
        args.limit,
        args.sample_limit,
        args.state_db,
        input_stream,
        output_stream,
        secret_store=secret_store or SystemCredentialStore(),
        policy_override=policy,
    )


def execute_shadow_review(
    args: argparse.Namespace,
    input_stream: TextIO,
    output_stream: TextIO,
    *,
    secret_store: Any | None = None,
) -> dict[str, int | bool]:
    lock = (
        nullcontext()
        if bool(getattr(args, "operation_lock_held", False))
        else AccountOperationLock(
            account_operation_lock_path(args.state_db, args.account)
        )
    )
    with lock:
        return _execute_shadow_review_locked(
            args,
            input_stream,
            output_stream,
            secret_store=secret_store,
        )


def _execute_shadow_review_locked(
    args: argparse.Namespace,
    input_stream: TextIO,
    output_stream: TextIO,
    *,
    secret_store: Any | None = None,
) -> dict[str, int | bool]:
    """Review only existing Quarantine proposals for the selected profile."""

    if not args.confirm_read_bodies:
        raise ValueError("manca la conferma locale per mostrare le proposte")
    if not 1 <= args.limit <= 500:
        raise ValueError("limite revisione non valido")
    if not args.limit <= args.search_limit <= 1_000:
        raise ValueError("search limit revisione non valido")
    provider = ProviderKind(args.provider)
    profile = profile_for_backend(args.backend, args.ollama_model)
    scan_profile = (
        scan_profile_for_model(profile)
        if profile is not None
        else "heuristic-policy-v2"
    )
    policy = runtime_policy(
        args.config,
        args.account,
        provider,
        unread_age_days=args.unread_days,
        read_one_time_code_age_days=args.otp_days,
    )
    write_event(
        output_stream,
        {
            "type": "phase",
            "phase": "shadow_review",
            "message": "Preparing pending Quarantine proposals…",
        },
    )
    return run_shadow_review_bridge(
        args.config,
        args.account,
        args.limit,
        args.search_limit,
        scan_profile,
        args.state_db,
        input_stream,
        output_stream,
        secret_store=secret_store or SystemCredentialStore(),
        policy_override=policy,
    )


def execute_threat_backtest(
    args: argparse.Namespace,
    output_stream: TextIO,
    *,
    backend_factory: Callable[[str, str], tuple[object, object | None]] = (
        _build_classifier
    ),
) -> dict[str, object]:
    """Run only the packaged synthetic corpus; no account or mailbox is opened."""

    started_at = time.monotonic()
    write_event(
        output_stream,
        {
            "type": "phase",
            "phase": "threat_backtest",
            "message": "The local model is evaluating the synthetic threat corpus…",
        },
    )

    def progress(processed: int, limit: int) -> None:
        write_event(
            output_stream,
            {"type": "progress", "processed": processed, "limit": limit},
        )

    _, local_backend = backend_factory(args.backend, args.ollama_model)
    try:
        report = run_synthetic_threat_backtest(
            local_backend,
            progress=progress,
        )
    finally:
        _unload_local_backend(local_backend)  # type: ignore[arg-type]
    payload = report.as_dict()
    payload["elapsed_seconds"] = round(time.monotonic() - started_at, 3)
    write_event(output_stream, payload)
    return payload


def _record_terminal_scan_status(args: argparse.Namespace, status: str) -> None:
    if getattr(args, "command", None) != "scan":
        return
    try:
        profile = profile_for_backend(args.backend, args.ollama_model)
        scan_profile = (
            scan_profile_for_model(profile)
            if profile is not None
            else "heuristic-policy-v2"
        )
        append_diagnostic(
            diagnostic_path(args.state_db),
            diagnostic_for_terminal_status(
                status=status,
                trigger=str(getattr(args, "trigger", "manual")),
                provider=str(args.provider),
                destination=str(args.destination),
                scan_profile=scan_profile,
                governor_requested=bool(args.enforce_safety_governor),
            ),
        )
    except Exception:  # noqa: BLE001 - diagnostics must never mask the root failure
        pass


def _write_terminal_worker_event(
    args: argparse.Namespace,
    *,
    event_type: str,
    error_code: str | None = None,
) -> None:
    event: dict[str, object] = {"type": event_type}
    if error_code is not None:
        event["error_code"] = error_code
        event["message"] = WORKER_FAILURE_MESSAGES[error_code]
    if getattr(args, "command", None) == "scan":
        mutation_started = bool(
            getattr(args, "_mailbox_mutation_started", False)
        )
        event["stage"] = str(getattr(args, "_worker_stage", "startup"))
        event["processed_before_stop"] = max(
            0, int(getattr(args, "_worker_processed", 0))
        )
        event["mailbox_outcome"] = (
            "unknown" if mutation_started else "unchanged"
        )
        event["mailbox_changes_unknown"] = mutation_started
    write_event(sys.stdout, event)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    def stop_on_terminate(signum, frame):  # noqa: ANN001, ARG001
        raise KeyboardInterrupt

    previous_handler = signal.signal(signal.SIGTERM, stop_on_terminate)
    try:
        if args.command == "scan":
            execute_scan(args, sys.stdout)
        elif args.command == "quiz":
            execute_quiz(args, sys.stdin, sys.stdout)
        elif args.command == "shadow-review":
            execute_shadow_review(args, sys.stdin, sys.stdout)
        else:
            execute_threat_backtest(args, sys.stdout)
    except KeyboardInterrupt:
        _record_terminal_scan_status(args, "cancelled")
        _write_terminal_worker_event(args, event_type="cancelled")
        return 130
    except UnicodeError:
        # Do not expose Python's raw codec diagnostics (which may include a
        # message-derived value) through the GUI JSON protocol.
        _record_terminal_scan_status(args, "failed")
        _write_terminal_worker_event(
            args,
            event_type="error",
            error_code="invalid_local_text",
        )
        return 2
    except (OSError, RuntimeError, ValueError) as exc:
        _record_terminal_scan_status(args, "failed")
        _write_terminal_worker_event(
            args,
            event_type="error",
            error_code=worker_failure_code(exc),
        )
        return 2
    except Exception as exc:  # noqa: BLE001 - final local process safety boundary
        # Provider libraries and native runtimes may expose exception classes
        # outside the small set above (for example an IMAP connection abort).
        # Keep the process protocol intact while never forwarding raw
        # exception text, which could contain local paths or message data.
        _record_terminal_scan_status(args, "failed")
        _write_terminal_worker_event(
            args,
            event_type="error",
            error_code=worker_failure_code(exc),
        )
        return 2
    finally:
        signal.signal(signal.SIGTERM, previous_handler)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
