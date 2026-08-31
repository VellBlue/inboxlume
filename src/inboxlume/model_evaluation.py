from __future__ import annotations

import json
import os
import queue
import signal
import subprocess
import sys
import threading
import time
from collections import Counter
from datetime import datetime, timedelta
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path
from typing import Any, Callable, Iterable

from .classifier import HeuristicClassifier, HybridClassifier, OllamaClassifier
from .config import AccountPolicy
from .learning import PreferenceStore
from .lumegraph import (
    LIFECYCLE_REASON_CODES,
    DateRelation,
    LifecycleObservation,
    LifecycleCondition,
    LifecycleState,
    UtilityKind,
    UtilityVector,
)
from .local_models import LocalModelProfile, resolve_cached_gemma, resolve_mlx_python
from .models import (
    Classification,
    EmailCategory,
    EmailRecord,
    PolicyAction,
    RetentionSignal,
)
from .policy import SafetyPolicyEngine
from .providers.gmail import GmailReadOnlyMailbox
from .threat_signals import (
    SemanticThreatAssessment,
    parse_semantic_threat_mapping,
)


MODEL_NAMES = ("qwen8", "gemma12", "gemma26")
MLX_STARTUP_TIMEOUT_SECONDS = 180.0
MLX_RESPONSE_TIMEOUT_SECONDS = 120.0
MLX_WRITE_TIMEOUT_SECONDS = 10.0
MLX_MAX_RESPONSE_CHARS = 1_000_000
MLX_MAX_REQUEST_CHARS = 400_000


def mlx_worker_path() -> Path:
    bundle_root = getattr(sys, "_MEIPASS", None)
    if bundle_root is not None:
        return Path(str(bundle_root)) / "benchmarks" / "mlx_email_worker.py"
    try:
        installed_distribution = distribution("inboxlume")
    except PackageNotFoundError:
        installed_distribution = None
    if installed_distribution is not None:
        for item in installed_distribution.files or ():
            normalized = str(item).replace("\\", "/")
            if normalized.endswith("benchmarks/mlx_email_worker.py"):
                recorded_worker = Path(installed_distribution.locate_file(item))
                if recorded_worker.is_file():
                    return recorded_worker
    installed_worker = Path(sys.prefix) / "benchmarks" / "mlx_email_worker.py"
    source_worker = Path(__file__).resolve().parents[2] / "benchmarks" / "mlx_email_worker.py"
    if installed_worker.is_file():
        return installed_worker
    return source_worker


def recover_answered_messages(
    policy: AccountPolicy,
    mailbox: GmailReadOnlyMailbox,
    store: PreferenceStore,
    now: datetime,
    search_limit: int,
) -> list[tuple[EmailRecord, str]]:
    """Recupera in RAM solo messaggi già etichettati; nessun testo viene salvato."""

    if now.tzinfo is None:
        raise ValueError("now deve includere il fuso orario")
    if not 1 <= search_limit <= 500:
        raise ValueError("search_limit deve essere tra 1 e 500")
    cutoff = now - timedelta(days=policy.unread_age_days)
    answer_for_id = lambda message_id: store.quiz_answer_for_message_id(  # noqa: E731
        policy.account_id,
        policy.provider,
        message_id,
    )
    recovered = list(
        mailbox.iter_inbox_answered_quiz_sample(
            search_limit,
            cutoff,
            answer_for_id,
        )
    )
    for message, answer in recovered:
        store.backfill_similarity_example(message, answer)
    return recovered


class MlxWorkerClassifier:
    """Processo MLX locale isolato, avviato soltanto per la durata del confronto."""

    def __init__(self, model_name: str) -> None:
        try:
            profile = LocalModelProfile(model_name)
        except ValueError as exc:
            raise ValueError(f"modello Gemma non consentito: {model_name}") from exc
        if profile not in {LocalModelProfile.GEMMA12, LocalModelProfile.GEMMA26}:
            raise ValueError(f"modello Gemma non consentito: {model_name}")
        model_path = resolve_cached_gemma(profile)
        worker = mlx_worker_path()
        python = resolve_mlx_python()
        if not worker.is_file():
            raise RuntimeError("runtime MLX locale non disponibile")

        environment = os.environ.copy()
        for name in (
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ):
            environment.pop(name, None)
        environment.update(
            {
                "HF_HUB_OFFLINE": "1",
                "TRANSFORMERS_OFFLINE": "1",
                "NO_PROXY": "*",
                "no_proxy": "*",
                "PYTHONUNBUFFERED": "1",
            }
        )
        self.model_name = profile.value
        process_group: dict[str, object] = {}
        if os.name == "nt":  # pragma: no cover - exercised on Windows
            process_group["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            process_group["start_new_session"] = True
        self.process = subprocess.Popen(
            [
                str(python),
                str(worker),
                "--model",
                str(model_path),
                "--name",
                profile.value,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            # Keep stderr private and inspect it only when the worker exits
            # before sending its first JSON response.  MLX can terminate at
            # the Metal layer (for example with SIGABRT) before Python gets a
            # chance to emit the structured error on stdout.
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
            env=environment,
            **process_group,
        )
        self._start_pipe_readers()
        try:
            ready = self._read_response(MLX_STARTUP_TIMEOUT_SECONDS)
        except RuntimeError as exc:
            self.close()
            raise RuntimeError(
                f"impossibile caricare {profile.value} dalla cache locale: {exc}"
            ) from exc
        if ready.get("type") != "ready":
            self.close()
            code = ready.get("code")
            details = {
                "metal_device_unavailable": "dispositivo Metal/GPU non disponibile",
                "insufficient_memory": "memoria insufficiente per questo profilo",
                "runtime_model_incompatible": "runtime MLX incompatibile con la cache",
                "model_load_failed": "errore del runtime MLX",
            }
            reason = details.get(str(code), "errore del runtime MLX")
            exception_name = ready.get("exception")
            if (
                reason == details["model_load_failed"]
                and isinstance(exception_name, str)
                and exception_name
            ):
                reason = f"{reason} ({exception_name})"
            raise RuntimeError(
                f"impossibile caricare {profile.value} dalla cache locale: {reason}"
            )

    def _start_pipe_readers(self) -> None:
        if self.process.stdout is None or self.process.stderr is None:
            raise RuntimeError("processo MLX privo di pipe locali")
        self._response_queue: queue.Queue[tuple[str, str]] = queue.Queue(maxsize=4)
        self._stderr_categories: set[str] = set()
        self._stderr_lock = threading.Lock()

        def read_stdout() -> None:
            try:
                while True:
                    # ``TextIOWrapper.read(4096)`` can wait for all 4096
                    # characters while the persistent MLX worker is already
                    # waiting for its first request.  The protocol is one
                    # bounded JSON object per line, so deliver the short
                    # startup receipt as soon as its newline is flushed.
                    line = self.process.stdout.readline(
                        MLX_MAX_RESPONSE_CHARS + 1
                    )
                    if line == "":
                        break
                    if len(line) > MLX_MAX_RESPONSE_CHARS:
                        self._response_queue.put(("oversize", ""))
                        return
                    self._response_queue.put(("line", line.rstrip("\r\n")))
            finally:
                self._response_queue.put(("eof", ""))

        def read_stderr() -> None:
            for chunk in iter(lambda: self.process.stderr.readline(4096), ""):
                lowered = chunk.casefold()
                found: set[str] = set()
                if "metal" in lowered or "gpu" in lowered or "device" in lowered:
                    found.add("device")
                if "memory" in lowered or "out of" in lowered or "alloc" in lowered:
                    found.add("memory")
                if (
                    "unsupported" in lowered
                    or "model type" in lowered
                    or "architecture" in lowered
                ):
                    found.add("incompatible")
                if found:
                    with self._stderr_lock:
                        self._stderr_categories.update(found)

        self._stdout_reader = threading.Thread(target=read_stdout, daemon=True)
        self._stderr_reader = threading.Thread(target=read_stderr, daemon=True)
        self._stdout_reader.start()
        self._stderr_reader.start()

    def _terminate_process_tree(self) -> None:
        process = self.process
        if process.poll() is not None:
            return
        try:
            if os.name != "nt":
                os.killpg(process.pid, signal.SIGTERM)
            else:  # pragma: no cover - exercised on Windows
                subprocess.run(
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                )
            process.wait(timeout=3)
        except (OSError, ProcessLookupError, subprocess.TimeoutExpired):
            try:
                if os.name != "nt":
                    os.killpg(process.pid, signal.SIGKILL)
                else:  # pragma: no cover - exercised on Windows
                    subprocess.run(
                        ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                        check=False,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=5,
                    )
                process.wait(timeout=3)
            except (OSError, ProcessLookupError, subprocess.TimeoutExpired):
                pass

    def _read_response(
        self,
        timeout_seconds: float = MLX_RESPONSE_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        try:
            kind, line = self._response_queue.get(timeout=timeout_seconds)
        except queue.Empty as exc:
            self._terminate_process_tree()
            raise RuntimeError("timeout del processo MLX locale") from exc
        if kind == "oversize":
            self._terminate_process_tree()
            raise RuntimeError("risposta MLX locale oltre il limite")
        if kind == "eof":
            with self._stderr_lock:
                categories = set(self._stderr_categories)
            if "device" in categories:
                raise RuntimeError(
                    "runtime MLX interrotto: dispositivo Metal/GPU non disponibile"
                )
            if "memory" in categories:
                raise RuntimeError(
                    "runtime MLX interrotto: memoria insufficiente per questo profilo"
                )
            if "incompatible" in categories:
                raise RuntimeError(
                    "runtime MLX interrotto: cache incompatibile con il runtime"
                )
            raise RuntimeError("processo MLX locale interrotto prima della risposta")
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RuntimeError("risposta MLX locale non valida") from exc
        if not isinstance(value, dict):
            raise RuntimeError("risposta MLX locale non valida")
        return value

    def _request_response(
        self,
        request: dict[str, object],
        *,
        write_timeout_seconds: float = MLX_WRITE_TIMEOUT_SECONDS,
        response_timeout_seconds: float = MLX_RESPONSE_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        """Write through a supervised thread so a wedged worker cannot block forever."""

        if self.process.stdin is None or self.process.stdin.closed:
            raise RuntimeError("processo MLX privo di input")
        serialized = json.dumps(request, ensure_ascii=False) + "\n"
        if len(serialized) > MLX_MAX_REQUEST_CHARS:
            raise RuntimeError("richiesta MLX locale oltre il limite")
        outcome: queue.Queue[BaseException | None] = queue.Queue(maxsize=1)

        def write_request() -> None:
            try:
                self.process.stdin.write(serialized)
                self.process.stdin.flush()
            except (BrokenPipeError, OSError, ValueError) as exc:
                outcome.put(exc)
            else:
                outcome.put(None)

        writer = threading.Thread(target=write_request, daemon=True)
        writer.start()
        try:
            write_error = outcome.get(timeout=write_timeout_seconds)
        except queue.Empty as exc:
            self._terminate_process_tree()
            raise RuntimeError("timeout input del processo MLX locale") from exc
        if write_error is not None:
            raise RuntimeError("scrittura al processo MLX locale fallita") from write_error
        return self._read_response(response_timeout_seconds)

    def classify(self, message: EmailRecord) -> Classification:
        request = {
            "sender": message.sender,
            "subject": message.subject,
            "body": message.body_text,
        }
        try:
            response = self._request_response(request)
            if response.get("type") != "classification":
                raise RuntimeError("classificazione MLX locale fallita")
            reasons = response.get("reason_codes")
            confidence = response.get("confidence")
            retention_confidence = response.get("retention_confidence")
            if (
                not isinstance(reasons, list)
                or not all(isinstance(item, str) for item in reasons)
                or isinstance(confidence, bool)
                or not isinstance(confidence, (int, float))
                or not 0.0 <= float(confidence) <= 1.0
                or isinstance(retention_confidence, bool)
                or not isinstance(retention_confidence, (int, float))
                or not 0.0 <= float(retention_confidence) <= 1.0
            ):
                raise RuntimeError("classificazione MLX locale non valida")
            return Classification(
                category=EmailCategory(str(response["category"])),
                confidence=float(confidence),
                reason_codes=tuple(reasons),
                classifier=f"mlx:{self.model_name}",
                retention=RetentionSignal(str(response["retention"])),
                retention_confidence=float(retention_confidence),
            )
        except (BrokenPipeError, KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("classificazione MLX locale fallita") from exc

    def extract_lifecycle(
        self,
        message: EmailRecord,
        expected_kind: UtilityKind,
        now: datetime,
    ) -> LifecycleObservation:
        if expected_kind is UtilityKind.NONE:
            raise ValueError("lifecycle kind is required")
        if now.tzinfo is None:
            raise ValueError("now must include a timezone")
        request = {
            "task": "lifecycle",
            "expected_kind": expected_kind.value,
            "now_date": now.date().isoformat(),
            "sender": message.sender,
            "subject": message.subject,
            "body": message.body_text,
        }
        try:
            response = self._request_response(request)
            if response.get("type") != "lifecycle":
                raise RuntimeError("estrazione ciclo di vita MLX fallita")
            utility = response.get("utility")
            reasons = response.get("reason_codes")
            if (
                not isinstance(utility, dict)
                or set(utility) != {
                    "operational",
                    "evidentiary",
                    "personal",
                    "security",
                }
                or any(type(utility[name]) is not bool for name in utility)
                or not isinstance(reasons, list)
                or len(reasons) > 6
                or any(
                    not isinstance(item, str) or item not in LIFECYCLE_REASON_CODES
                    for item in reasons
                )
            ):
                raise RuntimeError("estrazione ciclo di vita MLX non valida")
            kind = UtilityKind(str(response["kind"]))
            if kind is UtilityKind.NONE or kind is not expected_kind:
                raise RuntimeError("tipo ciclo di vita MLX inatteso")
            confidence = response["confidence"]
            if (
                isinstance(confidence, bool)
                or not isinstance(confidence, (int, float))
                or not 0.0 <= float(confidence) <= 1.0
            ):
                raise RuntimeError("confidenza ciclo di vita MLX non valida")
            return LifecycleObservation(
                kind=kind,
                state=LifecycleState(str(response["state"])),
                utility=UtilityVector(
                    operational=utility["operational"],
                    evidentiary=utility["evidentiary"],
                    personal=utility["personal"],
                    security=utility["security"],
                ),
                date_relation=DateRelation(str(response["date_relation"])),
                condition=LifecycleCondition(str(response["condition"])),
                confidence=float(confidence),
                reason_codes=tuple(reasons),
                extractor=f"mlx-lifecycle:{self.model_name}",
            )
        except (BrokenPipeError, KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("estrazione ciclo di vita MLX fallita") from exc

    def assess_threat_semantics(self, message: EmailRecord) -> SemanticThreatAssessment:
        request = {
            "task": "threat",
            "sender": message.sender,
            "subject": message.subject,
            "body": message.body_text,
        }
        try:
            response = self._request_response(request)
            if response.get("type") != "threat":
                raise RuntimeError("analisi semantica minacce MLX fallita")
            raw = {key: value for key, value in response.items() if key != "type"}
            return parse_semantic_threat_mapping(
                raw,
                analyzer=f"mlx-threat:{self.model_name}",
            )
        except (BrokenPipeError, KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("analisi semantica minacce MLX fallita") from exc

    def close(self) -> None:
        process = getattr(self, "process", None)
        if process is None:
            return
        if process.stdin is not None and process.poll() is None:
            try:
                self._request_response(
                    {"type": "stop"},
                    write_timeout_seconds=2.0,
                    response_timeout_seconds=2.0,
                )
            except RuntimeError:
                self._terminate_process_tree()
            try:
                process.stdin.close()
            except (BrokenPipeError, OSError, ValueError):
                pass
        elif process.stdin is not None and not process.stdin.closed:
            process.stdin.close()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self._terminate_process_tree()
        for reader_name in ("_stdout_reader", "_stderr_reader"):
            reader = getattr(self, reader_name, None)
            if reader is not None:
                reader.join(timeout=1)
        for stream_name in ("stdout", "stderr"):
            stream = getattr(process, stream_name, None)
            if stream is not None and not stream.closed:
                stream.close()

    def unload(self) -> None:
        self.close()


def _predict_not_interested(
    message: EmailRecord,
    classification: Classification,
    policy: AccountPolicy,
    now: datetime,
) -> bool:
    if (
        classification.category is EmailCategory.ONE_TIME_CODE
        and classification.confidence >= policy.review_confidence
        and not message.unread
        and message.age_days(now) >= policy.read_one_time_code_age_days
    ):
        return True
    if (
        classification.confidence < policy.review_confidence
        or classification.retention is not RetentionSignal.DISCARD_CANDIDATE
        or classification.retention_confidence < policy.review_confidence
    ):
        return False
    if classification.category in {
        EmailCategory.ADVERTISING,
        EmailCategory.SOCIAL,
        EmailCategory.SPAM,
    }:
        return True
    return False


def evaluate_classifier(
    model_name: str,
    classifier,
    labeled_messages: Iterable[tuple[EmailRecord, str]],
    policy: AccountPolicy,
    now: datetime,
) -> dict[str, Any]:
    engine = SafetyPolicyEngine()
    categories: Counter[str] = Counter()
    retentions: Counter[str] = Counter()
    actions: Counter[str] = Counter()
    labels: Counter[str] = Counter()
    predicted_not_interested = 0
    false_cleanup_on_keep = 0
    cleanup_match_on_dont_keep = 0
    policy_quarantine_on_keep = 0
    policy_quarantine_on_dont_keep = 0
    model_failures = 0
    guardrail_classifications = 0
    started = time.monotonic()

    for message, answer in labeled_messages:
        classification = classifier.classify(message)
        decision = engine.decide(message, classification, policy, now)
        categories[classification.category.value] += 1
        retentions[classification.retention.value] += 1
        actions[decision.action.value] += 1
        labels[answer] += 1
        if "local_model_fallback" in classification.reason_codes:
            model_failures += 1
        elif classification.classifier.startswith("heuristic"):
            guardrail_classifications += 1

        predicts_cleanup = _predict_not_interested(message, classification, policy, now)
        predicted_not_interested += int(predicts_cleanup)
        false_cleanup_on_keep += int(answer == "keep" and predicts_cleanup)
        cleanup_match_on_dont_keep += int(answer == "dont_keep" and predicts_cleanup)
        policy_quarantine_on_keep += int(
            answer == "keep" and decision.action is PolicyAction.QUARANTINE
        )
        policy_quarantine_on_dont_keep += int(
            answer == "dont_keep" and decision.action is PolicyAction.QUARANTINE
        )

    keep = labels["keep"]
    dont_keep = labels["dont_keep"]
    evaluated = keep + dont_keep
    correct_interest = (keep - false_cleanup_on_keep) + cleanup_match_on_dont_keep
    return {
        "model": model_name,
        "evaluated": evaluated,
        "ignored_unsure": labels["unsure"],
        "keep_labels": keep,
        "dont_keep_labels": dont_keep,
        "interest_accuracy": round(correct_interest / evaluated, 4) if evaluated else None,
        "false_cleanup_on_keep": false_cleanup_on_keep,
        "cleanup_matches_on_dont_keep": cleanup_match_on_dont_keep,
        "cleanup_recall": round(cleanup_match_on_dont_keep / dont_keep, 4)
        if dont_keep
        else None,
        "policy_quarantine_on_keep": policy_quarantine_on_keep,
        "policy_quarantine_on_dont_keep": policy_quarantine_on_dont_keep,
        "predicted_not_interested": predicted_not_interested,
        "model_failures": model_failures,
        "guardrail_classifications": guardrail_classifications,
        "categories": dict(sorted(categories.items())),
        "content_assessments": dict(sorted(retentions.items())),
        "policy_actions": dict(sorted(actions.items())),
        "elapsed_seconds": round(time.monotonic() - started, 2),
    }


def evaluate_local_models(
    model_names: list[str],
    labeled_messages: list[tuple[EmailRecord, str]],
    policy: AccountPolicy,
    now: datetime,
    progress: Callable[[str], None] | None = None,
) -> list[dict[str, Any]]:
    if not model_names or any(name not in MODEL_NAMES for name in model_names):
        raise ValueError("elenco modelli non valido")
    results: list[dict[str, Any]] = []
    for name in model_names:
        if progress is not None:
            progress(name)
        heuristic = HeuristicClassifier()
        if name == "qwen8":
            local = OllamaClassifier("qwen3-vl:8b")
            classifier = HybridClassifier(local, heuristic)
            try:
                results.append(
                    evaluate_classifier(name, classifier, labeled_messages, policy, now)
                )
            finally:
                try:
                    local.unload()
                except RuntimeError:
                    pass
            continue

        local = MlxWorkerClassifier(name)
        classifier = HybridClassifier(local, heuristic)
        try:
            results.append(evaluate_classifier(name, classifier, labeled_messages, policy, now))
        finally:
            local.close()
    return results
