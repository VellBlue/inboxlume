from __future__ import annotations

import hashlib
import hmac
import base64
import binascii
import math
import os
import re
import secrets
import sqlite3
import stat
import tempfile
import unicodedata
from contextlib import closing, contextmanager
from dataclasses import dataclass
from email.utils import parseaddr
from enum import StrEnum
from pathlib import Path
from datetime import datetime, timezone
from typing import Callable, Iterable, Mapping, Protocol

from .lumegraph import (
    LifecycleCondition,
    LifecycleObservation,
    LifecycleState,
    UtilityKind,
    transition_for_state,
)
from .models import (
    Classification,
    EmailCategory,
    EmailRecord,
    PolicyDecision,
    PreferenceSnapshot,
    ProviderKind,
)
from .proof_of_obsolescence import (
    PROOF_ENGINE_VERSION,
    ObsolescenceProof,
    ProofStatus,
    StoredLifecycleEvidence,
    has_hard_policy_reason,
    successor_transition_proof,
)
from .threat_signals import (
    THREAT_CONSENSUS_ENGINE_VERSION,
    ThreatConsensusAssessment,
    ThreatSemanticMode,
)


# Identificatore legacy intenzionalmente stabile: cambiarlo perderebbe l'accesso
# alla chiave HMAC delle preferenze gia apprese.
PREFERENCE_HMAC_KEYCHAIN_SERVICE = "it.local.mail-guardian.preference-hmac.v1"
_STATE_KEY_CHECK_CONTEXT = b"inboxlume-state-key-check-v1\0"


class PreferenceSecretStore(Protocol):
    def get(self, service: str, account: str) -> str | None: ...

    def set(self, service: str, account: str, secret: str) -> None: ...


@contextmanager
def _exclusive_key_creation_lock(path: Path):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        mode = os.fstat(descriptor).st_mode
        if not stat.S_ISREG(mode):
            raise RuntimeError("lock chiave HMAC non valido")
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX)
        else:  # pragma: no cover - exercised by the Windows package smoke test
            import msvcrt

            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"\0")
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
        yield
    finally:
        try:
            if os.name != "nt":
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
            else:  # pragma: no cover - exercised on Windows
                import msvcrt

                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        finally:
            os.close(descriptor)


def _decode_hmac_key(encoded: str) -> bytes:
    try:
        key = base64.b64decode(encoded, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("chiave HMAC nel Portachiavi non valida") from exc
    if len(key) != 32:
        raise ValueError("chiave HMAC nel Portachiavi non valida")
    return key


def _database_contains_account_state(database_path: Path, account_id: str) -> bool:
    """Fail closed for legacy/corrupt DBs; allow a genuinely new shared account."""

    try:
        uri = f"{database_path.resolve().as_uri()}?mode=ro"
        with closing(sqlite3.connect(uri, uri=True)) as connection:
            tables = [
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
                if isinstance(row[0], str) and not str(row[0]).startswith("sqlite_")
            ]
            if not tables:
                return True
            saw_binding_table = "state_key_binding" in tables
            for table in tables:
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", table) is None:
                    return True
                columns = {
                    str(row[1])
                    for row in connection.execute(f'PRAGMA table_info("{table}")')
                }
                if "account_id" not in columns:
                    continue
                row = connection.execute(
                    f'SELECT 1 FROM "{table}" WHERE account_id = ? LIMIT 1',
                    (account_id,),
                ).fetchone()
                if row is not None:
                    return True
            # A modern shared DB can safely add a new account.  A legacy DB
            # without bindings has no reliable way to distinguish lost state.
            return not saw_binding_table
    except (OSError, sqlite3.Error, ValueError):
        return True


def load_or_create_hmac_key(
    store: PreferenceSecretStore,
    account_id: str,
    state_db: str | Path | None = None,
) -> bytes:
    """Conserva nel Portachiavi la chiave che rende opache le preferenze locali."""

    if not account_id.strip() or len(account_id) > 512 or "\0" in account_id:
        raise ValueError("account_id HMAC non valido")
    database_path = Path(state_db) if state_db is not None else None
    # The keyring identity is (service, account), not (database, account).
    # Every database path must therefore contend on the same creation lock.
    lock_identity = (
        f"{PREFERENCE_HMAC_KEYCHAIN_SERVICE}\0{account_id}".encode("utf-8")
    )
    user_suffix = str(os.getuid()) if hasattr(os, "getuid") else "user"
    lock_path = (
        Path(tempfile.gettempdir())
        / f"inboxlume-hmac-locks-{user_suffix}"
        / f"{hashlib.sha256(lock_identity).hexdigest()}.lock"
    )
    with _exclusive_key_creation_lock(lock_path):
        encoded = store.get(PREFERENCE_HMAC_KEYCHAIN_SERVICE, account_id)
        if encoded is not None:
            return _decode_hmac_key(encoded)
        if (
            database_path is not None
            and database_path.exists()
            and database_path.stat().st_size > 0
            and _database_contains_account_state(database_path, account_id)
        ):
            raise RuntimeError(
                "chiave HMAC locale mancante per un database esistente; "
                "azioni sulla posta bloccate"
            )
        key = secrets.token_bytes(32)
        store.set(
            PREFERENCE_HMAC_KEYCHAIN_SERVICE,
            account_id,
            base64.urlsafe_b64encode(key).decode("ascii"),
        )
        persisted = store.get(PREFERENCE_HMAC_KEYCHAIN_SERVICE, account_id)
        if persisted is None:
            raise RuntimeError("salvataggio chiave HMAC locale non confermato")
        return _decode_hmac_key(persisted)


class FeedbackSignal(StrEnum):
    OPENED = "opened"
    REPLIED = "replied"
    STARRED = "starred"
    MARKED_IMPORTANT = "marked_important"
    EXPLICIT_KEEP = "explicit_keep"
    RESTORED = "restored"
    LEFT_UNREAD = "left_unread"
    EXPLICIT_NOT_INTERESTED = "explicit_not_interested"


@dataclass(frozen=True, slots=True)
class _SignalWeight:
    positive: float
    negative: float


_WEIGHTS = {
    FeedbackSignal.OPENED: _SignalWeight(1.0, 0.0),
    FeedbackSignal.REPLIED: _SignalWeight(3.0, 0.0),
    FeedbackSignal.STARRED: _SignalWeight(3.0, 0.0),
    FeedbackSignal.MARKED_IMPORTANT: _SignalWeight(3.0, 0.0),
    FeedbackSignal.EXPLICIT_KEEP: _SignalWeight(4.0, 0.0),
    FeedbackSignal.RESTORED: _SignalWeight(5.0, 0.0),
    # Non aprire può significare semplicemente non aver visto una mail importante.
    FeedbackSignal.LEFT_UNREAD: _SignalWeight(0.0, 0.15),
    FeedbackSignal.EXPLICIT_NOT_INTERESTED: _SignalWeight(0.0, 3.0),
}


_CONTENT_STOPWORDS = frozenset(
    {
        "alla",
        "alle",
        "anche",
        "che",
        "con",
        "dalla",
        "delle",
        "dello",
        "dove",
        "email",
        "from",
        "have",
        "mail",
        "nella",
        "nelle",
        "non",
        "per",
        "sono",
        "that",
        "the",
        "this",
        "una",
        "your",
    }
)


def _template_tokens(text: str, limit: int) -> tuple[str, ...]:
    """Token stabili per somiglianza; numeri, URL e indirizzi non sono conservati."""

    normalized = unicodedata.normalize("NFKC", text).casefold()
    normalized = re.sub(r"https?://\S+|www\.\S+", " url ", normalized)
    normalized = re.sub(r"\b[^\s@]+@[^\s@]+\b", " address ", normalized)
    normalized = re.sub(r"\d+", " number ", normalized)
    tokens = re.findall(r"[a-zà-öø-ÿ][a-zà-öø-ÿ_-]{2,}", normalized)
    return tuple(token for token in tokens if token not in _CONTENT_STOPWORDS)[:limit]


def _content_similarity_features(message: EmailRecord) -> tuple[str, ...]:
    """Feature testuali effimere; il database riceve esclusivamente i loro HMAC."""

    subject = _template_tokens(message.subject, 24)
    body = _template_tokens(message.body_text, 96)
    features: set[str] = set()
    if subject:
        features.add(f"subject-template:{' '.join(subject[:16])}")
    for size, prefix, tokens, cap in (
        (2, "subject-pair", subject, 20),
        (3, "body-trigram", body, 48),
    ):
        for index in range(max(0, len(tokens) - size + 1)):
            features.add(f"{prefix}:{' '.join(tokens[index:index + size])}")
            if len([item for item in features if item.startswith(f"{prefix}:")]) >= cap:
                break
    return tuple(sorted(features))


class PreferenceStore:
    """Memorizza solo feature HMAC; mai oggetto, corpo o indirizzo in chiaro."""

    def __init__(
        self,
        path: str | Path,
        hmac_key: bytes,
        account_id: str | None = None,
    ) -> None:
        if len(hmac_key) < 32:
            raise ValueError("hmac_key deve contenere almeno 32 byte")
        database_path = Path(path)
        database_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if database_path.is_symlink():
            raise RuntimeError("database preferenze simbolico non consentito")
        self.path = str(database_path)
        self.hmac_key = hmac_key
        self._bound_accounts: set[str] = set()
        self._initialize()
        if account_id is not None:
            self._ensure_key_binding(account_id)

    def _connect(self) -> sqlite3.Connection:
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.path, flags, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise RuntimeError("database preferenze non regolare")
            if os.name != "nt":
                os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)
        connection = sqlite3.connect(self.path)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            with connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS state_key_binding (
                        account_id TEXT PRIMARY KEY,
                        key_check TEXT NOT NULL
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS preference (
                        account_id TEXT NOT NULL,
                        feature_hash TEXT NOT NULL,
                        positive REAL NOT NULL DEFAULT 0,
                        negative REAL NOT NULL DEFAULT 0,
                        observations INTEGER NOT NULL DEFAULT 0,
                        PRIMARY KEY (account_id, feature_hash)
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS shadow_scan (
                        account_id TEXT NOT NULL,
                        message_hash TEXT NOT NULL,
                        scan_profile TEXT NOT NULL,
                        scanned_at TEXT NOT NULL,
                        category TEXT NOT NULL,
                        suggested_action TEXT NOT NULL,
                        reason_codes TEXT,
                        policy_fingerprint TEXT,
                        processing_complete INTEGER NOT NULL DEFAULT 0,
                        hard_protected INTEGER NOT NULL DEFAULT 0,
                        PRIMARY KEY (account_id, message_hash, scan_profile)
                    )
                    """
                )
                shadow_columns = {
                    str(row[1])
                    for row in connection.execute(
                        "PRAGMA table_info(shadow_scan)"
                    ).fetchall()
                }
                if "reason_codes" not in shadow_columns:
                    connection.execute(
                        "ALTER TABLE shadow_scan ADD COLUMN reason_codes TEXT"
                    )
                if "policy_fingerprint" not in shadow_columns:
                    connection.execute(
                        "ALTER TABLE shadow_scan ADD COLUMN policy_fingerprint TEXT"
                    )
                if "processing_complete" not in shadow_columns:
                    connection.execute(
                        "ALTER TABLE shadow_scan ADD COLUMN "
                        "processing_complete INTEGER NOT NULL DEFAULT 0"
                    )
                if "hard_protected" not in shadow_columns:
                    # Existing complete rows predate this safety fact.  Treat
                    # them as protected and retryable until current policy code
                    # has evaluated them again; never infer safety from a
                    # partially migrated ledger.
                    connection.execute(
                        "ALTER TABLE shadow_scan ADD COLUMN "
                        "hard_protected INTEGER NOT NULL DEFAULT 1"
                    )
                    connection.execute(
                        "UPDATE shadow_scan SET processing_complete = 0"
                    )
                threat_assessment_existed = connection.execute(
                    "SELECT 1 FROM sqlite_master "
                    "WHERE type = 'table' AND name = 'threat_assessment'"
                ).fetchone() is not None
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS threat_assessment (
                        account_id TEXT NOT NULL,
                        message_hash TEXT NOT NULL,
                        scan_profile TEXT NOT NULL,
                        assessed_at TEXT NOT NULL,
                        engine_version TEXT NOT NULL,
                        level TEXT NOT NULL,
                        score_bucket INTEGER NOT NULL,
                        semantic_verdict TEXT NOT NULL,
                        semantic_intent TEXT NOT NULL,
                        deterministic_signals TEXT NOT NULL,
                        signal_families TEXT NOT NULL,
                        semantic_reason_codes TEXT NOT NULL,
                        analyzer TEXT NOT NULL,
                        independent_consensus INTEGER NOT NULL,
                        protective_review INTEGER NOT NULL,
                        PRIMARY KEY (account_id, message_hash, scan_profile)
                    )
                    """
                )
                if not threat_assessment_existed:
                    # A legacy completed shadow row without the Threat ledger
                    # cannot prove that the protective stage ever ran.
                    connection.execute(
                        "UPDATE shadow_scan SET processing_complete = 0"
                    )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS threat_marker_execution (
                        account_id TEXT NOT NULL,
                        message_hash TEXT NOT NULL,
                        scan_profile TEXT NOT NULL,
                        marked_at TEXT NOT NULL,
                        marker_kind TEXT NOT NULL,
                        outcome TEXT NOT NULL,
                        PRIMARY KEY (account_id, message_hash, scan_profile)
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS quiz_answer (
                        account_id TEXT NOT NULL,
                        message_hash TEXT NOT NULL,
                        answer TEXT NOT NULL,
                        answered_at TEXT,
                        PRIMARY KEY (account_id, message_hash)
                    )
                    """
                )
                quiz_columns = {
                    str(row[1])
                    for row in connection.execute(
                        "PRAGMA table_info(quiz_answer)"
                    ).fetchall()
                }
                if "answered_at" not in quiz_columns:
                    connection.execute(
                        "ALTER TABLE quiz_answer ADD COLUMN answered_at TEXT"
                    )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS similarity_example (
                        account_id TEXT NOT NULL,
                        message_hash TEXT NOT NULL,
                        answer TEXT NOT NULL,
                        feature_count INTEGER NOT NULL,
                        PRIMARY KEY (account_id, message_hash)
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS similarity_feature (
                        account_id TEXT NOT NULL,
                        message_hash TEXT NOT NULL,
                        feature_hash TEXT NOT NULL,
                        PRIMARY KEY (account_id, message_hash, feature_hash),
                        FOREIGN KEY (account_id, message_hash)
                            REFERENCES similarity_example(account_id, message_hash)
                            ON DELETE CASCADE
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS quarantine_pilot_execution (
                        account_id TEXT NOT NULL,
                        message_hash TEXT NOT NULL,
                        scan_profile TEXT NOT NULL,
                        executed_at TEXT NOT NULL,
                        outcome TEXT NOT NULL,
                        PRIMARY KEY (account_id, message_hash, scan_profile)
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS quarantine_location (
                        account_id TEXT NOT NULL,
                        message_hash TEXT NOT NULL,
                        provider TEXT NOT NULL,
                        scan_profile TEXT NOT NULL,
                        folder TEXT NOT NULL,
                        uid_validity TEXT NOT NULL,
                        uid TEXT NOT NULL,
                        located_at TEXT NOT NULL,
                        PRIMARY KEY (account_id, message_hash, scan_profile)
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS quarantine_finalization (
                        account_id TEXT NOT NULL,
                        message_hash TEXT NOT NULL,
                        scan_profile TEXT NOT NULL,
                        finalized_at TEXT NOT NULL,
                        outcome TEXT NOT NULL,
                        PRIMARY KEY (account_id, message_hash, scan_profile)
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS behavior_message (
                        account_id TEXT NOT NULL,
                        message_hash TEXT NOT NULL,
                        provider TEXT NOT NULL,
                        registered_at TEXT NOT NULL,
                        content_feature_count INTEGER NOT NULL,
                        PRIMARY KEY (account_id, message_hash)
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS behavior_feature (
                        account_id TEXT NOT NULL,
                        message_hash TEXT NOT NULL,
                        feature_hash TEXT NOT NULL,
                        feature_kind TEXT NOT NULL,
                        PRIMARY KEY (account_id, message_hash, feature_hash),
                        FOREIGN KEY (account_id, message_hash)
                            REFERENCES behavior_message(account_id, message_hash)
                            ON DELETE CASCADE
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS behavior_event (
                        account_id TEXT NOT NULL,
                        message_hash TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        observed_at TEXT NOT NULL,
                        PRIMARY KEY (account_id, message_hash, event_type),
                        FOREIGN KEY (account_id, message_hash)
                            REFERENCES behavior_message(account_id, message_hash)
                            ON DELETE CASCADE
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS gmail_history_cursor (
                        account_id TEXT PRIMARY KEY,
                        history_id TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS yahoo_uid_cursor (
                        account_id TEXT PRIMARY KEY,
                        uid_validity TEXT NOT NULL,
                        last_uid TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS provider_identity (
                        account_id TEXT NOT NULL,
                        provider TEXT NOT NULL,
                        identity_hash TEXT NOT NULL,
                        message_hash TEXT NOT NULL,
                        PRIMARY KEY (
                            account_id, provider, identity_hash, message_hash
                        ),
                        FOREIGN KEY (account_id, message_hash)
                            REFERENCES behavior_message(account_id, message_hash)
                            ON DELETE CASCADE
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS safety_backtest_run (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        account_id TEXT NOT NULL,
                        scan_profile TEXT NOT NULL,
                        engine_version TEXT NOT NULL,
                        evidence_fingerprint TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS safety_backtest_family (
                        run_id INTEGER NOT NULL,
                        category TEXT NOT NULL,
                        keep_count INTEGER NOT NULL,
                        dont_keep_count INTEGER NOT NULL,
                        unsure_count INTEGER NOT NULL,
                        unreviewed_count INTEGER NOT NULL,
                        PRIMARY KEY (run_id, category),
                        FOREIGN KEY (run_id)
                            REFERENCES safety_backtest_run(id)
                            ON DELETE CASCADE
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS scan_timing_sample (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        account_id TEXT NOT NULL,
                        scan_profile TEXT NOT NULL,
                        hardware_key TEXT NOT NULL,
                        provider TEXT NOT NULL,
                        destination TEXT NOT NULL,
                        governor_enforced INTEGER NOT NULL,
                        processed_messages INTEGER NOT NULL,
                        elapsed_seconds REAL NOT NULL,
                        recorded_at TEXT NOT NULL
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS lumegraph_node (
                        account_id TEXT NOT NULL,
                        message_hash TEXT NOT NULL,
                        scan_profile TEXT NOT NULL,
                        event_hash TEXT,
                        utility_kind TEXT NOT NULL,
                        lifecycle_state TEXT NOT NULL,
                        operational INTEGER NOT NULL,
                        evidentiary INTEGER NOT NULL,
                        personal INTEGER NOT NULL,
                        security INTEGER NOT NULL,
                        date_relation TEXT NOT NULL,
                        lifecycle_condition TEXT NOT NULL,
                        confidence_bucket INTEGER NOT NULL,
                        reason_codes TEXT NOT NULL,
                        extractor TEXT NOT NULL,
                        received_week INTEGER NOT NULL DEFAULT 0,
                        hard_protected INTEGER NOT NULL DEFAULT 1,
                        observed_at TEXT NOT NULL,
                        PRIMARY KEY (account_id, message_hash, scan_profile)
                    )
                    """
                )
                lumegraph_columns = {
                    str(row[1])
                    for row in connection.execute(
                        "PRAGMA table_info(lumegraph_node)"
                    ).fetchall()
                }
                if "lifecycle_condition" not in lumegraph_columns:
                    connection.execute(
                        "ALTER TABLE lumegraph_node ADD COLUMN "
                        "lifecycle_condition TEXT NOT NULL DEFAULT 'uncertain'"
                    )
                if "received_week" not in lumegraph_columns:
                    connection.execute(
                        "ALTER TABLE lumegraph_node ADD COLUMN "
                        "received_week INTEGER NOT NULL DEFAULT 0"
                    )
                if "hard_protected" not in lumegraph_columns:
                    # Existing research nodes are deliberately ineligible for a proof.
                    connection.execute(
                        "ALTER TABLE lumegraph_node ADD COLUMN "
                        "hard_protected INTEGER NOT NULL DEFAULT 1"
                    )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS lumegraph_transition (
                        account_id TEXT NOT NULL,
                        event_hash TEXT NOT NULL,
                        scan_profile TEXT NOT NULL,
                        from_message_hash TEXT NOT NULL,
                        to_message_hash TEXT NOT NULL,
                        transition_kind TEXT NOT NULL,
                        observed_at TEXT NOT NULL,
                        PRIMARY KEY (
                            account_id, event_hash, scan_profile,
                            from_message_hash, to_message_hash
                        )
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS lumegraph_relation (
                        account_id TEXT NOT NULL,
                        message_hash TEXT NOT NULL,
                        scan_profile TEXT NOT NULL,
                        relation_hash TEXT NOT NULL,
                        PRIMARY KEY (
                            account_id, message_hash, scan_profile, relation_hash
                        ),
                        FOREIGN KEY (account_id, message_hash, scan_profile)
                            REFERENCES lumegraph_node(
                                account_id, message_hash, scan_profile
                            ) ON DELETE CASCADE
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS obsolescence_proof (
                        account_id TEXT NOT NULL,
                        message_hash TEXT NOT NULL,
                        scan_profile TEXT NOT NULL,
                        engine_version TEXT NOT NULL,
                        status TEXT NOT NULL,
                        witness TEXT NOT NULL,
                        maximum_destination TEXT NOT NULL,
                        confidence_bucket INTEGER NOT NULL,
                        reason_codes TEXT NOT NULL,
                        source_message_hash TEXT,
                        created_at TEXT NOT NULL,
                        PRIMARY KEY (
                            account_id, message_hash, scan_profile, engine_version
                        )
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS similarity_feature_lookup
                    ON similarity_feature(account_id, feature_hash)
                    """
                )
                connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS behavior_feature_lookup
                    ON behavior_feature(account_id, feature_kind, feature_hash)
                    """
                )
                connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS safety_backtest_latest
                    ON safety_backtest_run(
                        account_id, scan_profile, engine_version, id DESC
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS scan_timing_lookup
                    ON scan_timing_sample(
                        account_id, scan_profile, hardware_key, provider,
                        destination, governor_enforced, id DESC
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS lumegraph_event_lookup
                    ON lumegraph_node(
                        account_id, event_hash, scan_profile, observed_at
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS lumegraph_relation_lookup
                    ON lumegraph_relation(account_id, relation_hash, scan_profile)
                    """
                )
                connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS obsolescence_proof_lookup
                    ON obsolescence_proof(
                        account_id, scan_profile, status, witness
                    )
                    """
                )

    def _ensure_key_binding(self, account_id: str) -> None:
        if account_id in self._bound_accounts:
            return
        if not account_id.strip() or len(account_id) > 512 or "\0" in account_id:
            raise ValueError("account_id HMAC non valido")
        expected = hmac.new(
            self.hmac_key,
            _STATE_KEY_CHECK_CONTEXT + account_id.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        with closing(self._connect()) as connection:
            with connection:
                row = connection.execute(
                    "SELECT key_check FROM state_key_binding WHERE account_id = ?",
                    (account_id,),
                ).fetchone()
                if row is None:
                    connection.execute(
                        "INSERT INTO state_key_binding(account_id, key_check) VALUES (?, ?)",
                        (account_id, expected),
                    )
                elif not hmac.compare_digest(str(row[0]), expected):
                    raise RuntimeError(
                        "chiave HMAC locale non corrisponde al database; "
                        "azioni sulla posta bloccate"
                    )
        self._bound_accounts.add(account_id)

    def _hash(self, account_id: str, feature: str) -> str:
        self._ensure_key_binding(account_id)
        material = f"{account_id}\0{feature.casefold()}".encode("utf-8")
        return hmac.new(self.hmac_key, material, hashlib.sha256).hexdigest()

    @staticmethod
    def _features(message: EmailRecord, classification: Classification) -> tuple[str, ...]:
        sender = parseaddr(message.sender)[1].strip().casefold()
        domain = sender.rsplit("@", 1)[-1] if "@" in sender else sender
        return (
            f"sender:{sender}",
            f"domain:{domain}",
            f"category:{classification.category.value}",
        )

    def observe(
        self,
        message: EmailRecord,
        classification: Classification,
        signal: FeedbackSignal,
    ) -> None:
        weight = _WEIGHTS[signal]
        with closing(self._connect()) as connection:
            with connection:
                self._observe_with_connection(connection, message, classification, weight)

    def _observe_with_connection(
        self,
        connection: sqlite3.Connection,
        message: EmailRecord,
        classification: Classification,
        weight: _SignalWeight,
    ) -> None:
        for feature in self._features(message, classification):
            feature_hash = self._hash(message.account_id, feature)
            connection.execute(
                """
                INSERT INTO preference(account_id, feature_hash, positive, negative, observations)
                VALUES (?, ?, ?, ?, 1)
                ON CONFLICT(account_id, feature_hash) DO UPDATE SET
                    positive = positive + excluded.positive,
                    negative = negative + excluded.negative,
                    observations = observations + 1
                """,
                (message.account_id, feature_hash, weight.positive, weight.negative),
            )

    def interest_for(
        self,
        message: EmailRecord,
        classification: Classification,
        now: datetime | None = None,
    ) -> PreferenceSnapshot:
        totals = [0.0, 0.0, 0]
        with closing(self._connect()) as connection:
            for feature in self._features(message, classification):
                row = connection.execute(
                    """
                    SELECT positive, negative, observations
                    FROM preference WHERE account_id = ? AND feature_hash = ?
                    """,
                    (message.account_id, self._hash(message.account_id, feature)),
                ).fetchone()
                if row:
                    totals[0] += float(row[0])
                    totals[1] += float(row[1])
                    totals[2] += int(row[2])
        # Prior volutamente favorevole alla conservazione.
        score = (3.0 + totals[0]) / (4.0 + totals[0] + totals[1])
        similarities = self._similarity_for(message)
        recent = self._recent_content_interest(message, now)
        return PreferenceSnapshot(
            score=score,
            observations=totals[2],
            keep_similarity=similarities["keep_similarity"],
            dont_keep_similarity=similarities["dont_keep_similarity"],
            keep_similar_examples=similarities["keep_similar_examples"],
            dont_keep_similar_examples=similarities["dont_keep_similar_examples"],
            recent_content_score=recent["score"],
            recent_content_evidence=recent["evidence"],
            recent_content_examples=recent["examples"],
        )

    def _recent_content_interest(
        self,
        message: EmailRecord,
        now: datetime | None,
    ) -> dict[str, float | int]:
        if now is None:
            return {"score": 0.5, "evidence": 0.0, "examples": 0}
        if now.tzinfo is None:
            raise ValueError("now deve includere il fuso orario")
        content_features = _content_similarity_features(message)
        if not content_features:
            return {"score": 0.5, "evidence": 0.0, "examples": 0}
        feature_hashes = tuple(
            self._hash(message.account_id, f"behavior-content:{feature}")
            for feature in content_features
        )
        placeholders = ",".join("?" for _ in feature_hashes)
        with closing(self._connect()) as connection:
            rows = connection.execute(
                f"""
                SELECT be.message_hash, be.event_type, be.observed_at,
                       bm.content_feature_count, COUNT(DISTINCT bf.feature_hash)
                FROM behavior_event AS be
                JOIN behavior_message AS bm
                  ON bm.account_id = be.account_id
                 AND bm.message_hash = be.message_hash
                JOIN behavior_feature AS bf
                  ON bf.account_id = be.account_id
                 AND bf.message_hash = be.message_hash
                WHERE be.account_id = ?
                  AND bf.feature_kind = 'content'
                  AND bf.feature_hash IN ({placeholders})
                GROUP BY be.message_hash, be.event_type, be.observed_at,
                         bm.content_feature_count
                """,
                (message.account_id, *feature_hashes),
            ).fetchall()
        positive = 0.0
        negative = 0.0
        evidence = 0.0
        examples: set[str] = set()
        current_count = len(feature_hashes)
        for raw_hash, raw_event, raw_at, raw_count, raw_intersection in rows:
            denominator = current_count + int(raw_count)
            similarity = (
                2.0 * int(raw_intersection) / denominator if denominator else 0.0
            )
            if similarity < 0.55:
                continue
            try:
                event = FeedbackSignal(str(raw_event))
                observed_at = datetime.fromisoformat(str(raw_at))
            except (ValueError, TypeError):
                continue
            if observed_at.tzinfo is None:
                continue
            age_days = max(0.0, (now - observed_at).total_seconds() / 86_400)
            decay = 0.5 ** (age_days / 45.0)
            weight = _WEIGHTS[event]
            positive += weight.positive * decay
            negative += weight.negative * decay
            evidence += (weight.positive + weight.negative) * decay
            examples.add(str(raw_hash))
        return {
            "score": (1.0 + positive) / (2.0 + positive + negative),
            "evidence": evidence,
            "examples": len(examples),
        }

    def _similarity_for(self, message: EmailRecord) -> dict[str, float | int]:
        features = _content_similarity_features(message)
        result: dict[str, float | int] = {
            "keep_similarity": 0.0,
            "dont_keep_similarity": 0.0,
            "keep_similar_examples": 0,
            "dont_keep_similar_examples": 0,
        }
        if not features:
            return result
        feature_hashes = [
            self._hash(message.account_id, f"content:{feature}") for feature in features
        ]
        placeholders = ",".join("?" for _ in feature_hashes)
        with closing(self._connect()) as connection:
            rows = connection.execute(
                f"""
                SELECT se.answer, se.feature_count, COUNT(*)
                FROM similarity_feature AS sf
                JOIN similarity_example AS se
                  ON se.account_id = sf.account_id
                 AND se.message_hash = sf.message_hash
                WHERE sf.account_id = ?
                  AND sf.feature_hash IN ({placeholders})
                GROUP BY se.message_hash, se.answer, se.feature_count
                """,
                (message.account_id, *feature_hashes),
            ).fetchall()
        current_count = len(feature_hashes)
        for raw_answer, raw_feature_count, raw_intersection in rows:
            answer = str(raw_answer)
            if answer not in {"keep", "dont_keep"}:
                continue
            denominator = current_count + int(raw_feature_count)
            similarity = (2.0 * int(raw_intersection) / denominator) if denominator else 0.0
            key = f"{answer}_similarity"
            result[key] = max(float(result[key]), similarity)
            if similarity >= 0.55:
                count_key = f"{answer}_similar_examples"
                result[count_key] = int(result[count_key]) + 1
        return result

    def _record_similarity_with_connection(
        self,
        connection: sqlite3.Connection,
        message: EmailRecord,
        answer: str,
    ) -> None:
        if answer not in {"keep", "dont_keep"}:
            return
        features = _content_similarity_features(message)
        if not features:
            return
        message_hash = self._hash(
            message.account_id,
            f"message:{message.provider.value}:{message.message_id}",
        )
        feature_hashes = tuple(
            self._hash(message.account_id, f"content:{feature}") for feature in features
        )
        connection.execute(
            """
            INSERT OR IGNORE INTO similarity_example(
                account_id, message_hash, answer, feature_count
            ) VALUES (?, ?, ?, ?)
            """,
            (message.account_id, message_hash, answer, len(feature_hashes)),
        )
        connection.executemany(
            """
            INSERT OR IGNORE INTO similarity_feature(
                account_id, message_hash, feature_hash
            ) VALUES (?, ?, ?)
            """,
            (
                (message.account_id, message_hash, feature_hash)
                for feature_hash in feature_hashes
            ),
        )

    def backfill_similarity_example(self, message: EmailRecord, answer: str) -> None:
        """Aggiunge impronte HMAC per una risposta storica recuperata in RAM."""

        with closing(self._connect()) as connection:
            with connection:
                self._record_similarity_with_connection(connection, message, answer)

    def record_quiz_answer(
        self,
        message: EmailRecord,
        classification: Classification,
        answer: str,
        signal: FeedbackSignal | None,
        answered_at: datetime | None = None,
    ) -> None:
        observed_at = answered_at or datetime.now(timezone.utc)
        if observed_at.tzinfo is None:
            raise ValueError("answered_at deve includere il fuso orario")
        message_hash = self._hash(
            message.account_id,
            f"message:{message.provider.value}:{message.message_id}",
        )
        with closing(self._connect()) as connection:
            with connection:
                existing = connection.execute(
                    """
                    SELECT answer FROM quiz_answer
                    WHERE account_id = ? AND message_hash = ?
                    """,
                    (message.account_id, message_hash),
                ).fetchone()
                # Il quiz non somma due volte lo stesso giudizio in caso di retry.
                if existing is not None:
                    return
                if signal is not None:
                    self._observe_with_connection(
                        connection,
                        message,
                        classification,
                        _WEIGHTS[signal],
                    )
                self._record_similarity_with_connection(connection, message, answer)
                connection.execute(
                    """
                    INSERT INTO quiz_answer(
                        account_id, message_hash, answer, answered_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        message.account_id,
                        message_hash,
                        answer,
                        observed_at.isoformat(),
                    ),
                )

    def temporal_preference_evidence(
        self,
        account_id: str,
        scan_profile: str,
        now: datetime,
        *,
        recent_days: int,
        historical_days: int,
    ) -> dict[str, dict[str, dict[str, int]]]:
        """Aggregate timestamped local signals by semantic family and window."""

        if not account_id.strip() or not scan_profile.strip():
            raise ValueError("account and scan profile are required")
        if now.tzinfo is None:
            raise ValueError("now must include a timezone")
        if not 1 <= recent_days < historical_days <= 3650:
            raise ValueError("invalid temporal evidence windows")
        recent_start = now.timestamp() - recent_days * 86_400
        history_start = now.timestamp() - historical_days * 86_400
        result: dict[str, dict[str, dict[str, int]]] = {}
        query = """
            WITH preference_events AS (
                SELECT ss.category AS category,
                       qa.message_hash AS message_hash,
                       CASE
                         WHEN qa.answer = 'keep' AND qa.answered_at IS NULL
                           THEN 'quiz_keep_legacy'
                         WHEN qa.answer = 'keep' THEN 'quiz_keep'
                         WHEN qa.answer = 'dont_keep' AND qa.answered_at IS NULL
                           THEN 'quiz_dont_keep_legacy'
                         WHEN qa.answer = 'dont_keep' THEN 'quiz_dont_keep'
                       END AS signal,
                       COALESCE(qa.answered_at, ss.scanned_at) AS observed_at
                FROM quiz_answer AS qa
                JOIN shadow_scan AS ss
                  ON ss.account_id = qa.account_id
                 AND ss.message_hash = qa.message_hash
                WHERE ss.account_id = ? AND ss.scan_profile = ?
                  AND ss.processing_complete = 1
                  AND ss.hard_protected = 0
                  AND qa.answer IN ('keep', 'dont_keep')
                UNION ALL
                SELECT ss.category, be.message_hash, be.event_type, be.observed_at
                FROM behavior_event AS be
                JOIN shadow_scan AS ss
                  ON ss.account_id = be.account_id
                 AND ss.message_hash = be.message_hash
                WHERE ss.account_id = ? AND ss.scan_profile = ?
                  AND ss.processing_complete = 1
                  AND ss.hard_protected = 0
                  AND be.event_type IN (
                    'opened', 'starred', 'marked_important', 'restored',
                    'left_unread'
                  )
            )
            SELECT category, message_hash, signal, observed_at
            FROM preference_events
        """
        with closing(self._connect()) as connection:
            rows = connection.execute(
                query,
                (account_id, scan_profile, account_id, scan_profile),
            ).fetchall()
        messages: dict[tuple[str, str], set[str]] = {}
        for raw_category, raw_hash, raw_signal, raw_at in rows:
            try:
                observed = datetime.fromisoformat(str(raw_at))
            except (TypeError, ValueError):
                continue
            if observed.tzinfo is None:
                continue
            timestamp = observed.timestamp()
            if timestamp > now.timestamp() or timestamp < history_start:
                continue
            window = "recent" if timestamp >= recent_start else "historical"
            category = str(raw_category)
            signal = str(raw_signal)
            bucket = result.setdefault(category, {}).setdefault(
                window,
                {},
            )
            bucket[signal] = bucket.get(signal, 0) + 1
            messages.setdefault((category, window), set()).add(str(raw_hash))
        for (category, window), hashes in messages.items():
            result[category][window]["messages"] = len(hashes)
        return {
            category: {
                window: dict(sorted(counts.items()))
                for window, counts in sorted(windows.items())
            }
            for category, windows in sorted(result.items())
        }

    def has_quiz_answer(self, message: EmailRecord) -> bool:
        return self.quiz_answer_for_message_id(
            message.account_id,
            message.provider,
            message.message_id,
        ) is not None

    def quiz_answer_for_message_id(
        self,
        account_id: str,
        provider: ProviderKind,
        message_id: str,
    ) -> str | None:
        """Recupera un'etichetta tramite HMAC senza memorizzare l'ID in chiaro."""

        message_hash = self._hash(
            account_id,
            f"message:{provider.value}:{message_id}",
        )
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT answer FROM quiz_answer
                WHERE account_id = ? AND message_hash = ?
                """,
                (account_id, message_hash),
            ).fetchone()
        if row is None:
            return None
        answer = str(row[0])
        if answer not in {"keep", "dont_keep", "unsure"}:
            raise ValueError("risposta quiz locale non valida")
        return answer

    def quiz_answer_counts(self, account_id: str) -> dict[str, int]:
        self._ensure_key_binding(account_id)
        counts = {"keep": 0, "dont_keep": 0, "unsure": 0}
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT answer, COUNT(*) FROM quiz_answer
                WHERE account_id = ? GROUP BY answer
                """,
                (account_id,),
            ).fetchall()
        for raw_answer, raw_count in rows:
            answer = str(raw_answer)
            if answer not in counts:
                raise ValueError("risposta quiz locale non valida")
            counts[answer] = int(raw_count)
        return counts

    def has_shadow_scan_id(
        self,
        account_id: str,
        provider: ProviderKind,
        message_id: str,
        scan_profile: str,
    ) -> bool:
        if not scan_profile.strip():
            raise ValueError("scan_profile non può essere vuoto")
        message_hash = self._hash(
            account_id,
            f"message:{provider.value}:{message_id}",
        )
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT 1 FROM shadow_scan
                WHERE account_id = ? AND message_hash = ? AND scan_profile = ?
                """,
                (account_id, message_hash, scan_profile),
            ).fetchone()
        return row is not None

    def shadow_scan_membership_checker(
        self,
        account_id: str,
        provider: ProviderKind,
        scan_profile: str,
        policy_fingerprint: str | None = None,
    ) -> Callable[[str], bool]:
        """Carica solo HMAC in RAM per saltare rapidamente archivi molto grandi."""

        if not scan_profile.strip():
            raise ValueError("scan_profile non può essere vuoto")
        with closing(self._connect()) as connection:
            if policy_fingerprint is None:
                rows = connection.execute(
                    """
                    SELECT message_hash FROM shadow_scan
                    WHERE account_id = ? AND scan_profile = ?
                      AND processing_complete = 1
                    """,
                    (account_id, scan_profile),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT message_hash FROM shadow_scan
                    WHERE account_id = ? AND scan_profile = ?
                      AND processing_complete = 1
                      AND policy_fingerprint = ?
                    """,
                    (account_id, scan_profile, policy_fingerprint),
                ).fetchall()
        known_hashes = frozenset(str(row[0]) for row in rows)

        def was_scanned(message_id: str) -> bool:
            message_hash = self._hash(
                account_id,
                f"message:{provider.value}:{message_id}",
            )
            return message_hash in known_hashes

        return was_scanned

    def has_quarantine_pilot_execution_id(
        self,
        account_id: str,
        provider: ProviderKind,
        message_id: str,
        scan_profile: str,
    ) -> bool:
        message_hash = self._hash(
            account_id,
            f"message:{provider.value}:{message_id}",
        )
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT 1 FROM quarantine_pilot_execution
                WHERE account_id = ? AND message_hash = ? AND scan_profile = ?
                """,
                (account_id, message_hash, scan_profile),
            ).fetchone()
        return row is not None

    def record_quarantine_pilot_execution(
        self,
        account_id: str,
        provider: ProviderKind,
        message_id: str,
        scan_profile: str,
        executed_at: datetime,
        outcome: str,
    ) -> None:
        allowed_outcomes = {
            "applied",
            "already_applied",
            "moved_to_trash",
            "skipped_not_inbox",
            "skipped_protected",
        }
        if outcome not in allowed_outcomes:
            raise ValueError("esito quarantena pilot non valido")
        if executed_at.tzinfo is None:
            raise ValueError("executed_at deve includere il fuso orario")
        message_hash = self._hash(
            account_id,
            f"message:{provider.value}:{message_id}",
        )
        with closing(self._connect()) as connection:
            with connection:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO quarantine_pilot_execution(
                        account_id, message_hash, scan_profile, executed_at, outcome
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        account_id,
                        message_hash,
                        scan_profile,
                        executed_at.isoformat(),
                        outcome,
                    ),
                )

    def quarantine_pilot_record_for_message_id(
        self,
        account_id: str,
        provider: ProviderKind,
        message_id: str,
        scan_profile: str,
    ) -> tuple[datetime, str] | None:
        message_hash = self._hash(
            account_id,
            f"message:{provider.value}:{message_id}",
        )
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT executed_at, outcome FROM quarantine_pilot_execution
                WHERE account_id = ? AND message_hash = ? AND scan_profile = ?
                """,
                (account_id, message_hash, scan_profile),
            ).fetchone()
        if row is None:
            return None
        try:
            executed_at = datetime.fromisoformat(str(row[0]))
        except ValueError as exc:
            raise ValueError("data quarantena pilot non valida") from exc
        if executed_at.tzinfo is None:
            raise ValueError("data quarantena pilot priva di fuso orario")
        return executed_at, str(row[1])

    def record_quarantine_location(
        self,
        account_id: str,
        provider: ProviderKind,
        message_id: str,
        scan_profile: str,
        folder: str,
        uid_validity: str,
        uid: str,
        located_at: datetime,
    ) -> None:
        """Store only an HMAC identity and destination UID for Yahoo review."""

        if not scan_profile.strip() or len(scan_profile) > 100:
            raise ValueError("scan_profile non valido")
        if not folder or any(char in folder for char in "\r\n"):
            raise ValueError("cartella quarantena non valida")
        if not re.fullmatch(r"[1-9][0-9]{0,19}", uid_validity):
            raise ValueError("UIDVALIDITY quarantena non valido")
        if not re.fullmatch(r"[1-9][0-9]{0,19}", uid):
            raise ValueError("UID quarantena non valido")
        if located_at.tzinfo is None:
            raise ValueError("located_at deve includere il fuso orario")
        message_hash = self._hash(
            account_id,
            f"message:{provider.value}:{message_id}",
        )
        with closing(self._connect()) as connection:
            with connection:
                connection.execute(
                    """
                    INSERT INTO quarantine_location(
                        account_id, message_hash, provider, scan_profile,
                        folder, uid_validity, uid, located_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(account_id, message_hash, scan_profile) DO UPDATE SET
                        folder = excluded.folder,
                        uid_validity = excluded.uid_validity,
                        uid = excluded.uid,
                        located_at = excluded.located_at
                    """,
                    (
                        account_id,
                        message_hash,
                        provider.value,
                        scan_profile,
                        folder,
                        uid_validity,
                        uid,
                        located_at.isoformat(),
                    ),
                )

    def quarantine_review_record_for_location(
        self,
        account_id: str,
        provider: ProviderKind,
        scan_profile: str,
        folder: str,
        uid_validity: str,
        uid: str,
    ) -> tuple[str, str] | None:
        """Resolve a Yahoo quarantine UID to its aggregate shadow proposal."""

        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT ss.category, ss.suggested_action
                FROM quarantine_location AS ql
                JOIN shadow_scan AS ss
                  ON ss.account_id = ql.account_id
                 AND ss.message_hash = ql.message_hash
                 AND ss.scan_profile = ql.scan_profile
                WHERE ql.account_id = ? AND ql.provider = ?
                  AND ql.scan_profile = ? AND ql.folder = ?
                  AND ql.uid_validity = ? AND ql.uid = ?
                  AND ss.suggested_action = 'quarantine'
                  AND NOT EXISTS (
                      SELECT 1 FROM quiz_answer AS qa
                      WHERE qa.account_id = ql.account_id
                        AND qa.message_hash = ql.message_hash
                  )
                """,
                (
                    account_id,
                    provider.value,
                    scan_profile,
                    folder,
                    uid_validity,
                    uid,
                ),
            ).fetchone()
        return None if row is None else (str(row[0]), str(row[1]))

    def has_quarantine_finalization_id(
        self,
        account_id: str,
        provider: ProviderKind,
        message_id: str,
        scan_profile: str,
    ) -> bool:
        message_hash = self._hash(
            account_id,
            f"message:{provider.value}:{message_id}",
        )
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT 1 FROM quarantine_finalization
                WHERE account_id = ? AND message_hash = ? AND scan_profile = ?
                """,
                (account_id, message_hash, scan_profile),
            ).fetchone()
        return row is not None

    def record_quarantine_finalization(
        self,
        account_id: str,
        provider: ProviderKind,
        message_id: str,
        scan_profile: str,
        finalized_at: datetime,
        outcome: str,
    ) -> None:
        allowed_outcomes = {
            "moved_to_trash",
            "moved_to_spam",
            "cancelled_label_removed",
            "cancelled_not_inbox",
            "cancelled_protected",
            "already_finalized",
        }
        if outcome not in allowed_outcomes:
            raise ValueError("esito finalizzazione quarantena non valido")
        if finalized_at.tzinfo is None:
            raise ValueError("finalized_at deve includere il fuso orario")
        message_hash = self._hash(
            account_id,
            f"message:{provider.value}:{message_id}",
        )
        with closing(self._connect()) as connection:
            with connection:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO quarantine_finalization(
                        account_id, message_hash, scan_profile, finalized_at, outcome
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        account_id,
                        message_hash,
                        scan_profile,
                        finalized_at.isoformat(),
                        outcome,
                    ),
                )

    def quarantine_pilot_summary(
        self,
        account_id: str,
        scan_profile: str,
    ) -> dict[str, int]:
        counts: dict[str, int] = {}
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT outcome, COUNT(*) FROM quarantine_pilot_execution
                WHERE account_id = ? AND scan_profile = ?
                GROUP BY outcome
                """,
                (account_id, scan_profile),
            ).fetchall()
        for outcome, count in rows:
            counts[str(outcome)] = int(count)
        return dict(sorted(counts.items()))

    def quarantine_finalization_summary(
        self,
        account_id: str,
        scan_profile: str,
    ) -> dict[str, int]:
        counts: dict[str, int] = {}
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT outcome, COUNT(*) FROM quarantine_finalization
                WHERE account_id = ? AND scan_profile = ?
                GROUP BY outcome
                """,
                (account_id, scan_profile),
            ).fetchall()
        for outcome, count in rows:
            counts[str(outcome)] = int(count)
        return dict(sorted(counts.items()))

    def _record_behavior_message_with_connection(
        self,
        connection: sqlite3.Connection,
        message: EmailRecord,
        scanned_at: datetime,
    ) -> None:
        message_hash = self._hash(
            message.account_id,
            f"message:{message.provider.value}:{message.message_id}",
        )
        content_features = _content_similarity_features(message)
        connection.execute(
            """
            INSERT OR IGNORE INTO behavior_message(
                account_id, message_hash, provider, registered_at,
                content_feature_count
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                message.account_id,
                message_hash,
                message.provider.value,
                scanned_at.isoformat(),
                len(content_features),
            ),
        )
        general_features = self._features(
            message,
            Classification(
                EmailCategory.UNCERTAIN,
                0.0,
                ("behavior_feature",),
                "local",
            ),
        )
        connection.executemany(
            """
            INSERT OR IGNORE INTO behavior_feature(
                account_id, message_hash, feature_hash, feature_kind
            ) VALUES (?, ?, ?, ?)
            """,
            (
                (
                    message.account_id,
                    message_hash,
                    self._hash(message.account_id, f"behavior:{feature}"),
                    feature.split(":", 1)[0],
                )
                for feature in general_features
            ),
        )
        connection.executemany(
            """
            INSERT OR IGNORE INTO behavior_feature(
                account_id, message_hash, feature_hash, feature_kind
            ) VALUES (?, ?, ?, 'content')
            """,
            (
                (
                    message.account_id,
                    message_hash,
                    self._hash(
                        message.account_id,
                        f"behavior-content:{feature}",
                    ),
                )
                for feature in content_features
            ),
        )
        raw_identity = next(
            (
                str(value)
                for key, value in message.headers.items()
                if str(key).casefold() == "message-id"
            ),
            "",
        )
        identity = unicodedata.normalize("NFKC", raw_identity).strip().casefold()
        if 3 <= len(identity) <= 998 and "\r" not in identity and "\n" not in identity:
            connection.execute(
                """
                INSERT OR IGNORE INTO provider_identity(
                    account_id, provider, identity_hash, message_hash
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    message.account_id,
                    message.provider.value,
                    self._hash(message.account_id, f"provider-identity:{identity}"),
                    message_hash,
                ),
            )
        if message.unread:
            connection.execute(
                """
                INSERT OR IGNORE INTO behavior_event(
                    account_id, message_hash, event_type, observed_at
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    message.account_id,
                    message_hash,
                    FeedbackSignal.LEFT_UNREAD.value,
                    scanned_at.isoformat(),
                ),
            )

    def record_behavior_event_for_message_id(
        self,
        account_id: str,
        provider: ProviderKind,
        message_id: str,
        event: FeedbackSignal,
        observed_at: datetime,
    ) -> bool:
        allowed = {
            FeedbackSignal.OPENED,
            FeedbackSignal.STARRED,
            FeedbackSignal.MARKED_IMPORTANT,
        }
        if event not in allowed:
            raise ValueError("segnale automatico non consentito")
        if observed_at.tzinfo is None:
            raise ValueError("observed_at deve includere il fuso orario")
        message_hash = self._hash(
            account_id,
            f"message:{provider.value}:{message_id}",
        )
        with closing(self._connect()) as connection:
            with connection:
                known = connection.execute(
                    """
                    SELECT 1 FROM behavior_message
                    WHERE account_id = ? AND message_hash = ? AND provider = ?
                    """,
                    (account_id, message_hash, provider.value),
                ).fetchone()
                if known is None:
                    return False
                cursor = connection.execute(
                    """
                    INSERT OR IGNORE INTO behavior_event(
                        account_id, message_hash, event_type, observed_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        account_id,
                        message_hash,
                        event.value,
                        observed_at.isoformat(),
                    ),
                )
        return cursor.rowcount == 1

    @staticmethod
    def _record_restored_hashes(
        connection: sqlite3.Connection,
        account_id: str,
        message_hashes: tuple[str, ...],
        observed_at: datetime,
    ) -> int:
        inserted = 0
        for message_hash in message_hashes:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO behavior_event(
                    account_id, message_hash, event_type, observed_at
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    account_id,
                    message_hash,
                    FeedbackSignal.RESTORED.value,
                    observed_at.isoformat(),
                ),
            )
            inserted += int(cursor.rowcount == 1)
        return inserted

    def record_restored_event_for_message_id(
        self,
        account_id: str,
        provider: ProviderKind,
        message_id: str,
        observed_at: datetime,
    ) -> bool:
        """Record a restore only after a successful InboxLume cleanup action."""
        if observed_at.tzinfo is None:
            raise ValueError("observed_at deve includere il fuso orario")
        message_hash = self._hash(
            account_id,
            f"message:{provider.value}:{message_id}",
        )
        with closing(self._connect()) as connection:
            with connection:
                eligible = connection.execute(
                    """
                    SELECT 1
                    FROM behavior_message AS bm
                    WHERE bm.account_id = ? AND bm.message_hash = ?
                      AND bm.provider = ?
                      AND (
                        EXISTS (
                          SELECT 1 FROM quarantine_pilot_execution AS qpe
                          WHERE qpe.account_id = bm.account_id
                            AND qpe.message_hash = bm.message_hash
                            AND qpe.outcome IN (
                              'applied', 'already_applied', 'moved_to_trash'
                            )
                        )
                        OR EXISTS (
                          SELECT 1 FROM quarantine_finalization AS qf
                          WHERE qf.account_id = bm.account_id
                            AND qf.message_hash = bm.message_hash
                            AND qf.outcome IN ('moved_to_trash', 'moved_to_spam')
                        )
                      )
                    """,
                    (account_id, message_hash, provider.value),
                ).fetchone()
                if eligible is None:
                    return False
                return bool(
                    self._record_restored_hashes(
                        connection,
                        account_id,
                        (message_hash,),
                        observed_at,
                    )
                )

    def record_restored_event_for_provider_identity(
        self,
        account_id: str,
        provider: ProviderKind,
        provider_identity: str,
        observed_at: datetime,
    ) -> int:
        """Resolve a restored copy through an HMAC identity; store no header text."""
        if observed_at.tzinfo is None:
            raise ValueError("observed_at deve includere il fuso orario")
        identity = unicodedata.normalize("NFKC", provider_identity).strip().casefold()
        if not 3 <= len(identity) <= 998 or "\r" in identity or "\n" in identity:
            return 0
        identity_hash = self._hash(
            account_id,
            f"provider-identity:{identity}",
        )
        with closing(self._connect()) as connection:
            with connection:
                rows = connection.execute(
                    """
                    SELECT DISTINCT pi.message_hash
                    FROM provider_identity AS pi
                    JOIN behavior_message AS bm
                      ON bm.account_id = pi.account_id
                     AND bm.message_hash = pi.message_hash
                    WHERE pi.account_id = ? AND pi.provider = ?
                      AND pi.identity_hash = ?
                      AND (
                        EXISTS (
                          SELECT 1 FROM quarantine_pilot_execution AS qpe
                          WHERE qpe.account_id = pi.account_id
                            AND qpe.message_hash = pi.message_hash
                            AND qpe.outcome IN (
                              'applied', 'already_applied', 'moved_to_trash'
                            )
                        )
                        OR EXISTS (
                          SELECT 1 FROM quarantine_finalization AS qf
                          WHERE qf.account_id = pi.account_id
                            AND qf.message_hash = pi.message_hash
                            AND qf.outcome IN ('moved_to_trash', 'moved_to_spam')
                        )
                      )
                    """,
                    (account_id, provider.value, identity_hash),
                ).fetchall()
                return self._record_restored_hashes(
                    connection,
                    account_id,
                    tuple(str(row[0]) for row in rows),
                    observed_at,
                )

    def gmail_history_cursor(self, account_id: str) -> str | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT history_id FROM gmail_history_cursor
                WHERE account_id = ?
                """,
                (account_id,),
            ).fetchone()
        if row is None:
            return None
        history_id = str(row[0])
        if not history_id.isdigit() or len(history_id) > 32:
            raise ValueError("cursore cronologia Gmail non valido")
        return history_id

    def set_gmail_history_cursor(
        self,
        account_id: str,
        history_id: str,
        updated_at: datetime,
    ) -> None:
        if not history_id.isdigit() or len(history_id) > 32:
            raise ValueError("cursore cronologia Gmail non valido")
        if updated_at.tzinfo is None:
            raise ValueError("updated_at deve includere il fuso orario")
        with closing(self._connect()) as connection:
            with connection:
                connection.execute(
                    """
                    INSERT INTO gmail_history_cursor(account_id, history_id, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(account_id) DO UPDATE SET
                        history_id = excluded.history_id,
                        updated_at = excluded.updated_at
                    """,
                    (account_id, history_id, updated_at.isoformat()),
                )

    def yahoo_uid_cursor(self, account_id: str) -> tuple[str, str] | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT uid_validity, last_uid FROM yahoo_uid_cursor
                WHERE account_id = ?
                """,
                (account_id,),
            ).fetchone()
        if row is None:
            return None
        uid_validity, last_uid = str(row[0]), str(row[1])
        if not uid_validity.isdigit() or not last_uid.isdigit():
            raise ValueError("cursore UID Yahoo non valido")
        return uid_validity, last_uid

    def set_yahoo_uid_cursor(
        self,
        account_id: str,
        uid_validity: str,
        last_uid: str,
        updated_at: datetime,
    ) -> None:
        if not uid_validity.isdigit() or not last_uid.isdigit():
            raise ValueError("cursore UID Yahoo non valido")
        if updated_at.tzinfo is None:
            raise ValueError("updated_at deve includere il fuso orario")
        with closing(self._connect()) as connection:
            with connection:
                connection.execute(
                    """
                    INSERT INTO yahoo_uid_cursor(
                        account_id, uid_validity, last_uid, updated_at
                    ) VALUES (?, ?, ?, ?)
                    ON CONFLICT(account_id) DO UPDATE SET
                        uid_validity = excluded.uid_validity,
                        last_uid = excluded.last_uid,
                        updated_at = excluded.updated_at
                    """,
                    (account_id, uid_validity, last_uid, updated_at.isoformat()),
                )

    def behavior_event_summary(self, account_id: str) -> dict[str, int]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT event_type, COUNT(*) FROM behavior_event
                WHERE account_id = ? GROUP BY event_type
                """,
                (account_id,),
            ).fetchall()
        return dict(sorted((str(event), int(count)) for event, count in rows))

    def record_shadow_scan(
        self,
        message: EmailRecord,
        classification: Classification,
        decision: PolicyDecision,
        scan_profile: str,
        scanned_at: datetime,
        policy_fingerprint: str | None = None,
        *,
        processing_complete: bool = True,
    ) -> None:
        if not scan_profile.strip() or len(scan_profile) > 100:
            raise ValueError("scan_profile non valido")
        if scanned_at.tzinfo is None:
            raise ValueError("scanned_at deve includere il fuso orario")
        if policy_fingerprint is not None and not re.fullmatch(
            r"[0-9a-f]{64}", policy_fingerprint
        ):
            raise ValueError("policy_fingerprint non valido")
        message_hash = self._hash(
            message.account_id,
            f"message:{message.provider.value}:{message.message_id}",
        )
        with closing(self._connect()) as connection:
            with connection:
                self._upsert_shadow_scan_with_connection(
                    connection,
                    message,
                    message_hash,
                    classification,
                    decision,
                    scan_profile,
                    scanned_at,
                    policy_fingerprint,
                    processing_complete,
                )
                self._record_behavior_message_with_connection(
                    connection,
                    message,
                    scanned_at,
                )

    def _upsert_shadow_scan_with_connection(
        self,
        connection: sqlite3.Connection,
        message: EmailRecord,
        message_hash: str,
        classification: Classification,
        decision: PolicyDecision,
        scan_profile: str,
        scanned_at: datetime,
        policy_fingerprint: str | None,
        processing_complete: bool,
    ) -> None:
        connection.execute(
            """
            INSERT INTO shadow_scan(
                account_id, message_hash, scan_profile, scanned_at,
                category, suggested_action, reason_codes, policy_fingerprint,
                processing_complete, hard_protected
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(account_id, message_hash, scan_profile) DO UPDATE SET
                scanned_at = excluded.scanned_at,
                category = excluded.category,
                suggested_action = excluded.suggested_action,
                reason_codes = excluded.reason_codes,
                policy_fingerprint = excluded.policy_fingerprint,
                processing_complete = excluded.processing_complete,
                hard_protected = excluded.hard_protected
            WHERE shadow_scan.processing_complete = 0
               OR shadow_scan.policy_fingerprint IS NOT excluded.policy_fingerprint
            """,
            (
                message.account_id,
                message_hash,
                scan_profile,
                scanned_at.isoformat(),
                classification.category.value,
                decision.action.value,
                ",".join(decision.reason_codes),
                policy_fingerprint,
                int(processing_complete),
                int(has_hard_policy_reason(decision.reason_codes)),
            ),
        )

    def record_shadow_scan_batch(
        self,
        entries: Iterable[tuple[EmailRecord, Classification, PolicyDecision]],
        scan_profile: str,
        scanned_at: datetime,
        policy_fingerprint: str,
        *,
        processing_complete: bool,
    ) -> None:
        """Persist a classified batch in one SQLite transaction."""

        materialized = tuple(entries)
        if not scan_profile.strip() or len(scan_profile) > 100:
            raise ValueError("scan_profile non valido")
        if scanned_at.tzinfo is None:
            raise ValueError("scanned_at deve includere il fuso orario")
        if not re.fullmatch(r"[0-9a-f]{64}", policy_fingerprint):
            raise ValueError("policy_fingerprint non valido")
        with closing(self._connect()) as connection:
            with connection:
                for message, classification, decision in materialized:
                    message_hash = self._hash(
                        message.account_id,
                        f"message:{message.provider.value}:{message.message_id}",
                    )
                    self._upsert_shadow_scan_with_connection(
                        connection,
                        message,
                        message_hash,
                        classification,
                        decision,
                        scan_profile,
                        scanned_at,
                        policy_fingerprint,
                        processing_complete,
                    )
                    self._record_behavior_message_with_connection(
                        connection,
                        message,
                        scanned_at,
                    )

    def mark_shadow_batch_complete(
        self,
        messages: Iterable[EmailRecord],
        scan_profile: str,
        policy_fingerprint: str,
    ) -> None:
        with closing(self._connect()) as connection:
            with connection:
                for message in messages:
                    message_hash = self._hash(
                        message.account_id,
                        f"message:{message.provider.value}:{message.message_id}",
                    )
                    connection.execute(
                        """
                        UPDATE shadow_scan SET processing_complete = 1
                        WHERE account_id = ? AND message_hash = ?
                          AND scan_profile = ? AND policy_fingerprint = ?
                        """,
                        (
                            message.account_id,
                            message_hash,
                            scan_profile,
                            policy_fingerprint,
                        ),
                    )

    def record_threat_assessment(
        self,
        message: EmailRecord,
        scan_profile: str,
        assessment: ThreatConsensusAssessment,
        assessed_at: datetime,
        *,
        protective_review: bool,
    ) -> None:
        """Persist only HMAC identity and controlled threat vocabulary."""

        if not scan_profile.strip() or len(scan_profile) > 100:
            raise ValueError("scan_profile non valido")
        if assessed_at.tzinfo is None:
            raise ValueError("assessed_at deve includere il fuso orario")
        message_hash = self._hash(
            message.account_id,
            f"message:{message.provider.value}:{message.message_id}",
        )
        deterministic_signals = ",".join(
            signal.value for signal in assessment.deterministic.signals
        )
        signal_families = ",".join(assessment.deterministic.signal_families)
        semantic_reasons = ",".join(assessment.semantic.reason_codes)
        protective = int(protective_review)
        with closing(self._connect()) as connection:
            with connection:
                connection.execute(
                    """
                    INSERT INTO threat_assessment(
                        account_id, message_hash, scan_profile, assessed_at,
                        engine_version, level, score_bucket, semantic_verdict,
                        semantic_intent, deterministic_signals, signal_families,
                        semantic_reason_codes, analyzer, independent_consensus,
                        protective_review
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(account_id, message_hash, scan_profile) DO UPDATE SET
                        assessed_at = excluded.assessed_at,
                        engine_version = excluded.engine_version,
                        level = excluded.level,
                        score_bucket = excluded.score_bucket,
                        semantic_verdict = excluded.semantic_verdict,
                        semantic_intent = excluded.semantic_intent,
                        deterministic_signals = excluded.deterministic_signals,
                        signal_families = excluded.signal_families,
                        semantic_reason_codes = excluded.semantic_reason_codes,
                        analyzer = excluded.analyzer,
                        independent_consensus = excluded.independent_consensus,
                        protective_review = excluded.protective_review
                    """,
                    (
                        message.account_id,
                        message_hash,
                        scan_profile,
                        assessed_at.isoformat(),
                        THREAT_CONSENSUS_ENGINE_VERSION,
                        assessment.level.value,
                        min(10, assessment.score // 10),
                        assessment.semantic.verdict.value,
                        assessment.semantic.intent.value,
                        deterministic_signals,
                        signal_families,
                        semantic_reasons,
                        assessment.semantic.analyzer,
                        int(assessment.independent_consensus),
                        protective,
                    ),
                )
                if protective:
                    # Recovery of an earlier batch must obey the same protection.
                    connection.execute(
                        """
                        UPDATE shadow_scan
                        SET suggested_action = 'review', hard_protected = 1
                        WHERE account_id = ? AND message_hash = ? AND scan_profile = ?
                        """,
                        (message.account_id, message_hash, scan_profile),
                    )

    def record_disabled_threat_assessment_batch(
        self,
        messages: Iterable[EmailRecord],
        scan_profile: str,
        assessed_at: datetime,
    ) -> None:
        """Commit an explicit, non-protective attestation for a disabled module."""

        if not scan_profile.strip() or len(scan_profile) > 100:
            raise ValueError("scan_profile non valido")
        if assessed_at.tzinfo is None:
            raise ValueError("assessed_at deve includere il fuso orario")
        with closing(self._connect()) as connection:
            with connection:
                for message in messages:
                    message_hash = self._hash(
                        message.account_id,
                        f"message:{message.provider.value}:{message.message_id}",
                    )
                    connection.execute(
                        """
                        INSERT INTO threat_assessment(
                            account_id, message_hash, scan_profile, assessed_at,
                            engine_version, level, score_bucket, semantic_verdict,
                            semantic_intent, deterministic_signals, signal_families,
                            semantic_reason_codes, analyzer, independent_consensus,
                            protective_review
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(account_id, message_hash, scan_profile) DO UPDATE SET
                            assessed_at = excluded.assessed_at,
                            engine_version = excluded.engine_version,
                            level = excluded.level,
                            score_bucket = excluded.score_bucket,
                            semantic_verdict = excluded.semantic_verdict,
                            semantic_intent = excluded.semantic_intent,
                            deterministic_signals = excluded.deterministic_signals,
                            signal_families = excluded.signal_families,
                            semantic_reason_codes = excluded.semantic_reason_codes,
                            analyzer = excluded.analyzer,
                            independent_consensus = excluded.independent_consensus,
                            protective_review = excluded.protective_review
                        """,
                        (
                            message.account_id,
                            message_hash,
                            scan_profile,
                            assessed_at.isoformat(),
                            "threat-disabled-v1",
                            "minimal",
                            0,
                            "benign",
                            "none",
                            "",
                            "",
                            "",
                            "disabled-by-user",
                            0,
                            0,
                        ),
                    )

    def reset_disabled_threat_assessments(
        self,
        account_id: str,
        scan_profile: str,
    ) -> int:
        """Make disabled attestations retryable before re-enabling Threat Protection."""

        with closing(self._connect()) as connection:
            with connection:
                hashes = connection.execute(
                    """
                    SELECT message_hash FROM threat_assessment
                    WHERE account_id = ? AND scan_profile = ?
                      AND analyzer = 'disabled-by-user'
                    """,
                    (account_id, scan_profile),
                ).fetchall()
                connection.execute(
                    """
                    UPDATE shadow_scan SET processing_complete = 0
                    WHERE account_id = ? AND scan_profile = ?
                      AND message_hash IN (
                        SELECT message_hash FROM threat_assessment
                        WHERE account_id = ? AND scan_profile = ?
                          AND analyzer = 'disabled-by-user'
                      )
                    """,
                    (account_id, scan_profile, account_id, scan_profile),
                )
                connection.execute(
                    """
                    DELETE FROM threat_assessment
                    WHERE account_id = ? AND scan_profile = ?
                      AND analyzer = 'disabled-by-user'
                    """,
                    (account_id, scan_profile),
                )
        return len(hashes)

    def reset_stale_threat_assessments(
        self,
        account_id: str,
        scan_profile: str,
        semantic_mode: ThreatSemanticMode | str,
    ) -> int:
        """Invalidate assessments that cannot satisfy the current Threat contract."""

        if not account_id.strip() or not scan_profile.strip():
            raise ValueError("identità assessment minaccia non valida")
        mode = ThreatSemanticMode(semantic_mode)
        with closing(self._connect()) as connection:
            with connection:
                rows = connection.execute(
                    """
                    SELECT message_hash FROM threat_assessment
                    WHERE account_id = ? AND scan_profile = ?
                      AND (
                        engine_version <> ?
                        OR analyzer = 'disabled-by-user'
                        -- A row recorded under a weaker mode never received the
                        -- pass the current mode would give it, so it must be
                        -- reopened rather than reused.  'technical-screen-clear'
                        -- marks a message with no signal at all, which no mode
                        -- would analyse, so it stays valid.
                        OR (
                            ? IN ('targeted_semantic', 'confirmed_semantic')
                            AND analyzer = 'technical-only'
                        )
                        OR (
                            ? = 'targeted_semantic'
                            AND analyzer = 'technical-below-alert'
                        )
                      )
                    """,
                    (
                        account_id,
                        scan_profile,
                        THREAT_CONSENSUS_ENGINE_VERSION,
                        mode.value,
                        mode.value,
                    ),
                ).fetchall()
                hashes = tuple(str(row[0]) for row in rows)
                if hashes:
                    placeholders = ",".join("?" for _ in hashes)
                    parameters = (account_id, scan_profile, *hashes)
                    connection.execute(
                        f"""
                        UPDATE shadow_scan SET processing_complete = 0
                        WHERE account_id = ? AND scan_profile = ?
                          AND message_hash IN ({placeholders})
                        """,
                        parameters,
                    )
                    connection.execute(
                        f"""
                        DELETE FROM threat_assessment
                        WHERE account_id = ? AND scan_profile = ?
                          AND message_hash IN ({placeholders})
                        """,
                        parameters,
                    )
        return len(hashes)

    def threat_protects_message_id(
        self,
        account_id: str,
        provider: ProviderKind,
        message_id: str,
        scan_profile: str,
    ) -> bool:
        message_hash = self._hash(
            account_id,
            f"message:{provider.value}:{message_id}",
        )
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT protective_review FROM threat_assessment
                WHERE account_id = ? AND message_hash = ? AND scan_profile = ?
                """,
                (account_id, message_hash, scan_profile),
            ).fetchone()
        return row is not None and int(row[0]) == 1

    def has_threat_assessment_id(
        self,
        account_id: str,
        provider: ProviderKind,
        message_id: str,
        scan_profile: str,
        *,
        allow_disabled: bool = False,
    ) -> bool:
        """Return whether the safety assessment completed for this scan row.

        Recovery paths use this as a commit-boundary check.  A missing row is
        never equivalent to a benign assessment: it can mean that a process
        stopped after persisting the shadow proposal but before Threat
        Protection completed.
        """

        message_hash = self._hash(
            account_id,
            f"message:{provider.value}:{message_id}",
        )
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT analyzer FROM threat_assessment
                WHERE account_id = ? AND message_hash = ? AND scan_profile = ?
                """,
                (account_id, message_hash, scan_profile),
            ).fetchone()
        return row is not None and (
            allow_disabled or str(row[0]) != "disabled-by-user"
        )

    def threat_assessment_summary(
        self,
        account_id: str,
        scan_profile: str,
    ) -> dict[str, object]:
        """Return aggregate controlled fields, never message identity or content."""

        with closing(self._connect()) as connection:
            total = connection.execute(
                """
                SELECT COUNT(*), COALESCE(SUM(protective_review), 0)
                FROM threat_assessment
                WHERE account_id = ? AND scan_profile = ?
                """,
                (account_id, scan_profile),
            ).fetchone()
            levels = connection.execute(
                """
                SELECT level, COUNT(*) FROM threat_assessment
                WHERE account_id = ? AND scan_profile = ? GROUP BY level
                """,
                (account_id, scan_profile),
            ).fetchall()
            intents = connection.execute(
                """
                SELECT semantic_intent, COUNT(*) FROM threat_assessment
                WHERE account_id = ? AND scan_profile = ? GROUP BY semantic_intent
                """,
                (account_id, scan_profile),
            ).fetchall()
        return {
            "assessed_total": int(total[0]) if total else 0,
            "protective_reviews_total": int(total[1]) if total else 0,
            "levels": dict(sorted((str(key), int(value)) for key, value in levels)),
            "intents": dict(sorted((str(key), int(value)) for key, value in intents)),
            "stored_plaintext": False,
        }

    def record_threat_marker_execution(
        self,
        account_id: str,
        provider: ProviderKind,
        message_id: str,
        scan_profile: str,
        marked_at: datetime,
        marker_kind: str,
        outcome: str,
    ) -> None:
        if marker_kind not in {
            # Folder marker kinds remain accepted only for existing ledgers;
            # current protection is additive and leaves messages in Inbox.
            "gmail_label",
            "yahoo_star",
            "gmail_threat_folder",
            "yahoo_threat_folder",
        }:
            raise ValueError("tipo indicatore minaccia non valido")
        if outcome not in {
            "applied",
            "already_applied",
            "skipped_not_inbox",
            "failed",
        }:
            raise ValueError("esito indicatore minaccia non valido")
        if marked_at.tzinfo is None:
            raise ValueError("marked_at deve includere il fuso orario")
        message_hash = self._hash(
            account_id,
            f"message:{provider.value}:{message_id}",
        )
        with closing(self._connect()) as connection:
            with connection:
                connection.execute(
                    """
                    INSERT INTO threat_marker_execution(
                        account_id, message_hash, scan_profile, marked_at,
                        marker_kind, outcome
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(account_id, message_hash, scan_profile) DO UPDATE SET
                        marked_at = excluded.marked_at,
                        marker_kind = excluded.marker_kind,
                        outcome = excluded.outcome
                    """,
                    (
                        account_id,
                        message_hash,
                        scan_profile,
                        marked_at.isoformat(),
                        marker_kind,
                        outcome,
                    ),
                )
                if outcome == "failed":
                    # The shadow batch is committed before provider markers are
                    # attempted.  A transient marker failure must therefore
                    # reopen this one row, otherwise normal membership filtering
                    # would hide the message forever and the protective marker
                    # could never be retried.  Successful, already-applied and
                    # no-longer-Inbox outcomes remain terminal.
                    connection.execute(
                        """
                        UPDATE shadow_scan
                        SET processing_complete = 0
                        WHERE account_id = ? AND message_hash = ?
                          AND scan_profile = ?
                        """,
                        (account_id, message_hash, scan_profile),
                    )

    def threat_marker_summary(
        self,
        account_id: str,
        scan_profile: str,
    ) -> dict[str, object]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT marker_kind, outcome, COUNT(*)
                FROM threat_marker_execution
                WHERE account_id = ? AND scan_profile = ?
                GROUP BY marker_kind, outcome
                """,
                (account_id, scan_profile),
            ).fetchall()
        counts = {
            f"{str(kind)}:{str(outcome)}": int(count)
            for kind, outcome, count in rows
        }
        return {"outcomes": dict(sorted(counts.items())), "stored_plaintext": False}

    def record_lumegraph_observation(
        self,
        message: EmailRecord,
        observation: LifecycleObservation,
        scan_profile: str,
        observed_at: datetime,
        relation_materials: tuple[str, ...] = (),
        *,
        hard_protected: bool = False,
    ) -> tuple[bool, bool]:
        """Persist a minimized shadow node; return ``(inserted, linked)``.

        Message and relation identifiers are HMACed before SQLite sees them. Exact dates,
        extracted references, sender data, subjects and bodies are never stored.
        """

        if not scan_profile.strip() or len(scan_profile) > 100:
            raise ValueError("invalid LumeGraph scan profile")
        if observed_at.tzinfo is None:
            raise ValueError("observed_at must include a timezone")
        if (
            len(relation_materials) > 4
            or len(set(relation_materials)) != len(relation_materials)
            or any(not material.strip() for material in relation_materials)
        ):
            raise ValueError("invalid LumeGraph relations")
        message_hash = self._hash(
            message.account_id,
            f"message:{message.provider.value}:{message.message_id}",
        )
        relation_hashes = tuple(
            self._hash(message.account_id, f"lumegraph-event:{material}")
            for material in relation_materials
        )
        event_hash = relation_hashes[0] if relation_hashes else None
        confidence_bucket = min(9, int(observation.confidence * 10))
        received_week = int(message.received_at.timestamp() // 604_800)
        reason_codes = ",".join(observation.reason_codes)
        linked = False
        with closing(self._connect()) as connection:
            with connection:
                existing = connection.execute(
                    """
                    SELECT 1 FROM lumegraph_node
                    WHERE account_id = ? AND message_hash = ? AND scan_profile = ?
                    """,
                    (message.account_id, message_hash, scan_profile),
                ).fetchone()
                if existing is not None:
                    return False, False
                connection.execute(
                    """
                    INSERT INTO lumegraph_node(
                        account_id, message_hash, scan_profile, event_hash,
                        utility_kind, lifecycle_state, operational, evidentiary,
                        personal, security, date_relation, confidence_bucket,
                        lifecycle_condition, reason_codes, extractor,
                        received_week, hard_protected, observed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        message.account_id,
                        message_hash,
                        scan_profile,
                        event_hash,
                        observation.kind.value,
                        observation.state.value,
                        int(observation.utility.operational),
                        int(observation.utility.evidentiary),
                        int(observation.utility.personal),
                        int(observation.utility.security),
                        observation.date_relation.value,
                        confidence_bucket,
                        observation.condition.value,
                        reason_codes,
                        observation.extractor,
                        received_week,
                        int(hard_protected),
                        observed_at.isoformat(),
                    ),
                )
                connection.executemany(
                    """
                    INSERT INTO lumegraph_relation(
                        account_id, message_hash, scan_profile, relation_hash
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        (
                            message.account_id,
                            message_hash,
                            scan_profile,
                            relation_hash,
                        )
                        for relation_hash in relation_hashes
                    ),
                )
                for relation_hash in relation_hashes:
                    older = self._nearest_lumegraph_node(
                        connection,
                        message.account_id,
                        scan_profile,
                        relation_hash,
                        received_week,
                        older=True,
                    )
                    newer = self._nearest_lumegraph_node(
                        connection,
                        message.account_id,
                        scan_profile,
                        relation_hash,
                        received_week,
                        older=False,
                    )
                    if older is not None:
                        linked |= self._record_lumegraph_transition_and_proof(
                            connection,
                            message.account_id,
                            scan_profile,
                            relation_hash,
                            older,
                            self._lumegraph_evidence_for_observation(
                                message_hash,
                                observation,
                                hard_protected,
                                confidence_bucket,
                            ),
                            observed_at,
                        )
                    if newer is not None:
                        linked |= self._record_lumegraph_transition_and_proof(
                            connection,
                            message.account_id,
                            scan_profile,
                            relation_hash,
                            self._lumegraph_evidence_for_observation(
                                message_hash,
                                observation,
                                hard_protected,
                                confidence_bucket,
                            ),
                            newer,
                            observed_at,
                        )
        return True, linked

    @staticmethod
    def _lumegraph_evidence_for_observation(
        message_hash: str,
        observation: LifecycleObservation,
        hard_protected: bool,
        confidence_bucket: int,
    ) -> tuple[str, StoredLifecycleEvidence]:
        return (
            message_hash,
            StoredLifecycleEvidence(
                observation.kind,
                observation.state,
                observation.condition,
                observation.utility.operational,
                observation.utility.evidentiary,
                observation.utility.personal,
                observation.utility.security,
                hard_protected,
                confidence_bucket,
                observation.reason_codes,
                observation.extractor,
            ),
        )

    @staticmethod
    def _lumegraph_evidence_from_row(
        row: sqlite3.Row | tuple[object, ...],
    ) -> tuple[str, StoredLifecycleEvidence]:
        return (
            str(row[0]),
            StoredLifecycleEvidence(
                UtilityKind(str(row[1])),
                LifecycleState(str(row[2])),
                LifecycleCondition(str(row[3])),
                bool(row[4]),
                bool(row[5]),
                bool(row[6]),
                bool(row[7]),
                bool(row[8]),
                int(row[9]),
                tuple(code for code in str(row[10]).split(",") if code),
                str(row[11]),
            ),
        )

    def _nearest_lumegraph_node(
        self,
        connection: sqlite3.Connection,
        account_id: str,
        scan_profile: str,
        relation_hash: str,
        received_week: int,
        *,
        older: bool,
    ) -> tuple[str, StoredLifecycleEvidence] | None:
        comparator = "<" if older else ">"
        order = "DESC" if older else "ASC"
        row = connection.execute(
            f"""
            SELECT node.message_hash, node.utility_kind, node.lifecycle_state,
                   node.lifecycle_condition, node.operational, node.evidentiary,
                   node.personal, node.security, node.hard_protected,
                   node.confidence_bucket, node.reason_codes, node.extractor
            FROM lumegraph_relation AS relation
            JOIN lumegraph_node AS node
              ON node.account_id = relation.account_id
             AND node.message_hash = relation.message_hash
             AND node.scan_profile = relation.scan_profile
            WHERE relation.account_id = ? AND relation.relation_hash = ?
              AND relation.scan_profile = ? AND node.received_week {comparator} ?
            ORDER BY node.received_week {order} LIMIT 1
            """,
            (account_id, relation_hash, scan_profile, received_week),
        ).fetchone()
        return None if row is None else self._lumegraph_evidence_from_row(row)

    def _record_lumegraph_transition_and_proof(
        self,
        connection: sqlite3.Connection,
        account_id: str,
        scan_profile: str,
        relation_hash: str,
        predecessor: tuple[str, StoredLifecycleEvidence],
        successor: tuple[str, StoredLifecycleEvidence],
        observed_at: datetime,
    ) -> bool:
        predecessor_hash, predecessor_evidence = predecessor
        successor_hash, successor_evidence = successor
        cursor = connection.execute(
            """
            INSERT OR IGNORE INTO lumegraph_transition(
                account_id, event_hash, scan_profile,
                from_message_hash, to_message_hash,
                transition_kind, observed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                account_id,
                relation_hash,
                scan_profile,
                predecessor_hash,
                successor_hash,
                transition_for_state(successor_evidence.state).value,
                observed_at.isoformat(),
            ),
        )
        proof = successor_transition_proof(
            predecessor_evidence,
            successor_evidence,
            scan_profile,
        )
        self._upsert_obsolescence_proof(
            connection,
            account_id,
            predecessor_hash,
            scan_profile,
            proof,
            observed_at,
            successor_hash,
        )
        return cursor.rowcount > 0

    @staticmethod
    def _upsert_obsolescence_proof(
        connection: sqlite3.Connection,
        account_id: str,
        message_hash: str,
        scan_profile: str,
        proof: ObsolescenceProof,
        created_at: datetime,
        source_message_hash: str | None,
    ) -> None:
        connection.execute(
            """
            INSERT INTO obsolescence_proof(
                account_id, message_hash, scan_profile, engine_version,
                status, witness, maximum_destination, confidence_bucket,
                reason_codes, source_message_hash, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(account_id, message_hash, scan_profile, engine_version)
            DO UPDATE SET
                status = excluded.status,
                witness = excluded.witness,
                maximum_destination = excluded.maximum_destination,
                confidence_bucket = excluded.confidence_bucket,
                reason_codes = excluded.reason_codes,
                source_message_hash = excluded.source_message_hash,
                created_at = excluded.created_at
            WHERE obsolescence_proof.status != 'verified'
               OR excluded.status = 'verified'
            """,
            (
                account_id,
                message_hash,
                scan_profile,
                PROOF_ENGINE_VERSION,
                proof.status.value,
                proof.witness.value,
                proof.maximum_destination.value,
                proof.confidence_bucket,
                ",".join(proof.reason_codes),
                source_message_hash,
                created_at.isoformat(),
            ),
        )

    def record_obsolescence_proof(
        self,
        message: EmailRecord,
        scan_profile: str,
        proof: ObsolescenceProof,
        created_at: datetime,
    ) -> None:
        if created_at.tzinfo is None:
            raise ValueError("created_at must include a timezone")
        message_hash = self._hash(
            message.account_id,
            f"message:{message.provider.value}:{message.message_id}",
        )
        with closing(self._connect()) as connection:
            with connection:
                self._upsert_obsolescence_proof(
                    connection,
                    message.account_id,
                    message_hash,
                    scan_profile,
                    proof,
                    created_at,
                    None,
                )

    def obsolescence_proof_for_message_id(
        self,
        account_id: str,
        provider: ProviderKind,
        message_id: str,
        scan_profile: str,
    ) -> tuple[str, str, str] | None:
        message_hash = self._hash(
            account_id,
            f"message:{provider.value}:{message_id}",
        )
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT status, witness, maximum_destination
                FROM obsolescence_proof
                WHERE account_id = ? AND message_hash = ? AND scan_profile = ?
                  AND engine_version = ?
                """,
                (account_id, message_hash, scan_profile, PROOF_ENGINE_VERSION),
            ).fetchone()
        if row is None:
            return None
        return str(row[0]), str(row[1]), str(row[2])

    def obsolescence_proof_summary(
        self,
        account_id: str,
        scan_profile: str,
    ) -> dict[str, object]:
        with closing(self._connect()) as connection:
            status_rows = connection.execute(
                """
                SELECT status, COUNT(*) FROM obsolescence_proof
                WHERE account_id = ? AND scan_profile = ? AND engine_version = ?
                GROUP BY status
                """,
                (account_id, scan_profile, PROOF_ENGINE_VERSION),
            ).fetchall()
            witness_rows = connection.execute(
                """
                SELECT witness, COUNT(*) FROM obsolescence_proof
                WHERE account_id = ? AND scan_profile = ? AND engine_version = ?
                  AND status = 'verified'
                GROUP BY witness
                """,
                (account_id, scan_profile, PROOF_ENGINE_VERSION),
            ).fetchall()
        statuses = dict(sorted((str(key), int(value)) for key, value in status_rows))
        return {
            "engine_version": PROOF_ENGINE_VERSION,
            "verified_total": int(statuses.get(ProofStatus.VERIFIED.value, 0)),
            "statuses": statuses,
            "witnesses": dict(
                sorted((str(key), int(value)) for key, value in witness_rows)
            ),
            "maximum_destination": "quarantine",
            "authorizes_trash": False,
            "permanent_delete_available": False,
            "stored_plaintext": False,
        }

    def lumegraph_summary(
        self,
        account_id: str,
        scan_profile: str,
    ) -> dict[str, object]:
        """Return aggregates only; never node, message, event or content identifiers."""

        if not account_id.strip() or not scan_profile.strip():
            raise ValueError("account and scan profile are required")
        with closing(self._connect()) as connection:
            total = connection.execute(
                """
                SELECT COUNT(*) FROM lumegraph_node
                WHERE account_id = ? AND scan_profile = ?
                """,
                (account_id, scan_profile),
            ).fetchone()
            transition_total = connection.execute(
                """
                SELECT COUNT(*) FROM lumegraph_transition
                WHERE account_id = ? AND scan_profile = ?
                """,
                (account_id, scan_profile),
            ).fetchone()
            relation_total = connection.execute(
                """
                SELECT COUNT(*) FROM lumegraph_relation
                WHERE account_id = ? AND scan_profile = ?
                """,
                (account_id, scan_profile),
            ).fetchone()
            kind_rows = connection.execute(
                """
                SELECT utility_kind, COUNT(*) FROM lumegraph_node
                WHERE account_id = ? AND scan_profile = ?
                GROUP BY utility_kind
                """,
                (account_id, scan_profile),
            ).fetchall()
            state_rows = connection.execute(
                """
                SELECT lifecycle_state, COUNT(*) FROM lumegraph_node
                WHERE account_id = ? AND scan_profile = ?
                GROUP BY lifecycle_state
                """,
                (account_id, scan_profile),
            ).fetchall()
        return {
            "nodes_total": int(total[0]) if total else 0,
            "transitions_total": int(transition_total[0]) if transition_total else 0,
            "relations_total": int(relation_total[0]) if relation_total else 0,
            "kinds": dict(sorted((str(key), int(value)) for key, value in kind_rows)),
            "states": dict(sorted((str(key), int(value)) for key, value in state_rows)),
        }

    def shadow_scan_summary(self, account_id: str, scan_profile: str) -> dict[str, object]:
        categories: dict[str, int] = {}
        actions: dict[str, int] = {}
        with closing(self._connect()) as connection:
            total_row = connection.execute(
                """
                SELECT COUNT(*) FROM shadow_scan
                WHERE account_id = ? AND scan_profile = ?
                  AND processing_complete = 1
                """,
                (account_id, scan_profile),
            ).fetchone()
            incomplete_row = connection.execute(
                """
                SELECT COUNT(*) FROM shadow_scan
                WHERE account_id = ? AND scan_profile = ?
                  AND processing_complete = 0
                """,
                (account_id, scan_profile),
            ).fetchone()
            category_rows = connection.execute(
                """
                SELECT category, COUNT(*) FROM shadow_scan
                WHERE account_id = ? AND scan_profile = ?
                  AND processing_complete = 1 GROUP BY category
                """,
                (account_id, scan_profile),
            ).fetchall()
            action_rows = connection.execute(
                """
                SELECT suggested_action, COUNT(*) FROM shadow_scan
                WHERE account_id = ? AND scan_profile = ?
                  AND processing_complete = 1 GROUP BY suggested_action
                """,
                (account_id, scan_profile),
            ).fetchall()
        for category, count in category_rows:
            categories[str(category)] = int(count)
        for action, count in action_rows:
            actions[str(action)] = int(count)
        return {
            "processed_total": int(total_row[0]) if total_row else 0,
            "retryable_incomplete": int(incomplete_row[0]) if incomplete_row else 0,
            "categories": dict(sorted(categories.items())),
            "suggested_actions": dict(sorted(actions.items())),
        }

    def shadow_record_for_message_id(
        self,
        account_id: str,
        provider: ProviderKind,
        message_id: str,
        scan_profile: str,
    ) -> tuple[str, str] | None:
        message_hash = self._hash(
            account_id,
            f"message:{provider.value}:{message_id}",
        )
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT category, suggested_action FROM shadow_scan
                WHERE account_id = ? AND message_hash = ? AND scan_profile = ?
                """,
                (account_id, message_hash, scan_profile),
            ).fetchone()
        if row is None:
            return None
        return str(row[0]), str(row[1])

    def shadow_record_for_provider_identity(
        self,
        account_id: str,
        provider: ProviderKind,
        provider_identity: str,
        scan_profile: str,
    ) -> tuple[str, str] | None:
        """Resolve a proposal whose provider UID changed when it was moved.

        A move gives the message a new UID in the destination folder, so the
        identity recorded during the scan no longer matches and the proposal
        would look absent.  The RFC Message-ID stays stable across the move and
        is already stored as an HMAC, never as header text.
        """

        identity = unicodedata.normalize("NFKC", provider_identity).strip().casefold()
        if not 3 <= len(identity) <= 998 or "\r" in identity or "\n" in identity:
            return None
        identity_hash = self._hash(account_id, f"provider-identity:{identity}")
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT ss.category, ss.suggested_action
                FROM provider_identity AS pi
                JOIN shadow_scan AS ss
                  ON ss.account_id = pi.account_id
                 AND ss.message_hash = pi.message_hash
                WHERE pi.account_id = ? AND pi.provider = ?
                  AND pi.identity_hash = ? AND ss.scan_profile = ?
                """,
                (account_id, provider.value, identity_hash, scan_profile),
            ).fetchone()
        if row is None:
            return None
        return str(row[0]), str(row[1])

    def shadow_recovery_expected_unread(
        self,
        account_id: str,
        provider: ProviderKind,
        message_id: str,
        scan_profile: str,
        current_policy_fingerprint: str,
    ) -> bool | None:
        """Return the read state on which a recoverable proposal was based.

        A legacy or partially committed row has no controlled reason metadata;
        callers must interpret ``None`` as non-recoverable.
        """

        message_hash = self._hash(
            account_id,
            f"message:{provider.value}:{message_id}",
        )
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT reason_codes, policy_fingerprint FROM shadow_scan
                WHERE account_id = ? AND message_hash = ? AND scan_profile = ?
                """,
                (account_id, message_hash, scan_profile),
            ).fetchone()
        if (
            row is None
            or row[0] is None
            or not str(row[0]).strip()
            or row[1] is None
            or not hmac.compare_digest(str(row[1]), current_policy_fingerprint)
        ):
            return None
        reasons = frozenset(str(row[0]).split(","))
        return not bool(
            reasons.intersection(
                {
                    "expired_read_one_time_code",
                    "expired_read_routine_access_alert",
                }
            )
        )

    def shadow_reason_codes_for_message_id(
        self,
        account_id: str,
        provider: ProviderKind,
        message_id: str,
        scan_profile: str,
    ) -> tuple[str, ...]:
        message_hash = self._hash(
            account_id,
            f"message:{provider.value}:{message_id}",
        )
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT reason_codes FROM shadow_scan
                WHERE account_id = ? AND message_hash = ? AND scan_profile = ?
                """,
                (account_id, message_hash, scan_profile),
            ).fetchone()
        if row is None or row[0] is None:
            return ()
        return tuple(item for item in str(row[0]).split(",") if item)

    def shadow_is_hard_protected(
        self,
        account_id: str,
        provider: ProviderKind,
        message_id: str,
        scan_profile: str,
    ) -> bool:
        message_hash = self._hash(
            account_id,
            f"message:{provider.value}:{message_id}",
        )
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT hard_protected FROM shadow_scan
                WHERE account_id = ? AND message_hash = ? AND scan_profile = ?
                """,
                (account_id, message_hash, scan_profile),
            ).fetchone()
        return row is None or int(row[0]) != 0

    def shadow_quarantine_label_summary(
        self,
        account_id: str,
        scan_profile: str,
    ) -> dict[str, int]:
        counts = {"keep": 0, "dont_keep": 0, "unsure": 0, "unreviewed": 0}
        with closing(self._connect()) as connection:
            reviewed_rows = connection.execute(
                """
                SELECT qa.answer, COUNT(*)
                FROM shadow_scan AS ss
                JOIN quiz_answer AS qa
                  ON qa.account_id = ss.account_id
                 AND qa.message_hash = ss.message_hash
                WHERE ss.account_id = ? AND ss.scan_profile = ?
                  AND ss.processing_complete = 1
                  AND ss.hard_protected = 0
                  AND NOT EXISTS (
                    SELECT 1 FROM threat_assessment AS ta
                    WHERE ta.account_id = ss.account_id
                      AND ta.message_hash = ss.message_hash
                      AND ta.scan_profile = ss.scan_profile
                      AND ta.protective_review = 1
                  )
                  AND (
                    ss.suggested_action = 'quarantine'
                    OR (
                      ss.suggested_action = 'review'
                      AND ss.category IN (
                        'advertising', 'social', 'spam', 'one_time_code'
                      )
                    )
                  )
                GROUP BY qa.answer
                """,
                (account_id, scan_profile),
            ).fetchall()
            unreviewed_row = connection.execute(
                """
                SELECT COUNT(*)
                FROM shadow_scan AS ss
                LEFT JOIN quiz_answer AS qa
                  ON qa.account_id = ss.account_id
                 AND qa.message_hash = ss.message_hash
                WHERE ss.account_id = ? AND ss.scan_profile = ?
                  AND ss.processing_complete = 1
                  AND ss.hard_protected = 0
                  AND NOT EXISTS (
                    SELECT 1 FROM threat_assessment AS ta
                    WHERE ta.account_id = ss.account_id
                      AND ta.message_hash = ss.message_hash
                      AND ta.scan_profile = ss.scan_profile
                      AND ta.protective_review = 1
                  )
                  AND (
                    ss.suggested_action = 'quarantine'
                    OR (
                      ss.suggested_action = 'review'
                      AND ss.category IN (
                        'advertising', 'social', 'spam', 'one_time_code'
                      )
                    )
                  )
                  AND qa.message_hash IS NULL
                """,
                (account_id, scan_profile),
            ).fetchone()
        for answer, count in reviewed_rows:
            normalized = str(answer)
            if normalized not in counts:
                raise ValueError("risposta quiz locale non valida")
            counts[normalized] = int(count)
        counts["unreviewed"] = int(unreviewed_row[0]) if unreviewed_row else 0
        return counts

    def shadow_quarantine_evidence_by_category(
        self,
        account_id: str,
        scan_profile: str,
    ) -> dict[str, dict[str, int]]:
        """Return aggregate quiz evidence; never message IDs or plaintext."""
        if not account_id.strip():
            raise ValueError("account_id non può essere vuoto")
        if not scan_profile.strip() or len(scan_profile) > 100:
            raise ValueError("scan_profile non valido")
        allowed_answers = {"keep", "dont_keep", "unsure", "unreviewed"}
        evidence: dict[str, dict[str, int]] = {}
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT category, evidence_answer, COUNT(*)
                FROM (
                  SELECT ss.category,
                    CASE
                      WHEN EXISTS (
                        SELECT 1 FROM behavior_event AS be
                        WHERE be.account_id = ss.account_id
                          AND be.message_hash = ss.message_hash
                          AND be.event_type = 'restored'
                      ) THEN 'keep'
                      ELSE COALESCE(qa.answer, 'unreviewed')
                    END AS evidence_answer
                  FROM shadow_scan AS ss
                  LEFT JOIN quiz_answer AS qa
                    ON qa.account_id = ss.account_id
                   AND qa.message_hash = ss.message_hash
                  WHERE ss.account_id = ? AND ss.scan_profile = ?
                    AND ss.processing_complete = 1
                    AND ss.hard_protected = 0
                    AND NOT EXISTS (
                      SELECT 1 FROM threat_assessment AS ta
                      WHERE ta.account_id = ss.account_id
                        AND ta.message_hash = ss.message_hash
                        AND ta.scan_profile = ss.scan_profile
                        AND ta.protective_review = 1
                    )
                    AND (
                      ss.suggested_action = 'quarantine'
                      OR (
                        ss.suggested_action = 'review'
                        AND ss.category IN (
                          'advertising', 'social', 'spam', 'one_time_code'
                        )
                      )
                    )
                )
                GROUP BY category, evidence_answer
                """,
                (account_id, scan_profile),
            ).fetchall()
        for raw_category, raw_answer, raw_count in rows:
            category = str(raw_category)
            try:
                EmailCategory(category)
            except ValueError as exc:
                raise ValueError("categoria shadow locale non valida") from exc
            answer = str(raw_answer)
            if answer not in allowed_answers:
                raise ValueError("risposta quiz locale non valida")
            counts = evidence.setdefault(
                category,
                {item: 0 for item in sorted(allowed_answers)},
            )
            counts[answer] = int(raw_count)
        return dict(sorted(evidence.items()))

    @staticmethod
    def _normalized_backtest_evidence(
        evidence_by_family: Mapping[str, Mapping[str, int]],
    ) -> dict[str, dict[str, int]]:
        answers = ("keep", "dont_keep", "unsure", "unreviewed")
        normalized: dict[str, dict[str, int]] = {}
        for raw_category, raw_counts in evidence_by_family.items():
            category = EmailCategory(str(raw_category)).value
            unknown = set(raw_counts) - set(answers)
            if unknown:
                raise ValueError("unknown safety evidence field")
            counts: dict[str, int] = {}
            for answer in answers:
                value = raw_counts.get(answer, 0)
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise ValueError("invalid safety evidence count")
                counts[answer] = value
            normalized[category] = counts
        return dict(sorted(normalized.items()))

    def latest_safety_backtest_evidence(
        self,
        account_id: str,
        scan_profile: str,
        engine_version: str,
    ) -> tuple[str, dict[str, dict[str, int]]] | None:
        if not account_id.strip() or not scan_profile.strip():
            raise ValueError("account and scan profile are required")
        if not engine_version.strip() or len(engine_version) > 64:
            raise ValueError("invalid backtest engine version")
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT id, evidence_fingerprint
                FROM safety_backtest_run
                WHERE account_id = ? AND scan_profile = ? AND engine_version = ?
                ORDER BY id DESC LIMIT 1
                """,
                (account_id, scan_profile, engine_version),
            ).fetchone()
            if row is None:
                return None
            family_rows = connection.execute(
                """
                SELECT category, keep_count, dont_keep_count,
                       unsure_count, unreviewed_count
                FROM safety_backtest_family
                WHERE run_id = ? ORDER BY category
                """,
                (int(row[0]),),
            ).fetchall()
        evidence = {
            str(category): {
                "keep": int(keep),
                "dont_keep": int(dont_keep),
                "unsure": int(unsure),
                "unreviewed": int(unreviewed),
            }
            for category, keep, dont_keep, unsure, unreviewed in family_rows
        }
        return str(row[1]), evidence

    def record_safety_backtest_evidence(
        self,
        account_id: str,
        scan_profile: str,
        engine_version: str,
        evidence_fingerprint: str,
        created_at: datetime,
        evidence_by_family: Mapping[str, Mapping[str, int]],
    ) -> bool:
        if not account_id.strip() or not scan_profile.strip():
            raise ValueError("account and scan profile are required")
        if not engine_version.strip() or len(engine_version) > 64:
            raise ValueError("invalid backtest engine version")
        if not re.fullmatch(r"[0-9a-f]{64}", evidence_fingerprint):
            raise ValueError("invalid evidence fingerprint")
        if created_at.tzinfo is None:
            raise ValueError("created_at must include a timezone")
        evidence = self._normalized_backtest_evidence(evidence_by_family)
        with closing(self._connect()) as connection:
            with connection:
                latest = connection.execute(
                    """
                    SELECT evidence_fingerprint FROM safety_backtest_run
                    WHERE account_id = ? AND scan_profile = ?
                      AND engine_version = ?
                    ORDER BY id DESC LIMIT 1
                    """,
                    (account_id, scan_profile, engine_version),
                ).fetchone()
                if latest is not None and str(latest[0]) == evidence_fingerprint:
                    return False
                cursor = connection.execute(
                    """
                    INSERT INTO safety_backtest_run(
                        account_id, scan_profile, engine_version,
                        evidence_fingerprint, created_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        account_id,
                        scan_profile,
                        engine_version,
                        evidence_fingerprint,
                        created_at.isoformat(),
                    ),
                )
                run_id = int(cursor.lastrowid)
                connection.executemany(
                    """
                    INSERT INTO safety_backtest_family(
                        run_id, category, keep_count, dont_keep_count,
                        unsure_count, unreviewed_count
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        (
                            run_id,
                            category,
                            counts["keep"],
                            counts["dont_keep"],
                            counts["unsure"],
                            counts["unreviewed"],
                        )
                        for category, counts in evidence.items()
                    ),
                )
        return True

    def record_scan_timing_sample(
        self,
        account_id: str,
        scan_profile: str,
        hardware_key: str,
        provider: ProviderKind,
        destination: str,
        governor_enforced: bool,
        processed_messages: int,
        elapsed_seconds: float,
        recorded_at: datetime,
    ) -> None:
        """Persist only aggregate timing dimensions; never message data."""

        if not account_id.strip():
            raise ValueError("account is required")
        if not scan_profile.strip() or len(scan_profile) > 100:
            raise ValueError("invalid scan profile")
        if re.fullmatch(r"[0-9a-f]{64}", hardware_key) is None:
            raise ValueError("invalid hardware timing key")
        if not isinstance(provider, ProviderKind):
            raise ValueError("invalid timing provider")
        if destination not in {"quarantine", "trash"}:
            raise ValueError("invalid timing destination")
        if not isinstance(governor_enforced, bool):
            raise ValueError("invalid governor timing state")
        if (
            isinstance(processed_messages, bool)
            or not isinstance(processed_messages, int)
            or processed_messages < 1
        ):
            raise ValueError("processed timing count must be positive")
        if not math.isfinite(elapsed_seconds) or elapsed_seconds <= 0:
            raise ValueError("elapsed timing must be positive and finite")
        if recorded_at.tzinfo is None:
            raise ValueError("recorded_at must include a timezone")
        with closing(self._connect()) as connection:
            with connection:
                connection.execute(
                    """
                    INSERT INTO scan_timing_sample(
                        account_id, scan_profile, hardware_key, provider,
                        destination, governor_enforced, processed_messages,
                        elapsed_seconds, recorded_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        account_id,
                        scan_profile,
                        hardware_key,
                        provider.value,
                        destination,
                        int(governor_enforced),
                        processed_messages,
                        elapsed_seconds,
                        recorded_at.isoformat(),
                    ),
                )

    def scan_timing_samples(
        self,
        account_id: str,
        scan_profile: str,
        hardware_key: str,
        provider: ProviderKind,
        destination: str,
        governor_enforced: bool,
        *,
        limit: int = 20,
    ) -> tuple[tuple[int, float], ...]:
        """Return recent timings only for the exact current execution profile."""

        if not account_id.strip() or not scan_profile.strip():
            raise ValueError("account and scan profile are required")
        if re.fullmatch(r"[0-9a-f]{64}", hardware_key) is None:
            raise ValueError("invalid hardware timing key")
        if not isinstance(provider, ProviderKind):
            raise ValueError("invalid timing provider")
        if destination not in {"quarantine", "trash"}:
            raise ValueError("invalid timing destination")
        if not isinstance(governor_enforced, bool):
            raise ValueError("invalid governor timing state")
        if isinstance(limit, bool) or not 1 <= limit <= 100:
            raise ValueError("invalid timing sample limit")
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT processed_messages, elapsed_seconds
                FROM scan_timing_sample
                WHERE account_id = ? AND scan_profile = ?
                  AND hardware_key = ? AND provider = ?
                  AND destination = ? AND governor_enforced = ?
                ORDER BY id DESC LIMIT ?
                """,
                (
                    account_id,
                    scan_profile,
                    hardware_key,
                    provider.value,
                    destination,
                    int(governor_enforced),
                    limit,
                ),
            ).fetchall()
        return tuple((int(count), float(elapsed)) for count, elapsed in rows)
