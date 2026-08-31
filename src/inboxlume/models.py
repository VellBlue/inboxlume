from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
import math
from typing import Mapping


class ProviderKind(StrEnum):
    GMAIL = "gmail"
    YAHOO = "yahoo"
    FIXTURE = "fixture"


class EmailCategory(StrEnum):
    ADVERTISING = "advertising"
    BANKING = "banking"
    IMPORTANT = "important"
    MEDICAL_LEGAL = "medical_legal"
    ONE_TIME_CODE = "one_time_code"
    PERSONAL = "personal"
    SCHOOL = "school"
    SECURITY = "security"
    SOCIAL = "social"
    SPAM = "spam"
    TRANSACTIONAL = "transactional"
    OTHER = "other"
    UNCERTAIN = "uncertain"


class RetentionSignal(StrEnum):
    """Valutazione del contenuto, separata dalla categoria del messaggio."""

    PROTECT = "protect"
    DISCARD_CANDIDATE = "discard_candidate"
    UNCERTAIN = "uncertain"


class PolicyAction(StrEnum):
    """Azioni consentite alla policy della fase 1.

    Non esistono azioni di cancellazione, invio o modifica della casella. Anche
    QUARANTINE e LABEL_REVIEW sono soltanto proposte durante la modalita shadow.
    """

    KEEP = "keep"
    REVIEW = "review"
    LABEL_REVIEW = "label_review"
    QUARANTINE = "quarantine"


@dataclass(frozen=True, slots=True)
class EmailRecord:
    account_id: str
    provider: ProviderKind
    message_id: str
    received_at: datetime
    unread: bool
    sender: str
    subject: str = ""
    body_text: str = ""
    headers: Mapping[str, str] = field(default_factory=dict)
    flags: frozenset[str] = field(default_factory=frozenset)
    known_contact: bool = False
    user_replied: bool = False
    has_attachment: bool = False

    def __post_init__(self) -> None:
        if not self.account_id.strip():
            raise ValueError("account_id non può essere vuoto")
        if not self.message_id.strip():
            raise ValueError("message_id non può essere vuoto")
        if self.received_at.tzinfo is None:
            raise ValueError("received_at deve includere il fuso orario")

    def age_days(self, now: datetime) -> int:
        if now.tzinfo is None:
            raise ValueError("now deve includere il fuso orario")
        return max(0, (now - self.received_at).days)

    @property
    def normalized_flags(self) -> frozenset[str]:
        return frozenset(flag.casefold() for flag in self.flags)


@dataclass(frozen=True, slots=True)
class Classification:
    category: EmailCategory
    confidence: float
    reason_codes: tuple[str, ...]
    classifier: str
    retention: RetentionSignal = RetentionSignal.UNCERTAIN
    retention_confidence: float = 0.0

    def __post_init__(self) -> None:
        if (
            isinstance(self.confidence, bool)
            or not isinstance(self.confidence, (int, float))
            or not math.isfinite(float(self.confidence))
            or not 0.0 <= float(self.confidence) <= 1.0
        ):
            raise ValueError("confidence deve essere compresa tra 0 e 1")
        if (
            isinstance(self.retention_confidence, bool)
            or not isinstance(self.retention_confidence, (int, float))
            or not math.isfinite(float(self.retention_confidence))
            or not 0.0 <= float(self.retention_confidence) <= 1.0
        ):
            raise ValueError("retention_confidence deve essere compresa tra 0 e 1")
        if len(self.reason_codes) > 8:
            raise ValueError("sono ammessi al massimo 8 reason_codes")


@dataclass(frozen=True, slots=True)
class PreferenceSnapshot:
    score: float
    observations: int
    keep_similarity: float = 0.0
    dont_keep_similarity: float = 0.0
    keep_similar_examples: int = 0
    dont_keep_similar_examples: int = 0
    recent_content_score: float = 0.5
    recent_content_evidence: float = 0.0
    recent_content_examples: int = 0

    def __post_init__(self) -> None:
        probabilities = {
            "score": self.score,
            "keep_similarity": self.keep_similarity,
            "dont_keep_similarity": self.dont_keep_similarity,
            "recent_content_score": self.recent_content_score,
        }
        for name, value in probabilities.items():
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or not 0.0 <= float(value) <= 1.0
            ):
                raise ValueError(f"{name} deve essere compreso tra 0 e 1")
        counts = {
            "observations": self.observations,
            "keep_similar_examples": self.keep_similar_examples,
            "dont_keep_similar_examples": self.dont_keep_similar_examples,
            "recent_content_examples": self.recent_content_examples,
        }
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in counts.values()
        ):
            raise ValueError("i conteggi delle preferenze non possono essere negativi")
        if (
            isinstance(self.recent_content_evidence, bool)
            or not isinstance(self.recent_content_evidence, (int, float))
            or not math.isfinite(float(self.recent_content_evidence))
            or self.recent_content_evidence < 0.0
        ):
            raise ValueError("recent_content_evidence non può essere negativa")


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    action: PolicyAction
    reason_codes: tuple[str, ...]
    dry_run: bool = True

    @property
    def changes_mailbox(self) -> bool:
        # Nella fase 1 ogni decisione è solo una proposta.
        return False
