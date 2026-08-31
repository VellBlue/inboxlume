from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from email.utils import parseaddr
from enum import StrEnum

from .learning import FeedbackSignal, PreferenceStore
from .models import Classification, EmailCategory, EmailRecord


class QuizAnswer(StrEnum):
    KEEP = "keep"
    DONT_KEEP = "dont_keep"
    UNSURE = "unsure"


@dataclass(frozen=True, slots=True)
class QuizCandidate:
    message: EmailRecord
    classification: Classification


def _sender_key(message: EmailRecord) -> str:
    address = parseaddr(message.sender)[1].casefold()
    return address or message.sender.casefold()


class QuizSelector:
    """Seleziona casi informativi evitando sequenze dello stesso mittente."""

    def __init__(self, max_per_sender: int = 2) -> None:
        if max_per_sender < 1:
            raise ValueError("max_per_sender deve essere almeno 1")
        self.max_per_sender = max_per_sender

    def select(
        self,
        candidates: list[QuizCandidate],
        limit: int,
        store: PreferenceStore | None = None,
    ) -> list[QuizCandidate]:
        if limit < 1:
            return []
        unique: dict[tuple[str, str], QuizCandidate] = {}
        for candidate in candidates:
            key = (candidate.message.account_id, candidate.message.message_id)
            if store is not None and store.has_quiz_answer(candidate.message):
                continue
            unique.setdefault(key, candidate)

        def priority(candidate: QuizCandidate) -> tuple[int, float, str]:
            uncertain = candidate.classification.category in {
                EmailCategory.UNCERTAIN,
                EmailCategory.OTHER,
            }
            return (
                0 if uncertain else 1,
                candidate.classification.confidence,
                candidate.message.message_id,
            )

        ordered = sorted(unique.values(), key=priority)
        chosen: list[QuizCandidate] = []
        sender_counts: Counter[str] = Counter()
        category_counts: Counter[EmailCategory] = Counter()

        # Primo giro: massima diversità anche tra categorie.
        for candidate in ordered:
            sender = _sender_key(candidate.message)
            category = candidate.classification.category
            if sender_counts[sender] >= self.max_per_sender or category_counts[category] >= 2:
                continue
            chosen.append(candidate)
            sender_counts[sender] += 1
            category_counts[category] += 1
            if len(chosen) == limit:
                return chosen

        # Secondo giro: riempie il limite rispettando almeno il vincolo mittente.
        chosen_ids = {item.message.message_id for item in chosen}
        for candidate in ordered:
            sender = _sender_key(candidate.message)
            if candidate.message.message_id in chosen_ids:
                continue
            if sender_counts[sender] >= self.max_per_sender:
                continue
            chosen.append(candidate)
            chosen_ids.add(candidate.message.message_id)
            sender_counts[sender] += 1
            if len(chosen) == limit:
                break
        return chosen


class CalibrationQuiz:
    def __init__(self, store: PreferenceStore) -> None:
        self.store = store

    def answer(self, candidate: QuizCandidate, answer: QuizAnswer) -> None:
        signal = {
            QuizAnswer.KEEP: FeedbackSignal.EXPLICIT_KEEP,
            QuizAnswer.DONT_KEEP: FeedbackSignal.EXPLICIT_NOT_INTERESTED,
            QuizAnswer.UNSURE: None,
        }[answer]
        self.store.record_quiz_answer(
            candidate.message,
            candidate.classification,
            answer.value,
            signal,
        )

