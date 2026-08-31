from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from inboxlume.learning import PreferenceStore
from inboxlume.models import Classification, EmailCategory
from inboxlume.quiz import CalibrationQuiz, QuizAnswer, QuizCandidate, QuizSelector

from tests.helpers import make_message


def candidate(
    message_id: str,
    sender: str,
    category: EmailCategory,
    confidence: float,
) -> QuizCandidate:
    return QuizCandidate(
        make_message(message_id=message_id, sender=sender),
        Classification(category, confidence, ("test",), "test"),
    )


class QuizTests(unittest.TestCase):
    def test_selector_prioritizes_uncertainty_and_sender_diversity(self) -> None:
        candidates = [
            candidate("1", "a@example.invalid", EmailCategory.ADVERTISING, 0.90),
            candidate("2", "a@example.invalid", EmailCategory.UNCERTAIN, 0.20),
            candidate("3", "b@example.invalid", EmailCategory.SOCIAL, 0.80),
            candidate("4", "c@example.invalid", EmailCategory.SCHOOL, 0.85),
        ]
        selected = QuizSelector(max_per_sender=1).select(candidates, limit=3)
        self.assertEqual(selected[0].message.message_id, "2")
        self.assertEqual(len({item.message.sender for item in selected}), 3)

    def test_answers_train_locally_and_are_not_repeated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "quiz.sqlite3", b"q" * 32)
            quiz = CalibrationQuiz(store)
            keep = candidate("keep", "friend@example.invalid", EmailCategory.PERSONAL, 0.8)
            skip = candidate("skip", "unknown@example.invalid", EmailCategory.UNCERTAIN, 0.2)

            quiz.answer(keep, QuizAnswer.KEEP)
            quiz.answer(skip, QuizAnswer.UNSURE)

            self.assertTrue(store.has_quiz_answer(keep.message))
            self.assertTrue(store.has_quiz_answer(skip.message))
            self.assertGreater(
                store.interest_for(keep.message, keep.classification).score,
                0.75,
            )
            selected = QuizSelector().select([keep, skip], limit=2, store=store)
            self.assertEqual(selected, [])

    def test_dont_keep_is_a_strong_negative_signal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = PreferenceStore(Path(directory) / "quiz.sqlite3", b"n" * 32)
            quiz = CalibrationQuiz(store)
            remove = candidate("remove", "ads@example.invalid", EmailCategory.ADVERTISING, 0.9)
            quiz.answer(remove, QuizAnswer.DONT_KEEP)
            self.assertLess(
                store.interest_for(remove.message, remove.classification).score,
                0.5,
            )


if __name__ == "__main__":
    unittest.main()

