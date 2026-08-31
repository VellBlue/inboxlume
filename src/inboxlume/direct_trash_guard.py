from __future__ import annotations

from typing import Mapping

from .local_models import model_spec, profile_for_backend
from .settings import (
    RECOMMENDED_INITIAL_DONT_KEEP_ANSWERS,
    RECOMMENDED_INITIAL_KEEP_ANSWERS,
    RECOMMENDED_INITIAL_QUIZ_ANSWERS,
)


def require_direct_trash_model(backend: str, ollama_model: str) -> None:
    profile = profile_for_backend(backend, ollama_model)
    if profile is None or not model_spec(profile).direct_trash_allowed:
        raise ValueError(
            "il profilo selezionato usa solo la Quarantena per sicurezza; "
            "il Cestino diretto richiede il profilo Gemma 26B autorizzato"
        )


def require_direct_trash_authority(
    backend: str,
    ollama_model: str,
    calibration: Mapping[str, int],
) -> None:
    """Apply the same fail-closed Trash prerequisites to every entry point."""

    require_direct_trash_model(backend, ollama_model)
    total = sum(int(value) for value in calibration.values())
    if not (
        total >= RECOMMENDED_INITIAL_QUIZ_ANSWERS
        and int(calibration.get("keep", 0)) >= RECOMMENDED_INITIAL_KEEP_ANSWERS
        and int(calibration.get("dont_keep", 0))
        >= RECOMMENDED_INITIAL_DONT_KEEP_ANSWERS
    ):
        raise ValueError(
            "il Cestino diretto richiede la calibrazione iniziale completa"
        )
