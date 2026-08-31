"""Compatibilità temporanea per checkpoint Gemma 4 `gemma4_unified`.

MLX-LM 0.31.3 contiene l'implementazione Gemma 4 ma non l'alias del nuovo
`model_type`. L'alias è già presente nel ramo upstream successivo alla release.
Questo wrapper non modifica l'installazione e non scarica codice o modelli.
"""

from __future__ import annotations

import sys

from mlx_lm.models import gemma4


sys.modules.setdefault("mlx_lm.models.gemma4_unified", gemma4)

_original_sanitize = gemma4.Model.sanitize


def _sanitize_unified(self, weights):
    without_encoder = {
        key: value
        for key, value in weights.items()
        if not key.removeprefix("model.").startswith("vision_embedder")
    }
    return _original_sanitize(self, without_encoder)


gemma4.Model.sanitize = _sanitize_unified

from mlx_lm.generate import main  # noqa: E402


if __name__ == "__main__":
    main()
