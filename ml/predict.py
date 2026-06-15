"""Simple, safe prediction shim for payload anomaly detection.

This implementation attempts to load a persisted model from the local
`ml/` directory (common filenames: `model.joblib`, `model.pkl`). If no
model is available, it returns a safe "NORMAL" fallback so the WAF
continues operating.
"""
from __future__ import annotations

import os
from typing import Dict, Any

MODEL_FILENAMES = ("model.joblib", "model.pkl")

_model = None


def _try_load_model() -> None:
    global _model
    if _model is not None:
        return
    base = os.path.dirname(__file__)
    for name in MODEL_FILENAMES:
        path = os.path.join(base, name)
        if os.path.exists(path):
            try:
                from joblib import load

                _model = load(path)
                return
            except Exception:
                _model = None
                return


def predict_payload(payload: str) -> Dict[str, Any]:
    """Predict whether `payload` is anomalous.

    Returns a dict with keys `prediction` and `score`.
    If no model is available or an error occurs, returns the safe fallback:
    {"prediction": "NORMAL", "score": 0.0}
    """
    try:
        _try_load_model()
        if _model is None:
            return {"prediction": "NORMAL", "score": 0.0}

        # Lightweight featurization: length and digit fraction.
        try:
            import numpy as np

            digits = sum(c.isdigit() for c in payload)
            features = [len(payload), digits]
            X = np.array(features).reshape(1, -1)
        except Exception:
            # If numpy unavailable or featurization fails, fallback safely.
            X = None

        if X is None:
            # If model supports string inputs, try passing payload directly.
            try:
                pred = _model.predict([payload])[0]
                score = float(getattr(_model, "score", 0.0))
                return {"prediction": str(pred), "score": score}
            except Exception:
                return {"prediction": "NORMAL", "score": 0.0}

        # Prefer probability outputs when available
        try:
            if hasattr(_model, "predict_proba"):
                probs = _model.predict_proba(X)
                # best class and probability
                idx = int(probs.argmax())
                cls = _model.classes_[idx] if hasattr(_model, "classes_") else None
                score = float(probs.max())
                return {"prediction": str(cls) if cls is not None else "ANOMALY", "score": score}
            else:
                pred = _model.predict(X)[0]
                return {"prediction": str(pred), "score": float(getattr(_model, "score", 0.0))}
        except Exception:
            return {"prediction": "NORMAL", "score": 0.0}
    except Exception:
        return {"prediction": "NORMAL", "score": 0.0}
