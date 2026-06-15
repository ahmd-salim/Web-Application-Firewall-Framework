"""ML package for payload prediction.

Provides a safe `predict_payload` function via `ml.predict`.
"""

from .predict import predict_payload

__all__ = ["predict_payload"]
