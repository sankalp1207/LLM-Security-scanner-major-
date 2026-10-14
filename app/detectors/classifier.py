"""Detector classifier adapter providing ML prediction capabilities to detection modules."""

from typing import Tuple

from app.ml.inference import ThreatPrediction, threat_engine


class ClassifierAdapter:
    """Wrapper exposing ML threat probability and top features."""

    @staticmethod
    def classify(text: str, threshold: float = 0.55) -> ThreatPrediction:
        """Classify input text using baseline ML model."""
        return threat_engine.predict(text, threshold=threshold)

    @staticmethod
    def is_suspicious(text: str, threshold: float = 0.55) -> Tuple[bool, float]:
        """Convenience helper returning (is_threat, probability)."""
        pred = threat_engine.predict(text, threshold=threshold)
        return pred.is_threat, pred.probability
