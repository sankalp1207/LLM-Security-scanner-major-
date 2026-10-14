"""Thread-safe model loading and real-time threat inference."""

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
from pydantic import BaseModel, Field

from app.config import get_settings


class ThreatPrediction(BaseModel):
    """Inference output schema."""

    is_threat: bool = Field(..., description="Binary classification (1 = suspicious, 0 = benign)")
    probability: float = Field(..., ge=0.0, le=1.0, description="Model-derived probability of threat")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence distance from threshold")
    top_contributing_tokens: List[Tuple[str, float]] = Field(
        default_factory=list,
        description="Explainability token weights",
    )
    model_loaded: bool = True
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ThreatInferenceEngine:
    """Singleton engine for model caching and inference execution."""

    _instance: Optional["ThreatInferenceEngine"] = None
    _pipeline = None

    def __new__(cls) -> "ThreatInferenceEngine":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        self.settings = get_settings()
        self.model_path = Path(self.settings.MODEL_DIR) / self.settings.MODEL_FILENAME
        self._load_model_if_available()

    def _load_model_if_available(self) -> bool:
        """Load serialized pipeline from disk if file exists."""
        if self._pipeline is not None:
            return True

        if self.model_path.is_file():
            try:
                self._pipeline = joblib.load(self.model_path)
                return True
            except Exception:
                self._pipeline = None
                return False
        return False

    def reload(self) -> bool:
        """Force reloading pipeline artifact from disk."""
        self._pipeline = None
        return self._load_model_if_available()

    def predict(self, text: str, threshold: Optional[float] = None) -> ThreatPrediction:
        """Execute inference against provided text."""
        thresh = threshold if threshold is not None else self.settings.DETECTION_THRESHOLD

        if not self._load_model_if_available():
            # Graceful fallback when model is not yet trained
            return ThreatPrediction(
                is_threat=False,
                probability=0.0,
                confidence=0.0,
                top_contributing_tokens=[],
                model_loaded=False,
                metadata={"status": "model_not_found", "fallback": True},
            )

        # Predict probability for class 1 (suspicious)
        probs = self._pipeline.predict_proba([text])[0]
        suspicious_prob = float(probs[1])
        is_threat = suspicious_prob >= thresh

        # Confidence: distance from decision threshold normalized
        confidence = round(abs(suspicious_prob - 0.5) * 2.0, 4)

        # Feature explanation (top token weights contributing to score)
        top_tokens = self._extract_top_features(text)

        return ThreatPrediction(
            is_threat=is_threat,
            probability=round(suspicious_prob, 4),
            confidence=confidence,
            top_contributing_tokens=top_tokens,
            model_loaded=True,
            metadata={"threshold": thresh},
        )

    def _extract_top_features(self, text: str, top_n: int = 5) -> List[Tuple[str, float]]:
        """Identify highest-weight tokens contributing to classification."""
        try:
            tfidf = self._pipeline.named_steps["tfidf"]
            clf = self._pipeline.named_steps["clf"]

            feature_names = tfidf.get_feature_names_out()
            coefficients = clf.coef_[0]

            # Transform single text
            tfidf_vec = tfidf.transform([text]).toarray()[0]
            matched_indices = tfidf_vec.nonzero()[0]

            contributions = []
            for idx in matched_indices:
                score = tfidf_vec[idx] * coefficients[idx]
                contributions.append((str(feature_names[idx]), round(float(score), 4)))

            # Sort descending by positive impact towards threat class
            contributions.sort(key=lambda x: x[1], reverse=True)
            return contributions[:top_n]
        except Exception:
            return []


# Global inference engine instance
threat_engine = ThreatInferenceEngine()
