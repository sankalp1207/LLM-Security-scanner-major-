"""Security schemas and enumerations for threat categories, severity, and detection."""

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ThreatCategory(str, Enum):
    """Supported LLM security threat categories."""

    PROMPT_INJECTION = "prompt_injection"
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"
    JAILBREAK = "jailbreak"
    DATA_LEAKAGE = "data_leakage"
    BENIGN = "benign"


class SeverityLevel(str, Enum):
    """Documented security severity levels."""

    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DetectionRequest(BaseModel):
    """Payload for real-time text threat detection."""

    text: str = Field(..., min_length=1, max_length=32768, description="Input text to analyze")
    context: Optional[str] = Field(None, max_length=65536, description="Optional RAG context or system prompt")
    category_hint: Optional[ThreatCategory] = Field(None, description="Optional category to focus analysis")


class DetectionResponse(BaseModel):
    """Structured detection outcome with evidence and recommendations."""

    is_suspicious: bool = Field(..., description="Whether the input triggers suspicious indicators or ML thresholds")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Classifier probability or heuristic confidence")
    predicted_category: ThreatCategory = Field(..., description="Primary identified threat category")
    severity: SeverityLevel = Field(..., description="Assessed severity level if exploited")
    matched_indicators: List[str] = Field(default_factory=list, description="Rule-based heuristic or canary match details")
    explanation: str = Field(..., description="Human-readable rationale for the detection decision")
    recommended_action: str = Field(..., description="Defensive guidance (e.g. block, sanitize, log)")
    details: Dict[str, Any] = Field(default_factory=dict, description="Detailed diagnostic scores and token matches")
