"""Real-time detection API endpoint evaluating user text against modular security detectors."""

from fastapi import APIRouter

from app.detectors.data_leakage import DataLeakageDetector
from app.detectors.indirect_injection import IndirectInjectionDetector
from app.detectors.jailbreak import JailbreakDetector
from app.detectors.prompt_injection import PromptInjectionDetector
from app.schemas.security import (
    DetectionRequest,
    DetectionResponse,
    SeverityLevel,
    ThreatCategory,
)

router = APIRouter(tags=["Detection"])


@router.post("/detect", response_model=DetectionResponse)
def detect_threat(request: DetectionRequest) -> DetectionResponse:
    """Analyze a single input string or context snippet for adversarial LLM threats."""
    # 1. Run all modular detectors
    pi_res = PromptInjectionDetector.analyze(input_text=request.text)
    jb_res = JailbreakDetector.analyze(input_text=request.text)
    dl_res = DataLeakageDetector.analyze(input_text=request.text)

    indirect_res = None
    if request.context:
        indirect_res = IndirectInjectionDetector.analyze(context_or_docs=request.context)

    # 2. Select dominant finding based on detection and confidence
    results = [pi_res, jb_res, dl_res]
    if indirect_res:
        results.append(indirect_res)

    detected_results = [r for r in results if r.is_detected]

    if not detected_results:
        # Benign outcome
        return DetectionResponse(
            is_suspicious=False,
            confidence_score=0.92,
            predicted_category=ThreatCategory.BENIGN,
            severity=SeverityLevel.INFORMATIONAL,
            matched_indicators=[],
            explanation="Input text does not exhibit adversarial manipulation, policy evasion, or secret probes.",
            recommended_action="Allow request to proceed normally.",
            details={"evaluations_run": len(results)},
        )

    # Prioritize by exploit verification and then highest confidence
    detected_results.sort(key=lambda r: (r.exploit_verified, r.confidence_score), reverse=True)
    top_result = detected_results[0]

    all_indicators = []
    for r in detected_results:
        all_indicators.extend(r.matched_indicators)

    # Action recommendation based on severity
    if top_result.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH):
        action = "Block request immediately and log security incident."
    elif top_result.severity == SeverityLevel.MEDIUM:
        action = "Apply runtime guardrail filters or request confirmation before execution."
    else:
        action = "Log suspicious interaction telemetry for monitoring."

    return DetectionResponse(
        is_suspicious=True,
        confidence_score=top_result.confidence_score,
        predicted_category=top_result.category,
        severity=top_result.severity,
        matched_indicators=all_indicators,
        explanation=top_result.explanation,
        recommended_action=action,
        details={
            "dominant_detector": top_result.category.value,
            "evidence": top_result.evidence,
        },
    )
