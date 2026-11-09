"""Scan preset schemas, limits, and server-side configurations."""

from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class ScanPresetConfig(BaseModel):
    """Server-side configuration and constraints for a scan preset."""

    preset_id: str = Field(..., description="Unique preset identifier")
    name: str = Field(..., description="Human-readable preset name")
    description: str = Field(..., description="Detailed explanation of the scan preset")
    enabled_categories: List[str] = Field(..., description="Default threat categories included in the preset")
    max_tests: int = Field(..., ge=1, le=200, description="Maximum test cases executed under this preset")
    max_duration_seconds: float = Field(..., ge=10.0, le=1800.0, description="Server-enforced timeout ceiling")
    max_concurrency: int = Field(default=3, ge=1, le=10, description="Concurrent connection limit")
    request_timeout: float = Field(default=8.0, ge=1.0, le=60.0, description="Per-request HTTP timeout in seconds")
    retry_policy: int = Field(default=0, ge=0, le=3, description="Number of automatic retries on transient errors")
    adaptive_testing: bool = Field(default=False, description="Whether adaptive mutation testing is activated")
    mutation_fuzzing: bool = Field(default=False, description="Whether payload obfuscation fuzzing is applied")
    required_capabilities: List[str] = Field(default_factory=list, description="Target capabilities required to run")
    resource_intensity: str = Field(default="low", description="Resource consumption profile (low, medium, high)")
    recommended_use_case: str = Field(..., description="Ideal development or operational use case")
    requires_authorization_ack: bool = Field(
        default=False,
        description="Whether explicit user acknowledgement of target authorization is mandatory",
    )


# Canonical Server-Enforced Scan Presets
SCAN_PRESETS: Dict[str, ScanPresetConfig] = {
    "quick_scan": ScanPresetConfig(
        preset_id="quick_scan",
        name="Quick Scan",
        description="Fast baseline security assessment designed for rapid developer feedback and continuous integration checks.",
        enabled_categories=["prompt_injection", "jailbreak", "data_leakage"],
        max_tests=15,
        max_duration_seconds=90.0,
        max_concurrency=3,
        request_timeout=8.0,
        retry_policy=0,
        adaptive_testing=False,
        mutation_fuzzing=False,
        required_capabilities=["chat_completion"],
        resource_intensity="low",
        recommended_use_case="Local development, pre-commit validation, and smoke testing without service interruption.",
        requires_authorization_ack=False,
    ),
    "full_scan": ScanPresetConfig(
        preset_id="full_scan",
        name="Full Scan",
        description="Comprehensive multi-category security audit examining direct/indirect injections, jailbreaks, data leaks, and pipeline integrity.",
        enabled_categories=[
            "prompt_injection",
            "indirect_prompt_injection",
            "jailbreak",
            "data_leakage",
        ],
        max_tests=60,
        max_duration_seconds=300.0,
        max_concurrency=5,
        request_timeout=12.0,
        retry_policy=1,
        adaptive_testing=False,
        mutation_fuzzing=False,
        required_capabilities=["chat_completion"],
        resource_intensity="medium",
        recommended_use_case="Staging security audits, release candidate readiness, and scheduled vulnerability assessments.",
        requires_authorization_ack=False,
    ),
    "deep_red_team": ScanPresetConfig(
        preset_id="deep_red_team",
        name="Deep Red Team",
        description="Advanced adversarial testing combining base test suites with automated mutation fuzzing (Base64, Homoglyphs, Leetspeak, Delimiters) to assess evasion resistance.",
        enabled_categories=[
            "prompt_injection",
            "indirect_prompt_injection",
            "jailbreak",
            "data_leakage",
        ],
        max_tests=120,
        max_duration_seconds=600.0,
        max_concurrency=5,
        request_timeout=15.0,
        retry_policy=1,
        adaptive_testing=True,
        mutation_fuzzing=True,
        required_capabilities=["chat_completion"],
        resource_intensity="high",
        recommended_use_case="Pre-production security certification, penetration testing, and defense-in-depth fuzzing.",
        requires_authorization_ack=True,
    ),
}


def get_preset_by_id(preset_id: str) -> Optional[ScanPresetConfig]:
    """Retrieve preset config by identifier."""
    return SCAN_PRESETS.get(preset_id.lower().strip())


def list_presets() -> List[ScanPresetConfig]:
    """List all available scan presets."""
    return list(SCAN_PRESETS.values())
