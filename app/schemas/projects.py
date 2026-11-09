"""Pydantic request and response schemas for projects, target configurations, and onboarding."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TargetConfigurationCreate(BaseModel):
    """Schema for creating a target endpoint configuration."""

    provider: str = Field(default="demo", description="Target provider (demo, ollama, vllm, openai_compatible, generic_http)")
    endpoint_url: str = Field(..., min_length=1, max_length=512, description="HTTP/HTTPS destination endpoint")
    model_identifier: str = Field(default="", max_length=128, description="Target model name or deployment ID")
    auth_type: str = Field(default="none", description="Authentication scheme (none, bearer, api_key, basic)")
    credential: Optional[str] = Field(default=None, description="Plaintext credential to encrypt (never returned)")
    connection_timeout: float = Field(default=10.0, ge=1.0, le=60.0, description="Connection timeout in seconds")


class TargetConfigurationUpdate(BaseModel):
    """Schema for updating target endpoint parameters."""

    provider: Optional[str] = None
    endpoint_url: Optional[str] = None
    model_identifier: Optional[str] = None
    auth_type: Optional[str] = None
    credential: Optional[str] = None
    connection_timeout: Optional[float] = None


class TargetConfigurationResponse(BaseModel):
    """Safe schema for returning target parameters without leaking secrets."""

    id: str
    project_id: str
    provider: str
    endpoint_url: str
    model_identifier: str
    auth_type: str
    masked_credential: str = Field(default="", description="Masked credential string, e.g. sk-••••••••1234")
    connection_timeout: float
    connection_status: str
    last_verified_at: Optional[str] = None
    verification_details: Dict[str, Any] = Field(default_factory=dict)


class SecurityPreferences(BaseModel):
    """Configurable security testing preferences for a project."""

    direct_prompt_injection: bool = True
    indirect_prompt_injection: bool = True
    jailbreak_testing: bool = True
    sensitive_data_leakage: bool = True
    rag_security: bool = True
    agent_security: bool = False
    input_validation: bool = True
    output_validation: bool = True
    scan_preference: str = Field(default="full", description="quick, full, deep_red_team")
    adversarial_mutation_fuzzing: bool = True


class ProjectCreateRequest(BaseModel):
    """Schema for provisioning a new security testing project."""

    name: str = Field(..., min_length=2, max_length=128, description="Project name")
    description: str = Field(default="", max_length=1000, description="Project scope or application description")
    application_type: str = Field(default="rag", description="chatbot, rag, agent, api, custom")
    environment: str = Field(default="development", description="development, testing, staging, production")
    target_type: str = Field(default="demo", description="demo, local_llm, external_api")
    target_configuration: Optional[TargetConfigurationCreate] = None
    default_scan_preferences: Optional[Dict[str, Any]] = None


class ProjectUpdateRequest(BaseModel):
    """Schema for modifying project details."""

    name: Optional[str] = Field(None, min_length=2, max_length=128)
    description: Optional[str] = Field(None, max_length=1000)
    application_type: Optional[str] = None
    environment: Optional[str] = None
    target_type: Optional[str] = None
    default_scan_preferences: Optional[Dict[str, Any]] = None
    is_archived: Optional[bool] = None


class ProjectResponse(BaseModel):
    """Full project representation returned to clients."""

    id: str
    owner_id: str
    name: str
    description: str
    application_type: str
    environment: str
    target_type: str
    target_configuration: Optional[TargetConfigurationResponse] = None
    default_scan_preferences: Dict[str, Any]
    is_archived: bool
    onboarding_completed: bool
    created_at: str
    updated_at: str
    last_scan_date: Optional[str] = None
    scans_count: int = 0
    security_posture_score: Optional[int] = None


class ProjectListResponse(BaseModel):
    """Paginated list of projects."""

    total: int
    items: List[ProjectResponse]


class ConnectionVerificationRequest(BaseModel):
    """Payload for live connection testing."""

    endpoint_url: Optional[str] = None
    target_type: Optional[str] = None
    provider: Optional[str] = None
    auth_type: Optional[str] = None
    credential: Optional[str] = None
    connection_timeout: Optional[float] = Field(default=10.0, ge=1.0, le=30.0)


class ConnectionVerificationResponse(BaseModel):
    """Structured response from non-adversarial connection diagnostics."""

    is_connected: bool
    status: str
    status_code: Optional[int] = None
    latency_ms: Optional[float] = None
    message: str
    remediation: str
    tested_url: str
    details: Dict[str, Any] = Field(default_factory=dict)


class OnboardingStatusResponse(BaseModel):
    """User onboarding status and project presence."""

    user_id: str
    is_completed: bool
    selected_demo: bool
    active_project_id: Optional[str] = None
    has_projects: bool = False


class OnboardingCompleteRequest(BaseModel):
    """Request acknowledging setup completion."""

    selected_demo: bool = False
    project_id: Optional[str] = None

