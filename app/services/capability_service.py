"""Target capability resolution and category compatibility evaluation."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.database.models import Project, TargetConfiguration


class CategorySupportDetail(BaseModel):
    """Detailed support status and rationale for a security testing category."""

    category: str
    is_supported: bool
    is_applicable: bool
    reason: str


class TargetCapabilityReport(BaseModel):
    """Comprehensive capability assessment and testing recommendations for a project target."""

    project_id: str
    project_name: str
    application_type: str
    target_type: str
    provider: str
    endpoint_url: str
    detected_capabilities: List[str]
    category_support: Dict[str, CategorySupportDetail]
    applicable_categories: List[str]
    skipped_categories: List[Dict[str, str]]
    recommended_preset: str


class CapabilityService:
    """Evaluates target capabilities and resolves compatible security test categories."""

    ALL_CATEGORIES = [
        "prompt_injection",
        "jailbreak",
        "data_leakage",
        "indirect_prompt_injection",
        "rag_security",
        "agent_security",
    ]

    @classmethod
    def resolve_project_capabilities(
        cls,
        project: Project,
        target_config: Optional[TargetConfiguration] = None,
    ) -> TargetCapabilityReport:
        """
        Inspect project configuration and provider parameters to establish target capabilities
        and filter applicable security testing categories.
        """
        tc = target_config or project.target_configuration
        app_type = (project.application_type or "rag").lower().strip()
        target_type = (project.target_type or "demo").lower().strip()
        provider = (tc.provider if tc else "demo").lower().strip()
        endpoint_url = tc.endpoint_url if tc else ""
        auth_type = (tc.auth_type if tc else "none").lower().strip()

        # 1. Determine capabilities
        capabilities: List[str] = ["chat_completion"]

        if target_type == "demo" or provider == "demo" or "demo-rag" in endpoint_url:
            capabilities.append("local_demo")
            capabilities.append("rag_retrieval")

        if app_type in ("rag", "custom") and "rag_retrieval" not in capabilities:
            capabilities.append("rag_retrieval")

        if app_type == "agent":
            capabilities.append("tool_calling")

        if auth_type not in ("none", ""):
            capabilities.append("authentication")

        # 2. Evaluate Category Support
        category_support: Dict[str, CategorySupportDetail] = {}
        applicable: List[str] = []
        skipped: List[Dict[str, str]] = []

        # Prompt Injection
        category_support["prompt_injection"] = CategorySupportDetail(
            category="prompt_injection",
            is_supported=True,
            is_applicable=True,
            reason="Applicable to all LLM target applications accepting prompt inputs.",
        )
        applicable.append("prompt_injection")

        # Jailbreak
        category_support["jailbreak"] = CategorySupportDetail(
            category="jailbreak",
            is_supported=True,
            is_applicable=True,
            reason="Applicable to all conversational and instruction-following models.",
        )
        applicable.append("jailbreak")

        # Data Leakage
        category_support["data_leakage"] = CategorySupportDetail(
            category="data_leakage",
            is_supported=True,
            is_applicable=True,
            reason="Evaluates unauthorized disclosure of confidential data and canary tokens.",
        )
        applicable.append("data_leakage")

        # Indirect Prompt Injection (Requires RAG retrieval / external context)
        has_rag = "rag_retrieval" in capabilities
        if has_rag:
            category_support["indirect_prompt_injection"] = CategorySupportDetail(
                category="indirect_prompt_injection",
                is_supported=True,
                is_applicable=True,
                reason="Target utilizes retrieved context/documents susceptible to delimiter smuggling.",
            )
            applicable.append("indirect_prompt_injection")
        else:
            reason = f"Application type '{app_type}' does not utilize retrieved context or documents; indirect prompt injection tests are skipped."
            category_support["indirect_prompt_injection"] = CategorySupportDetail(
                category="indirect_prompt_injection",
                is_supported=True,
                is_applicable=False,
                reason=reason,
            )
            skipped.append({"category": "indirect_prompt_injection", "reason": reason})

        # RAG Security
        if has_rag:
            category_support["rag_security"] = CategorySupportDetail(
                category="rag_security",
                is_supported=True,
                is_applicable=True,
                reason="Pipeline includes document retrieval components vulnerable to poisoning.",
            )
            applicable.append("rag_security")
        else:
            reason = f"Target application type '{app_type}' has no RAG retrieval pipeline configured."
            category_support["rag_security"] = CategorySupportDetail(
                category="rag_security",
                is_supported=True,
                is_applicable=False,
                reason=reason,
            )
            skipped.append({"category": "rag_security", "reason": reason})

        # Agent Security (Scheduled for Phase 4)
        agent_reason = "Agent tool security testing requires interactive tool-execution endpoints (planned for Phase 4)."
        category_support["agent_security"] = CategorySupportDetail(
            category="agent_security",
            is_supported=False,
            is_applicable=False,
            reason=agent_reason,
        )
        skipped.append({"category": "agent_security", "reason": agent_reason})

        # 3. Determine Recommended Preset
        env = (project.environment or "development").lower()
        if env in ("production", "staging"):
            recommended_preset = "full_scan"
        elif env == "testing":
            recommended_preset = "deep_red_team"
        else:
            recommended_preset = "quick_scan"

        return TargetCapabilityReport(
            project_id=project.id,
            project_name=project.name,
            application_type=app_type,
            target_type=target_type,
            provider=provider,
            endpoint_url=endpoint_url,
            detected_capabilities=capabilities,
            category_support=category_support,
            applicable_categories=applicable,
            skipped_categories=skipped,
            recommended_preset=recommended_preset,
        )
