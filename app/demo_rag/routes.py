"""FastAPI route handlers for the Vulnerable and Defended Demo RAG Target."""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.config import Settings, get_settings
from app.demo_rag.documents import get_all_documents
from app.demo_rag.generator import MockDeterministicGenerator
from app.demo_rag.retrieval import default_retriever

router = APIRouter(prefix="/demo-rag", tags=["Demonstration RAG Application"])

# In-memory target state (synchronized with settings by default)
demo_state = {
    "vulnerable_mode": True,
}

mock_generator = MockDeterministicGenerator()


class RAGQueryRequest(BaseModel):
    """Request payload for RAG query execution."""

    query: str = Field(..., min_length=1, max_length=4096, example="What is the refund policy?")
    vulnerable_mode: Optional[bool] = Field(
        None,
        description="Override global vulnerable mode for this specific test request",
    )
    top_k: int = Field(default=3, ge=1, le=10)


class RAGQueryResponse(BaseModel):
    """Response returned by the Demo RAG application."""

    response: str
    retrieved_documents: List[Dict[str, Any]]
    vulnerable_mode: bool
    guardrail_interventions: List[str]
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ConfigUpdateRequest(BaseModel):
    """Payload to toggle demo target security posture."""

    vulnerable_mode: bool = Field(..., description="Enable or disable vulnerable mode")


@router.post("/query", response_model=RAGQueryResponse)
def execute_query(
    request: RAGQueryRequest,
    settings: Settings = Depends(get_settings),
) -> RAGQueryResponse:
    """Execute a query against the synthetic RAG pipeline with optional guardrail defenses."""
    # Determine execution mode: request override > dynamic demo_state > settings default
    if request.vulnerable_mode is not None:
        effective_vulnerable = request.vulnerable_mode
    else:
        effective_vulnerable = demo_state.get("vulnerable_mode", settings.DEMO_RAG_VULNERABLE_MODE)

    # 1. Retrieval
    retrieved_pairs = default_retriever.retrieve(request.query, top_k=request.top_k)
    retrieved_docs = [doc for doc, _ in retrieved_pairs]

    # 2. Generation (Vulnerable or Defended)
    generation_result = mock_generator.generate(
        query=request.query,
        retrieved_docs=retrieved_docs,
        vulnerable_mode=effective_vulnerable,
    )

    doc_summaries = [
        {
            "id": d.id,
            "title": d.title,
            "category": d.category,
            "is_confidential": d.is_confidential,
            "is_poisoned": d.is_poisoned,
        }
        for d in generation_result.retrieved_documents
    ]

    return RAGQueryResponse(
        response=generation_result.text,
        retrieved_documents=doc_summaries,
        vulnerable_mode=generation_result.vulnerable_mode,
        guardrail_interventions=generation_result.guardrail_interventions,
        metadata=generation_result.metadata,
    )


@router.get("/documents")
def list_documents() -> List[Dict[str, Any]]:
    """List synthetic indexed documents and metadata."""
    docs = get_all_documents()
    return [
        {
            "id": d.id,
            "title": d.title,
            "category": d.category,
            "is_confidential": d.is_confidential,
            "is_poisoned": d.is_poisoned,
            "length": len(d.content),
        }
        for d in docs
    ]


@router.get("/config")
def get_config(settings: Settings = Depends(get_settings)) -> Dict[str, Any]:
    """Retrieve current security configuration for Demo RAG target."""
    return {
        "vulnerable_mode": demo_state.get("vulnerable_mode", settings.DEMO_RAG_VULNERABLE_MODE),
        "target_name": "ACME Corp Synthetic RAG Service",
        "guardrails_active": not demo_state.get("vulnerable_mode", settings.DEMO_RAG_VULNERABLE_MODE),
    }


@router.post("/config")
def update_config(config: ConfigUpdateRequest) -> Dict[str, Any]:
    """Update vulnerable vs defensive mode dynamically."""
    demo_state["vulnerable_mode"] = config.vulnerable_mode
    return {
        "vulnerable_mode": demo_state["vulnerable_mode"],
        "status": "updated",
        "guardrails_active": not demo_state["vulnerable_mode"],
    }
