"""FastAPI route endpoints for AI Security Copilot conversational sessions and intelligence queries."""

from typing import List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.schemas.copilot import (
    ConversationCreateRequest,
    ConversationUpdateRequest,
    CopilotCompareScansRequest,
    CopilotConversationListResponse,
    CopilotConversationResponse,
    CopilotExplainFindingRequest,
    CopilotMessageResponse,
    FindingExplanationResponse,
    MessageSendRequest,
    ScanComparisonResponse,
)
from app.services.copilot_service import CopilotService
from app.services.copilot_tools import CopilotToolAccessError

router = APIRouter(prefix="/copilot", tags=["AI Security Copilot"])


def get_current_user_id(x_user_id: Optional[str] = Header(None)) -> str:
    """Extract authenticated user identity from header or default."""
    return (x_user_id or "default_user").strip()


# -----------------------------------------------------------------------------
# CONVERSATION MANAGEMENT
# -----------------------------------------------------------------------------
@router.post("/conversations", response_model=CopilotConversationResponse)
def create_conversation(
    request: ConversationCreateRequest,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> CopilotConversationResponse:
    """Create a new Copilot conversational session optionally bound to a project."""
    try:
        return CopilotService.create_conversation(db=db, user_id=user_id, request=request)
    except CopilotToolAccessError as e:
        raise HTTPException(status_code=403, detail=str(e))


@router.get("/conversations", response_model=CopilotConversationListResponse)
def list_conversations(
    project_id: Optional[str] = Query(None, description="Optional filter by project workspace"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> CopilotConversationListResponse:
    """List conversation sessions owned by the authenticated user."""
    return CopilotService.list_conversations(
        db=db, user_id=user_id, project_id=project_id, skip=skip, limit=limit
    )


@router.get("/conversations/{conversation_id}", response_model=CopilotConversationResponse)
def get_conversation(
    conversation_id: str,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> CopilotConversationResponse:
    """Retrieve metadata for a specific conversation session."""
    try:
        return CopilotService.get_conversation(db=db, conversation_id=conversation_id, user_id=user_id)
    except CopilotToolAccessError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.delete("/conversations/{conversation_id}")
def delete_conversation(
    conversation_id: str,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> dict:
    """Delete a conversation session and all historical messages."""
    try:
        CopilotService.delete_conversation(db=db, conversation_id=conversation_id, user_id=user_id)
        return {"status": "success", "message": f"Conversation '{conversation_id}' deleted."}
    except CopilotToolAccessError as e:
        raise HTTPException(status_code=404, detail=str(e))


# -----------------------------------------------------------------------------
# MESSAGES & CHAT INTERACTION
# -----------------------------------------------------------------------------
@router.post("/conversations/{conversation_id}/messages", response_model=CopilotMessageResponse)
async def send_message(
    conversation_id: str,
    request: MessageSendRequest,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> CopilotMessageResponse:
    """Send a user message to the Copilot, execute context tools, and receive AI security advisory."""
    try:
        return await CopilotService.process_user_message(
            db=db,
            conversation_id=conversation_id,
            user_id=user_id,
            request=request,
        )
    except CopilotToolAccessError as e:
        raise HTTPException(status_code=403, detail=str(e))


@router.get("/conversations/{conversation_id}/messages", response_model=List[CopilotMessageResponse])
def list_messages(
    conversation_id: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=200),
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> List[CopilotMessageResponse]:
    """Retrieve chronological message history for a conversation."""
    try:
        return CopilotService.list_messages(
            db=db, conversation_id=conversation_id, user_id=user_id, skip=skip, limit=limit
        )
    except CopilotToolAccessError as e:
        raise HTTPException(status_code=404, detail=str(e))


# -----------------------------------------------------------------------------
# DEDICATED SECURITY INTELLIGENCE ENDPOINTS
# -----------------------------------------------------------------------------
@router.post("/explain-finding/{finding_id}", response_model=FindingExplanationResponse)
async def explain_finding(
    finding_id: str,
    request: Optional[CopilotExplainFindingRequest] = None,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> FindingExplanationResponse:
    """Generate structured evidence-backed analysis and remediation guidance for a specific finding."""
    try:
        user_query = request.user_query if request else None
        return await CopilotService.explain_finding(
            db=db,
            finding_id=finding_id,
            user_id=user_id,
            user_query=user_query,
        )
    except CopilotToolAccessError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/compare-scans", response_model=ScanComparisonResponse)
def compare_scans(
    request: CopilotCompareScansRequest,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
) -> ScanComparisonResponse:
    """Compare two historical security scans and compute differential security posture."""
    try:
        return CopilotService.compare_scans(
            db=db,
            scan_id_a=request.scan_id_a,
            scan_id_b=request.scan_id_b,
            user_id=user_id,
        )
    except CopilotToolAccessError as e:
        raise HTTPException(status_code=404, detail=str(e))
