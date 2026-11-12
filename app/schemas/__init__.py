"""Pydantic schemas package."""

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
from app.schemas.events import (
    ScanEventListResponse,
    ScanEventSchema,
    ScanEventType,
    ScanProgressResponse,
)

__all__ = [
    "ScanEventType",
    "ScanEventSchema",
    "ScanEventListResponse",
    "ScanProgressResponse",
    "ConversationCreateRequest",
    "ConversationUpdateRequest",
    "MessageSendRequest",
    "CopilotMessageResponse",
    "CopilotConversationResponse",
    "CopilotConversationListResponse",
    "CopilotExplainFindingRequest",
    "FindingExplanationResponse",
    "CopilotCompareScansRequest",
    "ScanComparisonResponse",
]
