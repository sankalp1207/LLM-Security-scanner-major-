"""Pydantic schemas for dataset and versioned test-case management."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class TestCaseCreateRequest(BaseModel):
    """Payload to create a new versioned security test case."""

    id: str = Field(..., min_length=2, max_length=64, description="Unique test case identifier")
    version: str = Field(default="1.0.0", description="Semantic version of test case")
    category: str = Field(..., min_length=2, max_length=64, description="Threat category")
    input: str = Field(..., min_length=1, description="Payload or prompt text")
    expected_behavior: str = Field(..., min_length=1, description="Required defensive behavior")
    expected_outcome: str = Field(default="", description="Specific expected result status")
    rationale: str = Field(default="", description="Security rationale")
    objective: str = Field(default="", description="Formal test objective")
    tags: List[str] = Field(default_factory=list, description="Categorization tags")
    provenance: str = Field(default="internal_synthetic", description="Origin of test case")
    license: str = Field(default="MIT", description="Dataset licensing terms")
    enabled: bool = Field(default=True)
    dataset_type: str = Field(default="evaluation", description="'training' or 'evaluation'")
    suite_version: str = Field(default="v1.0.0")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TestCaseUpdateRequest(BaseModel):
    """Payload to modify an existing test case."""

    category: Optional[str] = None
    input: Optional[str] = None
    expected_behavior: Optional[str] = None
    expected_outcome: Optional[str] = None
    rationale: Optional[str] = None
    objective: Optional[str] = None
    tags: Optional[List[str]] = None
    provenance: Optional[str] = None
    license: Optional[str] = None
    enabled: Optional[bool] = None
    version: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class TestCaseRetireRequest(BaseModel):
    """Payload to mark a test case as retired with an audit reason."""

    reason: str = Field(..., min_length=3, description="Justification for retiring test case")


class TestCaseResponse(BaseModel):
    """Response schema representing a single security test case."""

    id: str
    version: str
    category: str
    input: str
    expected_behavior: str
    expected_outcome: str
    rationale: str
    objective: str
    tags: List[str]
    provenance: str
    license: str
    enabled: bool
    retired: bool
    retirement_reason: Optional[str] = None
    dataset_type: str
    suite_version: str
    metadata: Dict[str, Any]
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    model_config = {"from_attributes": True}


class TestSuiteResponse(BaseModel):
    """Response schema representing a registered test suite version."""

    id: str
    suite_id: str
    version: str
    dataset_type: str
    description: str
    license: str
    provenance: str
    record_count: int
    checksum_sha256: str
    created_at: str

    model_config = {"from_attributes": True}


class DatasetImportRequest(BaseModel):
    """Request payload to import test cases via raw JSONL."""

    suite_version: str = Field(default="v1.0.0", description="Target suite version")
    dataset_type: str = Field(default="evaluation", description="'training' or 'evaluation'")
    raw_jsonl_content: str = Field(..., min_length=1, description="Raw JSONL lines to validate and import")


class DatasetImportResponse(BaseModel):
    """Response schema for dataset import operations."""

    status: str
    imported_count: int
    errors: List[str]


class DatasetExportMetadataItem(BaseModel):
    """Permitted metadata item exported for a test case."""

    id: str
    version: str
    category: str
    objective: str
    expected_behavior: str
    tags: List[str]
    provenance: str
    license: str
    enabled: bool
    retired: bool
    dataset_type: str
    has_metadata: bool
