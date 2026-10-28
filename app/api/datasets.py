"""FastAPI route handlers for versioned dataset and security test case management."""

from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.database.repository import TestCaseRepository, TestSuiteRepository
from app.ml.dataset import (
    calculate_dataset_checksum,
    export_dataset_metadata,
    get_dataset_statistics,
    load_dataset,
    validate_jsonl_content,
)
from app.schemas.datasets import (
    DatasetExportMetadataItem,
    DatasetImportRequest,
    DatasetImportResponse,
    TestCaseCreateRequest,
    TestCaseResponse,
    TestCaseRetireRequest,
    TestCaseUpdateRequest,
    TestSuiteResponse,
)

router = APIRouter(prefix="/datasets", tags=["Dataset & Threat Test Management"])


@router.get("/suites", response_model=List[TestSuiteResponse])
def list_suite_versions(
    dataset_type: Optional[str] = Query(None, description="Filter by 'training' or 'evaluation'"),
    db: Session = Depends(get_db),
) -> List[TestSuiteResponse]:
    """List all registered versioned test suite packages."""
    suites = TestSuiteRepository.list_suite_versions(db=db, dataset_type=dataset_type)
    return [
        TestSuiteResponse(
            id=s.id,
            suite_id=s.suite_id,
            version=s.version,
            dataset_type=s.dataset_type,
            description=s.description,
            license=s.license,
            provenance=s.provenance,
            record_count=s.record_count,
            checksum_sha256=s.checksum_sha256,
            created_at=s.created_at.isoformat() if s.created_at else "",
        )
        for s in suites
    ]


@router.get("/cases", response_model=List[TestCaseResponse])
def list_test_cases(
    category: Optional[str] = Query(None, description="Filter by threat category"),
    dataset_type: Optional[str] = Query(None, description="Filter by partition ('training' or 'evaluation')"),
    enabled_only: bool = Query(True, description="Filter only enabled test cases"),
    include_retired: bool = Query(False, description="Include retired obsolete test cases"),
    db: Session = Depends(get_db),
) -> List[TestCaseResponse]:
    """List test cases with category, dataset_type, and lifecycle status filtering."""
    cases = TestCaseRepository.get_all(
        db=db,
        category=category,
        enabled_only=enabled_only,
        dataset_type=dataset_type,
        include_retired=include_retired,
    )
    return [
        TestCaseResponse(
            id=c.id,
            version=c.version or "1.0.0",
            category=c.category,
            input=c.test_input,
            expected_behavior=c.expected_behavior,
            expected_outcome=c.expected_outcome or "",
            rationale=c.test_rationale or "",
            objective=c.objective or c.test_rationale or "",
            tags=c.tags or [],
            provenance=c.provenance or "internal_synthetic",
            license=c.license or "MIT",
            enabled=c.enabled,
            retired=c.retired,
            retirement_reason=c.retirement_reason,
            dataset_type=c.dataset_type or "evaluation",
            suite_version=c.suite_version or "v1.0.0",
            metadata=c.metadata_json or {},
            created_at=c.created_at.isoformat() if c.created_at else None,
            updated_at=c.updated_at.isoformat() if c.updated_at else None,
        )
        for c in cases
    ]


@router.get("/cases/{case_id}", response_model=TestCaseResponse)
def get_test_case(case_id: str, db: Session = Depends(get_db)) -> TestCaseResponse:
    """Retrieve details of a single security test case."""
    c = TestCaseRepository.get_by_id(db=db, case_id=case_id)
    if not c:
        raise HTTPException(status_code=404, detail=f"Test case '{case_id}' not found.")
    return TestCaseResponse(
        id=c.id,
        version=c.version or "1.0.0",
        category=c.category,
        input=c.test_input,
        expected_behavior=c.expected_behavior,
        expected_outcome=c.expected_outcome or "",
        rationale=c.test_rationale or "",
        objective=c.objective or c.test_rationale or "",
        tags=c.tags or [],
        provenance=c.provenance or "internal_synthetic",
        license=c.license or "MIT",
        enabled=c.enabled,
        retired=c.retired,
        retirement_reason=c.retirement_reason,
        dataset_type=c.dataset_type or "evaluation",
        suite_version=c.suite_version or "v1.0.0",
        metadata=c.metadata_json or {},
        created_at=c.created_at.isoformat() if c.created_at else None,
        updated_at=c.updated_at.isoformat() if c.updated_at else None,
    )


@router.post("/cases", response_model=TestCaseResponse, status_code=status.HTTP_201_CREATED)
def create_test_case(payload: TestCaseCreateRequest, db: Session = Depends(get_db)) -> TestCaseResponse:
    """Create a new versioned security test case."""
    existing = TestCaseRepository.get_by_id(db=db, case_id=payload.id)
    if existing:
        raise HTTPException(
            status_code=400,
            detail=f"Test case with ID '{payload.id}' already exists.",
        )

    tc = TestCaseRepository.create_case(db=db, case_data=payload.model_dump())
    return TestCaseResponse(
        id=tc.id,
        version=tc.version,
        category=tc.category,
        input=tc.test_input,
        expected_behavior=tc.expected_behavior,
        expected_outcome=tc.expected_outcome or "",
        rationale=tc.test_rationale or "",
        objective=tc.objective or tc.test_rationale or "",
        tags=tc.tags or [],
        provenance=tc.provenance,
        license=tc.license,
        enabled=tc.enabled,
        retired=tc.retired,
        retirement_reason=tc.retirement_reason,
        dataset_type=tc.dataset_type,
        suite_version=tc.suite_version,
        metadata=tc.metadata_json or {},
        created_at=tc.created_at.isoformat() if tc.created_at else None,
        updated_at=tc.updated_at.isoformat() if tc.updated_at else None,
    )


@router.put("/cases/{case_id}", response_model=TestCaseResponse)
def update_test_case(
    case_id: str,
    payload: TestCaseUpdateRequest,
    db: Session = Depends(get_db),
) -> TestCaseResponse:
    """Update fields or bump version of an existing test case."""
    existing = TestCaseRepository.get_by_id(db=db, case_id=case_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Test case '{case_id}' not found.")

    update_dict = {k: v for k, v in payload.model_dump().items() if v is not None}
    tc = TestCaseRepository.update_case(db=db, case_id=case_id, update_data=update_dict)
    if not tc:
        raise HTTPException(status_code=500, detail="Failed to update test case.")

    return TestCaseResponse(
        id=tc.id,
        version=tc.version,
        category=tc.category,
        input=tc.test_input,
        expected_behavior=tc.expected_behavior,
        expected_outcome=tc.expected_outcome or "",
        rationale=tc.test_rationale or "",
        objective=tc.objective or tc.test_rationale or "",
        tags=tc.tags or [],
        provenance=tc.provenance,
        license=tc.license,
        enabled=tc.enabled,
        retired=tc.retired,
        retirement_reason=tc.retirement_reason,
        dataset_type=tc.dataset_type,
        suite_version=tc.suite_version,
        metadata=tc.metadata_json or {},
        created_at=tc.created_at.isoformat() if tc.created_at else None,
        updated_at=tc.updated_at.isoformat() if tc.updated_at else None,
    )


@router.post("/cases/{case_id}/retire", response_model=TestCaseResponse)
def retire_test_case(
    case_id: str,
    payload: TestCaseRetireRequest,
    db: Session = Depends(get_db),
) -> TestCaseResponse:
    """Mark an obsolete test case as retired with an audit reason."""
    tc = TestCaseRepository.retire_case(db=db, case_id=case_id, reason=payload.reason)
    if not tc:
        raise HTTPException(status_code=404, detail=f"Test case '{case_id}' not found.")

    return TestCaseResponse(
        id=tc.id,
        version=tc.version,
        category=tc.category,
        input=tc.test_input,
        expected_behavior=tc.expected_behavior,
        expected_outcome=tc.expected_outcome or "",
        rationale=tc.test_rationale or "",
        objective=tc.objective or tc.test_rationale or "",
        tags=tc.tags or [],
        provenance=tc.provenance,
        license=tc.license,
        enabled=tc.enabled,
        retired=tc.retired,
        retirement_reason=tc.retirement_reason,
        dataset_type=tc.dataset_type,
        suite_version=tc.suite_version,
        metadata=tc.metadata_json or {},
        created_at=tc.created_at.isoformat() if tc.created_at else None,
        updated_at=tc.updated_at.isoformat() if tc.updated_at else None,
    )


@router.post("/import", response_model=DatasetImportResponse)
def import_dataset(payload: DatasetImportRequest, db: Session = Depends(get_db)) -> DatasetImportResponse:
    """Validate and import test cases from raw JSONL content without contamination."""
    valid_records, errors = validate_jsonl_content(
        payload.raw_jsonl_content,
        expected_type=payload.dataset_type,
    )

    if errors:
        return DatasetImportResponse(
            status="validation_failed",
            imported_count=0,
            errors=errors,
        )

    dicts = [r.model_dump() for r in valid_records]
    count = TestCaseRepository.bulk_upsert(
        db=db,
        test_cases=dicts,
        suite_version=payload.suite_version,
        dataset_type=payload.dataset_type,
    )

    return DatasetImportResponse(
        status="success",
        imported_count=count,
        errors=[],
    )


@router.get("/export", response_model=List[DatasetExportMetadataItem])
def export_metadata(
    dataset_type: Optional[str] = Query(None, description="Filter by 'training' or 'evaluation'"),
    category: Optional[str] = Query(None, description="Filter by category"),
    db: Session = Depends(get_db),
) -> List[DatasetExportMetadataItem]:
    """Export permitted metadata for active test cases without exposing raw payloads."""
    cases = TestCaseRepository.get_all(
        db=db,
        category=category,
        enabled_only=True,
        dataset_type=dataset_type,
        include_retired=False,
    )
    return [
        DatasetExportMetadataItem(
            id=c.id,
            version=c.version or "1.0.0",
            category=c.category,
            objective=c.objective or c.test_rationale or "",
            expected_behavior=c.expected_behavior,
            tags=c.tags or [],
            provenance=c.provenance or "internal_synthetic",
            license=c.license or "MIT",
            enabled=c.enabled,
            retired=c.retired,
            dataset_type=c.dataset_type or "evaluation",
            has_metadata=bool(c.metadata_json),
        )
        for c in cases
    ]


@router.get("/statistics")
def get_statistics(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Return live database test-case statistics."""
    all_cases = TestCaseRepository.get_all(db=db, enabled_only=False, include_retired=True)
    records = []
    for c in all_cases:
        from app.ml.dataset import TestCaseRecord
        records.append(
            TestCaseRecord(
                id=c.id,
                version=c.version or "1.0.0",
                category=c.category,
                input=c.test_input,
                expected_behavior=c.expected_behavior,
                expected_outcome=c.expected_outcome or "",
                rationale=c.test_rationale or "",
                objective=c.objective or c.test_rationale or "",
                tags=c.tags or [],
                provenance=c.provenance or "internal_synthetic",
                license=c.license or "MIT",
                enabled=c.enabled,
                retired=c.retired,
                retirement_reason=c.retirement_reason,
                dataset_type=c.dataset_type or "evaluation",
                metadata=c.metadata_json or {},
            )
        )
    return get_dataset_statistics(records)
