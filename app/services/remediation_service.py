"""Central Remediation Service orchestrating analysis, fix generation, validation, approval, application, testing, and retesting."""

import asyncio
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.database.models import Finding, Remediation, RemediationPatch
from app.database.repository import (
    FindingRepository,
    ProjectRepository,
    RemediationRepository,
)
from app.schemas.remediation import (
    PatchApplyResponse,
    PatchApprovalResponse,
    PatchValidationResponse,
    RemediationHistoryItem,
    RemediationHistoryResponse,
    RemediationPatchFile,
    RemediationPatchResponse,
    RemediationResponse,
    RemediationRollbackResponse,
    RemediationVerifyResponse,
)
from app.services.finding_service import FindingService
from app.services.patch_validator import PatchValidator
from app.services.remediation_library import RemediationLibrary
from app.services.remediation_workspace import ControlledWorkspace, WorkspaceSecurityError


class RemediationServiceError(Exception):
    """Raised when remediation workflow state transition or business logic fails."""
    pass


class RemediationService:
    """Orchestrates the 10-stage end-to-end vulnerability remediation lifecycle."""

    @staticmethod
    def classify_verification_outcome(
        retest_status: str,
        tests_executed: int,
        tests_failed: int,
        exit_code: Optional[int],
    ) -> str:
        """Classify verification only when real tests and a conclusive retest exist."""
        if tests_failed > 0:
            return "REGRESSION_DETECTED"
        if tests_executed <= 0 or exit_code != 0 or retest_status == "RETEST_INCONCLUSIVE":
            return "INCONCLUSIVE"
        if retest_status == "RETEST_PASSED":
            return "FIXED"
        if retest_status == "RETEST_FAILED":
            return "NOT_FIXED"
        return "PARTIALLY_FIXED"

    @staticmethod
    async def _run_workspace_tests(workspace: Path) -> Dict[str, Any]:
        """Run pytest in the approved workspace and summarize its actual result."""
        started = time.perf_counter()
        try:
            process = await asyncio.create_subprocess_exec(
                sys.executable, "-m", "pytest", "-q", "--disable-warnings",
                cwd=str(workspace),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            output_bytes, _ = await asyncio.wait_for(process.communicate(), timeout=120)
            output = output_bytes.decode("utf-8", errors="replace")
            counts = {name: 0 for name in ("passed", "failed", "error", "skipped", "xfailed", "xpassed")}
            for count, label in re.findall(
                r"\b(\d+) (passed|failed|errors?|skipped|xfailed|xpassed)\b", output
            ):
                normalized = "error" if label.startswith("error") else label
                counts[normalized] += int(count)
            executed = sum(counts.values())
            return {
                "test_runner": "pytest",
                "tests_executed": executed,
                "tests_passed": counts["passed"] + counts["xpassed"],
                "tests_failed": counts["failed"] + counts["error"],
                "tests_skipped": counts["skipped"] + counts["xfailed"],
                "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                "exit_code": process.returncode,
                "output_tail": output[-2000:],
            }
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return {
                "test_runner": "pytest", "tests_executed": 0, "tests_passed": 0,
                "tests_failed": 0, "tests_skipped": 0,
                "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                "exit_code": None, "error": "Workspace tests exceeded the 120 second limit.",
            }
        except (OSError, RuntimeError) as exc:
            return {
                "test_runner": "pytest", "tests_executed": 0, "tests_passed": 0,
                "tests_failed": 0, "tests_skipped": 0,
                "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                "exit_code": None, "error": f"Could not run workspace tests: {exc}",
            }

    @classmethod
    def _validate_finding_ownership(cls, db: Session, finding_id: str, user_id: str) -> Finding:
        """Verify that the finding exists and belongs to the authenticated tenant."""
        finding = FindingRepository.get_finding(db, finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")

        scan = finding.scan
        if scan:
            owner_match = (scan.user_id == user_id) or (scan.project and scan.project.owner_id == user_id)
            if not owner_match:
                raise HTTPException(status_code=404, detail="Finding not found or access denied.")

        return finding

    @classmethod
    def _validate_remediation_ownership(cls, db: Session, remediation_id: str, user_id: str) -> Remediation:
        """Verify that remediation exists and belongs to the authenticated user."""
        rem = RemediationRepository.get_remediation(db, remediation_id)
        if not rem:
            raise HTTPException(status_code=404, detail=f"Remediation '{remediation_id}' not found.")

        if rem.user_id != user_id:
            # Also check if user owns parent project
            if rem.project and rem.project.owner_id == user_id:
                pass
            else:
                raise HTTPException(status_code=404, detail="Remediation not found or access denied.")

        return rem

    @classmethod
    def initiate_remediation(
        cls,
        db: Session,
        finding_id: str,
        user_id: str,
        workspace_root: Optional[str] = None,
    ) -> RemediationResponse:
        """
        Stage 1 & 2: Analyze vulnerability finding and create remediation record.
        Automatically proposes initial patch if affected source code can be identified.
        """
        finding = cls._validate_finding_ownership(db, finding_id, user_id)

        project_id = finding.scan.project_id if finding.scan else None
        root_cause = RemediationLibrary.get_root_cause_analysis(
            category=finding.category, affected_component=finding.target_component
        )
        summary = f"Remediate {finding.title}"

        # 1. Create Remediation record
        remediation = RemediationRepository.create_remediation(
            db=db,
            finding_id=finding.id,
            user_id=user_id,
            project_id=project_id,
            summary=summary,
            root_cause_analysis=root_cause,
            affected_component=finding.target_component or "unknown",
            status="ANALYZING",
        )

        # 2. Stage 3 & 4: Attempt to generate and validate initial proposed fix
        ws_path = Path(workspace_root).resolve() if workspace_root else ControlledWorkspace.get_default_workspace_root()
        patch_data = RemediationLibrary.generate_patch_for_finding(finding, ws_path)

        latest_patch_id = None
        if patch_data:
            # Validate proposed patch structure and safety
            val_report = PatchValidator.validate_patch_safety_and_scope(
                patch_id="temp",
                files_manifest=patch_data["files"],
                source_hashes=patch_data["source_hashes"],
                workspace_root=ws_path,
            )

            val_status = "VALID" if val_report.is_valid else "INVALID"
            patch_record = RemediationRepository.create_patch(
                db=db,
                remediation_id=remediation.id,
                summary=patch_data["summary"],
                files_manifest=patch_data["files"],
                diff_content=patch_data["diff_content"],
                source_hashes=patch_data["source_hashes"],
                validation_status=val_status,
                validation_errors=val_report.errors,
                risks=patch_data.get("risks", []),
                verification_steps=patch_data.get("verification_steps", []),
            )
            latest_patch_id = patch_record.id

            new_status = "AWAITING_APPROVAL" if val_report.is_valid else "VALIDATION_FAILED"
            RemediationRepository.update_remediation_status(db, remediation.id, new_status)
            remediation.status = new_status
        else:
            # No direct patch file identified -> advise configuration review
            RemediationRepository.update_remediation_status(db, remediation.id, "FIX_PROPOSED")
            remediation.status = "FIX_PROPOSED"

        return RemediationResponse(
            id=remediation.id,
            project_id=remediation.project_id,
            finding_id=remediation.finding_id,
            user_id=remediation.user_id,
            status=remediation.status,
            summary=remediation.summary,
            root_cause_analysis=remediation.root_cause_analysis,
            affected_component=remediation.affected_component,
            created_at=remediation.created_at.isoformat(),
            updated_at=remediation.updated_at.isoformat(),
            latest_patch_id=latest_patch_id,
            latest_retest_status=finding.retest_status,
        )

    @classmethod
    def get_remediation(cls, db: Session, remediation_id: str, user_id: str) -> RemediationResponse:
        """Fetch remediation details and latest patch metadata."""
        rem = cls._validate_remediation_ownership(db, remediation_id, user_id)
        latest_patch = RemediationRepository.get_latest_patch(db, rem.id)
        latest_exec = RemediationRepository.get_latest_execution(db, rem.id)

        return RemediationResponse(
            id=rem.id,
            project_id=rem.project_id,
            finding_id=rem.finding_id,
            user_id=rem.user_id,
            status=rem.status,
            summary=rem.summary,
            root_cause_analysis=rem.root_cause_analysis,
            affected_component=rem.affected_component,
            created_at=rem.created_at.isoformat(),
            updated_at=rem.updated_at.isoformat(),
            latest_patch_id=latest_patch.id if latest_patch else None,
            latest_retest_status=latest_exec.retest_status if latest_exec else rem.finding.retest_status,
        )

    @classmethod
    def generate_fix(
        cls,
        db: Session,
        remediation_id: str,
        user_id: str,
        workspace_root: Optional[str] = None,
    ) -> RemediationPatchResponse:
        """Stage 3 & 4: Generate (or regenerate) a structured code patch for a remediation."""
        rem = cls._validate_remediation_ownership(db, remediation_id, user_id)
        ws_path = Path(workspace_root).resolve() if workspace_root else ControlledWorkspace.get_default_workspace_root()

        patch_data = RemediationLibrary.generate_patch_for_finding(rem.finding, ws_path)
        if not patch_data:
            raise HTTPException(
                status_code=400,
                detail="Could not automatically resolve target source file for this vulnerability. Please review configuration.",
            )

        val_report = PatchValidator.validate_patch_safety_and_scope(
            patch_id="temp",
            files_manifest=patch_data["files"],
            source_hashes=patch_data["source_hashes"],
            workspace_root=ws_path,
        )

        val_status = "VALID" if val_report.is_valid else "INVALID"
        patch = RemediationRepository.create_patch(
            db=db,
            remediation_id=rem.id,
            summary=patch_data["summary"],
            files_manifest=patch_data["files"],
            diff_content=patch_data["diff_content"],
            source_hashes=patch_data["source_hashes"],
            validation_status=val_status,
            validation_errors=val_report.errors,
            risks=patch_data.get("risks", []),
            verification_steps=patch_data.get("verification_steps", []),
        )

        new_status = "AWAITING_APPROVAL" if val_report.is_valid else "VALIDATION_FAILED"
        RemediationRepository.update_remediation_status(db, rem.id, new_status)

        return cls._format_patch_response(db, patch)

    @classmethod
    def get_patch(cls, db: Session, patch_id: str, user_id: str) -> RemediationPatchResponse:
        """Fetch patch details and diff representation."""
        patch = RemediationRepository.get_patch(db, patch_id)
        if not patch:
            raise HTTPException(status_code=404, detail=f"Patch '{patch_id}' not found.")

        cls._validate_remediation_ownership(db, patch.remediation_id, user_id)
        return cls._format_patch_response(db, patch)

    @classmethod
    def list_patches(cls, db: Session, remediation_id: str, user_id: str) -> List[RemediationPatchResponse]:
        """List all patch revisions for a remediation."""
        cls._validate_remediation_ownership(db, remediation_id, user_id)
        patches = RemediationRepository.list_patches(db, remediation_id)
        return [cls._format_patch_response(db, p) for p in patches]

    @classmethod
    def validate_patch(
        cls,
        db: Session,
        patch_id: str,
        user_id: str,
        workspace_root: Optional[str] = None,
    ) -> PatchValidationResponse:
        """Stage 4: Re-evaluate patch safety rules, workspace scope, and source file drift."""
        patch = RemediationRepository.get_patch(db, patch_id)
        if not patch:
            raise HTTPException(status_code=404, detail=f"Patch '{patch_id}' not found.")

        cls._validate_remediation_ownership(db, patch.remediation_id, user_id)
        ws_path = Path(workspace_root).resolve() if workspace_root else ControlledWorkspace.get_default_workspace_root()

        report = PatchValidator.validate_patch_safety_and_scope(
            patch_id=patch.id,
            files_manifest=patch.files_manifest,
            source_hashes=patch.source_hashes,
            workspace_root=ws_path,
        )

        val_status = "VALID" if report.is_valid else "INVALID"
        RemediationRepository.update_patch_validation(
            db, patch_id=patch.id, validation_status=val_status, validation_errors=report.errors
        )
        return report

    @classmethod
    def record_approval(
        cls,
        db: Session,
        patch_id: str,
        user_id: str,
        decision: str,
        reason: str = "",
    ) -> PatchApprovalResponse:
        """Stage 6: Record explicit human approval or rejection of a patch."""
        patch = RemediationRepository.get_patch(db, patch_id)
        if not patch:
            raise HTTPException(status_code=404, detail=f"Patch '{patch_id}' not found.")

        rem = cls._validate_remediation_ownership(db, patch.remediation_id, user_id)

        # Enforce that patch was validated before approval
        if decision == "APPROVED" and patch.validation_status != "VALID":
            raise HTTPException(
                status_code=400,
                detail=f"Cannot approve patch '{patch_id}': validation status is '{patch.validation_status}'.",
            )

        approval = RemediationRepository.create_approval(
            db=db,
            patch_id=patch.id,
            user_id=user_id,
            decision=decision,
            reason=reason or "",
        )

        new_status = "APPROVED" if decision == "APPROVED" else "REJECTED"
        RemediationRepository.update_remediation_status(db, rem.id, new_status)

        return PatchApprovalResponse(
            id=approval.id,
            patch_id=approval.patch_id,
            user_id=approval.user_id,
            decision=approval.decision,
            reason=approval.reason,
            created_at=approval.created_at.isoformat(),
        )

    @classmethod
    def apply_patch(
        cls,
        db: Session,
        patch_id: str,
        user_id: str,
        workspace_root: Optional[str] = None,
    ) -> PatchApplyResponse:
        """
        Stage 7: Apply approved patch files in a controlled local workspace.
        Enforces human approval, fresh drift validation, and automatic backup creation.
        """
        patch = RemediationRepository.get_patch(db, patch_id)
        if not patch:
            raise HTTPException(status_code=404, detail=f"Patch '{patch_id}' not found.")

        rem = cls._validate_remediation_ownership(db, patch.remediation_id, user_id)
        ws_path = Path(workspace_root).resolve() if workspace_root else ControlledWorkspace.get_default_workspace_root()

        # 1. Human Approval Check
        latest_approval = RemediationRepository.get_latest_approval(db, patch.id)
        if not latest_approval or latest_approval.decision != "APPROVED":
            raise HTTPException(
                status_code=400,
                detail="Security Gate: Patch has not been approved by a human operator.",
            )

        # 2. Fresh Drift Validation Check
        fresh_val = PatchValidator.validate_patch_safety_and_scope(
            patch_id=patch.id,
            files_manifest=patch.files_manifest,
            source_hashes=patch.source_hashes,
            workspace_root=ws_path,
        )
        if not fresh_val.is_valid:
            RemediationRepository.update_remediation_status(db, rem.id, "VALIDATION_FAILED")
            raise HTTPException(
                status_code=400,
                detail=f"Patch application rejected due to validation failure: {'; '.join(fresh_val.errors)}",
            )

        # 3. Apply files atomically with backup
        try:
            applied_files, backup_manifest = ControlledWorkspace.apply_patch_files(
                files_manifest=patch.files_manifest, workspace_root=ws_path
            )
        except WorkspaceSecurityError as e:
            RemediationRepository.update_remediation_status(db, rem.id, "FAILED")
            raise HTTPException(status_code=400, detail=f"Workspace application error: {str(e)}")

        # 4. Record execution
        execution = RemediationRepository.create_execution(
            db=db,
            remediation_id=rem.id,
            patch_id=patch.id,
            execution_status="APPLIED",
            backup_manifest=backup_manifest,
            test_summary={},
            retest_status="INCONCLUSIVE",
        )

        RemediationRepository.update_remediation_status(db, rem.id, "PATCH_APPLIED")

        return PatchApplyResponse(
            execution_id=execution.id,
            status="APPLIED",
            applied_files=applied_files,
            backup_count=len(backup_manifest),
            timestamp=execution.started_at.isoformat(),
        )

    @classmethod
    async def verify_remediation(
        cls,
        db: Session,
        remediation_id: str,
        user_id: str,
        workspace_root: Optional[str] = None,
    ) -> RemediationVerifyResponse:
        """
        Stage 8, 9, & 10: Run unit tests and retest the original vulnerability against the target.
        Evaluates verifiable security status (FIXED, PARTIALLY_FIXED, NOT_FIXED, REGRESSION_DETECTED).
        """
        rem = cls._validate_remediation_ownership(db, remediation_id, user_id)
        latest_exec = RemediationRepository.get_latest_execution(db, rem.id)
        if not latest_exec:
            raise HTTPException(status_code=400, detail="Cannot verify remediation: No applied patch execution found.")

        RemediationRepository.update_remediation_status(db, rem.id, "TESTING")

        # 1. Run the workspace's real test suite; never substitute synthetic pass counts.
        ws_path = Path(workspace_root).resolve() if workspace_root else ControlledWorkspace.get_default_workspace_root()
        test_summary = await cls._run_workspace_tests(ws_path)

        # 2. Retest original vulnerability
        try:
            retest_result = FindingService.retest_finding(db, finding_id=rem.finding_id)
            retest_status_raw = retest_result.get("retest_status", "RETEST_FAILED")
            retest_msg = retest_result.get("message", "")
        except Exception as e:
            retest_status_raw = "RETEST_INCONCLUSIVE"
            retest_msg = f"Retest execution failed: {str(e)}"

        # 3. Determine conclusive outcome
        final_status = cls.classify_verification_outcome(
            retest_status=retest_status_raw,
            tests_executed=test_summary["tests_executed"],
            tests_failed=test_summary["tests_failed"],
            exit_code=test_summary["exit_code"],
        )
        if final_status == "FIXED":
            outcome = "Remediation Verified: Original vulnerability was mitigated and all validation tests passed."
        elif final_status == "NOT_FIXED":
            outcome = "Remediation Ineffective: Vulnerability still reproduced during retesting."
        elif final_status == "REGRESSION_DETECTED":
            outcome = "Regression Detected: Workspace validation tests failed after patch application."
        elif final_status == "INCONCLUSIVE":
            outcome = "Verification Inconclusive: No conclusive passing test run and vulnerability retest were both available."
        else:
            outcome = "Partially Fixed: Some security indicators improved, but full verification requires further hardening."

        completed_at = datetime.now(timezone.utc)
        RemediationRepository.update_execution(
            db=db,
            execution_id=latest_exec.id,
            test_summary=test_summary,
            retest_status=final_status,
            retest_evidence=retest_result if "retest_result" in locals() else {},
            completed_at=completed_at,
        )

        RemediationRepository.update_remediation_status(db, rem.id, "RETEST_COMPLETED")

        return RemediationVerifyResponse(
            execution_id=latest_exec.id,
            remediation_id=rem.id,
            patch_id=latest_exec.patch_id,
            test_summary=test_summary,
            retest_status=final_status,
            retest_message=retest_msg,
            outcome=outcome,
            completed_at=completed_at.isoformat(),
        )

    @classmethod
    def rollback_remediation(
        cls,
        db: Session,
        remediation_id: str,
        user_id: str,
        workspace_root: Optional[str] = None,
    ) -> RemediationRollbackResponse:
        """Stage 12: Revert applied patch files using the recorded backup manifest."""
        rem = cls._validate_remediation_ownership(db, remediation_id, user_id)
        latest_exec = RemediationRepository.get_latest_execution(db, rem.id)
        if not latest_exec or latest_exec.execution_status != "APPLIED":
            raise HTTPException(status_code=400, detail="Cannot rollback: No currently applied execution record found.")

        ws_path = Path(workspace_root).resolve() if workspace_root else ControlledWorkspace.get_default_workspace_root()

        try:
            restored = ControlledWorkspace.rollback_patch_files(
                backup_manifest=latest_exec.backup_manifest, workspace_root=ws_path
            )
        except WorkspaceSecurityError as e:
            raise HTTPException(status_code=400, detail=f"Rollback safety error: {str(e)}")

        now = datetime.now(timezone.utc)
        RemediationRepository.update_execution(
            db=db,
            execution_id=latest_exec.id,
            execution_status="ROLLED_BACK",
            completed_at=now,
        )
        RemediationRepository.update_remediation_status(db, rem.id, "ROLLED_BACK")

        return RemediationRollbackResponse(
            execution_id=latest_exec.id,
            remediation_id=rem.id,
            status="ROLLED_BACK",
            restored_files=restored,
            timestamp=now.isoformat(),
        )

    @classmethod
    def list_project_remediations(
        cls,
        db: Session,
        project_id: Optional[str],
        user_id: str,
        skip: int = 0,
        limit: int = 50,
    ) -> RemediationHistoryResponse:
        """Stage 13: List historical remediation records for a project workspace."""
        if project_id:
            proj = ProjectRepository.get_project(db, project_id=project_id, owner_id=user_id)
            if not proj:
                raise HTTPException(status_code=404, detail="Project not found or unauthorized.")

        items = RemediationRepository.list_remediations(
            db=db, project_id=project_id, user_id=user_id, skip=skip, limit=limit
        )
        total = RemediationRepository.count_remediations(db=db, project_id=project_id, user_id=user_id)

        history_items = []
        for r in items:
            latest_exec = RemediationRepository.get_latest_execution(db, r.id)
            history_items.append(
                RemediationHistoryItem(
                    id=r.id,
                    project_id=r.project_id,
                    finding_id=r.finding_id,
                    finding_title=r.finding.title if r.finding else "Vulnerability",
                    finding_category=r.finding.category if r.finding else "unknown",
                    severity=r.finding.severity if r.finding else "MEDIUM",
                    status=r.status,
                    summary=r.summary,
                    patch_count=len(r.patches),
                    latest_retest_status=latest_exec.retest_status if latest_exec else (r.finding.retest_status if r.finding else None),
                    created_at=r.created_at.isoformat(),
                    updated_at=r.updated_at.isoformat(),
                )
            )

        return RemediationHistoryResponse(total=total, items=history_items)

    @classmethod
    def download_patch(cls, db: Session, patch_id: str, user_id: str) -> str:
        """Download raw unified diff patch content for manual review or git apply."""
        patch = RemediationRepository.get_patch(db, patch_id)
        if not patch:
            raise HTTPException(status_code=404, detail=f"Patch '{patch_id}' not found.")
        cls._validate_remediation_ownership(db, patch.remediation_id, user_id)
        return patch.diff_content

    @classmethod
    def _format_patch_response(cls, db: Session, patch: RemediationPatch) -> RemediationPatchResponse:
        """Format database patch model to structured Pydantic response."""
        files: List[RemediationPatchFile] = []
        for f in patch.files_manifest:
            files.append(
                RemediationPatchFile(
                    path=f.get("path", ""),
                    change_type=f.get("change_type", "modify"),
                    reason=f.get("reason", ""),
                    diff=f.get("diff", ""),
                    original_content=f.get("original_content"),
                    patched_content=f.get("patched_content"),
                )
            )

        latest_approval = RemediationRepository.get_latest_approval(db, patch.id)
        approval_status = latest_approval.decision if latest_approval else None

        return RemediationPatchResponse(
            id=patch.id,
            remediation_id=patch.remediation_id,
            patch_version=patch.patch_version,
            summary=patch.summary,
            files=files,
            diff_content=patch.diff_content,
            source_hashes=patch.source_hashes or {},
            validation_status=patch.validation_status,
            validation_errors=patch.validation_errors or [],
            risks=patch.risks or [],
            verification_steps=patch.verification_steps or [],
            created_at=patch.created_at.isoformat(),
            approval_status=approval_status,
        )

