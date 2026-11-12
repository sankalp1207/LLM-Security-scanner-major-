"""Deterministic Patch Validation Engine enforcing syntax, safety, scope, and stale file checks."""

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.schemas.remediation import PatchValidationResponse
from app.services.remediation_workspace import ControlledWorkspace, WorkspaceSecurityError


class PatchValidator:
    """Validates proposed code patches against safety rules, scope constraints, and source file drift."""

    @classmethod
    def validate_patch_structure(cls, patch_dict: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate that raw patch dictionary conforms to mandatory schema rules."""
        errors: List[str] = []

        files = patch_dict.get("files")
        if not files or not isinstance(files, list):
            errors.append("Patch must contain a non-empty 'files' list.")
            return False, errors

        for idx, item in enumerate(files):
            if not isinstance(item, dict):
                errors.append(f"File item #{idx} must be an object.")
                continue

            rel_path = item.get("path")
            if not rel_path or not isinstance(rel_path, str) or not rel_path.strip():
                errors.append(f"File item #{idx} missing valid 'path'.")

            patched_content = item.get("patched_content")
            if patched_content is None or not isinstance(patched_content, str):
                errors.append(f"File item #{idx} missing valid 'patched_content'.")

            diff = item.get("diff")
            if diff is None or not isinstance(diff, str):
                errors.append(f"File item #{idx} missing valid 'diff'.")

        return len(errors) == 0, errors

    @classmethod
    def validate_patch_safety_and_scope(
        cls,
        patch_id: str,
        files_manifest: List[Dict[str, Any]],
        source_hashes: Dict[str, str],
        workspace_root: Optional[Path] = None,
    ) -> PatchValidationResponse:
        """
        Comprehensive multi-stage validation:
        1. Path safety and workspace containment (no traversal, no absolute paths).
        2. Extension and sensitive pattern restrictions (.env, .git, etc.).
        3. File size limits.
        4. Stale file detection: verifies that files on disk still match source_hashes.
        """
        errors: List[str] = []
        warnings: List[str] = []
        checked_files: List[str] = []

        if not files_manifest:
            errors.append("No files declared in patch manifest.")
            return PatchValidationResponse(
                patch_id=patch_id,
                is_valid=False,
                errors=errors,
                warnings=warnings,
                checked_files=checked_files,
            )

        for item in files_manifest:
            rel_path = item.get("path", "")
            checked_files.append(rel_path)

            # 1. Workspace containment and disallowed path checks
            try:
                target_path = ControlledWorkspace.resolve_safe_path(rel_path, workspace_root)
            except WorkspaceSecurityError as e:
                errors.append(f"Path safety violation in '{rel_path}': {str(e)}")
                continue

            # 2. File size limit
            patched_content = item.get("patched_content", "")
            if len(patched_content.encode("utf-8")) > ControlledWorkspace.MAX_FILE_SIZE_BYTES:
                errors.append(f"Patched content for '{rel_path}' exceeds maximum 1MB size limit.")

            # 3. Stale file detection / drift check
            expected_hash = source_hashes.get(rel_path)
            if target_path.is_file():
                current_hash = ControlledWorkspace.compute_sha256(target_path)
                if expected_hash and current_hash != expected_hash:
                    errors.append(
                        f"Stale patch detected for '{rel_path}': source file has been modified on disk "
                        f"since this patch was generated (expected hash: {expected_hash[:8]}..., current: {current_hash[:8]}...)."
                    )
            elif expected_hash:
                # File was expected to exist according to source hash, but is now missing
                errors.append(f"Source file '{rel_path}' was deleted or moved since patch generation.")

            # 4. Warnings for high impact changes
            if "database" in rel_path.lower() or "auth" in rel_path.lower():
                warnings.append(f"High-impact security component '{rel_path}' is targeted by this patch.")

        is_valid = len(errors) == 0
        return PatchValidationResponse(
            patch_id=patch_id,
            is_valid=is_valid,
            errors=errors,
            warnings=warnings,
            checked_files=checked_files,
        )

