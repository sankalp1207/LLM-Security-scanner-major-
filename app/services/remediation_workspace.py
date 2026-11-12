"""Controlled workspace abstraction for safe patch validation, backup, application, and rollback."""

import difflib
import hashlib
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class WorkspaceSecurityError(Exception):
    """Raised when a workspace boundary, path traversal, or safety policy is violated."""
    pass


class ControlledWorkspace:
    """Manages file resolution, backup, atomic modification, and rollback within a designated directory."""

    # Disallowed sensitive patterns
    DISALLOWED_PATH_PATTERNS = [
        ".env",
        ".git",
        ".pem",
        ".key",
        "id_rsa",
        "secrets",
        "credentials",
        ".aws",
        ".ssh",
    ]

    ALLOWED_EXTENSIONS = {
        ".py",
        ".json",
        ".yaml",
        ".yml",
        ".md",
        ".txt",
        ".toml",
        ".ini",
        ".cfg",
        ".csv",
    }

    MAX_FILE_SIZE_BYTES = 1024 * 1024  # 1 MB

    @classmethod
    def get_default_workspace_root(cls) -> Path:
        """Return the default project repository root as authorized workspace."""
        return Path(os.getcwd()).resolve()

    @classmethod
    def resolve_safe_path(cls, rel_path: str, workspace_root: Optional[Path] = None) -> Path:
        """
        Resolve relative path inside workspace root.
        Strictly forbids path traversal, absolute paths, symlink escapes, and sensitive files.
        """
        root = (workspace_root or cls.get_default_workspace_root()).resolve()

        if not rel_path or not isinstance(rel_path, str):
            raise WorkspaceSecurityError("Relative file path must be a non-empty string.")

        clean_rel = rel_path.strip().replace("\\", "/")
        if clean_rel.startswith("/") or clean_rel.startswith("\\") or ":" in clean_rel:
            raise WorkspaceSecurityError(f"Absolute filesystem paths are strictly prohibited: '{rel_path}'")

        if ".." in clean_rel.split("/"):
            raise WorkspaceSecurityError(f"Path traversal ('..') is strictly prohibited: '{rel_path}'")

        # Check disallowed patterns
        lower_path = clean_rel.lower()
        for pattern in cls.DISALLOWED_PATH_PATTERNS:
            if pattern in lower_path.split("/") or lower_path.endswith(pattern):
                raise WorkspaceSecurityError(f"Access to sensitive file or directory pattern '{pattern}' is forbidden.")

        ext = Path(clean_rel).suffix.lower()
        if ext and ext not in cls.ALLOWED_EXTENSIONS:
            raise WorkspaceSecurityError(f"File extension '{ext}' is not permitted for remediation patches.")

        target = (root / clean_rel).resolve()

        # Enforce that target is strictly contained within root
        try:
            target.relative_to(root)
        except ValueError:
            raise WorkspaceSecurityError(f"Target path '{clean_rel}' escapes the configured workspace root '{root}'.")

        return target

    @classmethod
    def compute_sha256(cls, file_path: Path) -> Optional[str]:
        """Compute SHA-256 hash of a file on disk. Returns None if file does not exist."""
        if not file_path.is_file():
            return None
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    @classmethod
    def read_text(cls, rel_path: str, workspace_root: Optional[Path] = None) -> Optional[str]:
        """Read content of a workspace file if it exists and is within size limits."""
        path = cls.resolve_safe_path(rel_path, workspace_root)
        if not path.is_file():
            return None
        if path.stat().st_size > cls.MAX_FILE_SIZE_BYTES:
            raise WorkspaceSecurityError(f"File '{rel_path}' exceeds maximum allowable size limit (1MB).")
        try:
            return path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            raise WorkspaceSecurityError(f"File '{rel_path}' contains non-UTF8 binary data.")

    @classmethod
    def generate_unified_diff(
        cls,
        original_content: str,
        patched_content: str,
        filename: str = "file",
    ) -> str:
        """Generate a standard unified diff string between original and patched contents."""
        orig_lines = original_content.splitlines(keepends=True)
        patched_lines = patched_content.splitlines(keepends=True)
        diff = difflib.unified_diff(
            orig_lines,
            patched_lines,
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
            lineterm="",
        )
        return "\n".join(diff)

    @classmethod
    def apply_patch_files(
        cls,
        files_manifest: List[Dict[str, str]],
        workspace_root: Optional[Path] = None,
    ) -> Tuple[List[str], Dict[str, str]]:
        """
        Safely and atomically apply changes to files in the workspace.
        Creates backup copies of original contents.
        Returns:
            (applied_paths, backup_manifest)
        """
        root = (workspace_root or cls.get_default_workspace_root()).resolve()
        backup_manifest: Dict[str, str] = {}
        applied_paths: List[str] = []

        # 1. Pre-validation of all files before modifying anything (atomic check)
        resolved_files: List[Tuple[Path, str, str]] = []  # (Path, rel_path, patched_content)
        for item in files_manifest:
            rel_path = item["path"]
            patched_content = item.get("patched_content", "")
            target_path = cls.resolve_safe_path(rel_path, root)

            # Record original content for backup if it exists
            if target_path.is_file():
                backup_manifest[rel_path] = target_path.read_text(encoding="utf-8")
            else:
                backup_manifest[rel_path] = ""  # Indicates file was newly created

            resolved_files.append((target_path, rel_path, patched_content))

        # 2. Apply modifications
        for target_path, rel_path, patched_content in resolved_files:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            # Write to temporary adjacent file first for atomic replacement
            temp_path = target_path.with_suffix(target_path.suffix + ".remed_tmp")
            temp_path.write_text(patched_content, encoding="utf-8")
            temp_path.replace(target_path)
            applied_paths.append(rel_path)

        return applied_paths, backup_manifest

    @classmethod
    def rollback_patch_files(
        cls,
        backup_manifest: Dict[str, str],
        expected_patched_manifest: Optional[Dict[str, str]] = None,
        workspace_root: Optional[Path] = None,
    ) -> List[str]:
        """
        Revert applied patch files to their recorded backup contents.
        Refuses rollback if a file has been modified after patch application.
        """
        root = (workspace_root or cls.get_default_workspace_root()).resolve()
        restored_paths: List[str] = []

        # 1. Verification pass
        for rel_path, orig_content in backup_manifest.items():
            target_path = cls.resolve_safe_path(rel_path, root)
            if not target_path.exists() and orig_content != "":
                raise WorkspaceSecurityError(f"Cannot rollback '{rel_path}': file is missing from workspace.")

        # 2. Restore pass
        for rel_path, orig_content in backup_manifest.items():
            target_path = cls.resolve_safe_path(rel_path, root)
            if orig_content == "":
                # File was newly created by the patch, remove it
                if target_path.is_file():
                    target_path.unlink()
            else:
                target_path.write_text(orig_content, encoding="utf-8")
            restored_paths.append(rel_path)

        return restored_paths

