# Patch Security & Defensive Execution Architecture

## 1. Security Philosophy

Automating source code modifications introduces critical operational and cybersecurity risks:
- Malicious or hallucinated code could compromise system availability.
- Path traversal could overwrite host configuration files.
- Unauthorized callers could tamper with production code.
- Applying patches to files that changed concurrently could create broken merge states.

To eliminate these risks, the LLM Security Scanner enforces a zero-trust patch execution architecture.

---

## 2. Security Invariants & Defenses

### A. Mandatory Human Approval Gate
- **Invariant**: No patch can be applied without explicit approval recorded in `RemediationApproval`.
- **Enforcement**:
  ```python
  latest_approval = RemediationRepository.get_latest_approval(db, patch.id)
  if not latest_approval or latest_approval.decision != "APPROVED":
      raise HTTPException(status_code=400, detail="Security Gate: Patch has not been approved by a human operator.")
  ```
- Any unapproved call to `/apply` fails with HTTP 400.

### B. Path Traversal & Symlink Escape Defense
- **Invariant**: Filesystem modifications cannot escape the configured workspace root.
- **Enforcement**:
  1. Checks that relative paths do not begin with `/`, `\`, or drive letters (`C:`).
  2. Rejects path components containing `..`.
  3. Resolves the canonical target path and verifies `target.relative_to(workspace_root)`.

### C. Sensitive File Protection
- **Invariant**: Environment variables, private keys, certificates, and source control metadata cannot be touched.
- **Blacklisted Patterns**: `.env`, `.git`, `.pem`, `.key`, `id_rsa`, `secrets`, `credentials`, `.aws`, `.ssh`.

### D. File Extension Allowlist
- **Allowed Extensions**: `.py`, `.json`, `.yaml`, `.yml`, `.md`, `.txt`, `.toml`, `.ini`, `.cfg`, `.csv`.
- Disallows `.exe`, `.dll`, `.sh`, `.bat`, or arbitrary binary file types.

### E. Source File Drift & Stale Patch Detection
- **Invariant**: A patch must not be applied if target files have changed on disk since patch generation.
- **Mechanism**:
  1. At fix generation, the SHA-256 hash of each target file is recorded in `patch.source_hashes`.
  2. Prior to application, the validator re-computes the disk SHA-256 hash.
  3. If `current_hash != expected_hash`, validation fails with:
     *"Stale patch detected: source file has been modified on disk since this patch was generated."*
  4. Application is aborted, requiring human review and patch regeneration.

### F. Zero Shell Execution
- The remediation engine does not execute shell commands (`os.system`, `subprocess.call` with untrusted shell strings).
- Modifications are made exclusively via Python string operations and atomic file replacement.

### G. Rollback Verification & State Integrity
- Before applying changes, full file contents are recorded in `RemediationExecution.backup_manifest`.
- Rollback verifies that the current file matches the expected post-patch state, preventing the accidental destruction of subsequent edits.

---

## 3. Threat Model Matrix

| Threat | Impact | Mitigation in Remediation Engine |
| :--- | :--- | :--- |
| **Directory Traversal** | Overwrite system binaries / configs | `ControlledWorkspace.resolve_safe_path` rejects traversal (`..`) and outside paths. |
| **Accidental Secret Overwrite** | Delete or leak `.env` / credentials | Explicit blacklist blocks `.env`, `.git`, `.key`, `.pem`. |
| **Concurrent Edit Race (Drift)** | Corrupt source code with stale diff | SHA-256 hash comparison between generation time and application time. |
| **Hallucinated Ineffective Fix** | False sense of security | Verification stage retests vulnerability against target; marked FIXED only if retest passes. |
| **Malicious API Trigger** | Unauthorized code modification | Multi-tenant authorization (`user_id` and `owner_id`) checks on all endpoints. |

