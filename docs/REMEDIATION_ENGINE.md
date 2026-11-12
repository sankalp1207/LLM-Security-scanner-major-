# Automated Remediation Assistant: Architecture & Operations Guide

## 1. Executive Summary

The **Automated Remediation Assistant** is an end-to-end vulnerability mitigation and verified retesting system embedded directly into the LLM Security Scanner. It bridges the critical divide between vulnerability detection and confirmed software remediation.

The core principle of the system is:
$$\text{GENERATE FIX} \neq \text{APPLY FIX} \neq \text{VERIFIED FIX}$$

Rather than relying on unverified generative text, the assistant implements a **10-stage persisted workflow** where proposed code modifications are deterministically validated, reviewed via unified diffs, explicitly approved by human operators, applied in a controlled workspace with automatic rollback backups, and confirmed resolved through automated vulnerability retesting.

---

## 2. The 10-Stage Remediation Workflow

```
[ 1. DETECT ]
      │  Vulnerability identified during automated security scan
      ▼
[ 2. ANALYZE VULNERABILITY ]
      │  Retrieve finding telemetry, affected component, and root-cause hypothesis
      ▼
[ 3. GENERATE PROPOSED FIX ]
      │  Synthesize structured code patch tailored to target component
      ▼
[ 4. VALIDATE PROPOSED PATCH ]
      │  Deterministic safety checks: path traversal, file extensions, source hashes
      ▼
[ 5. DISPLAY CODE DIFF ]
      │  Interactive unified diff review (added, removed, modified lines)
      ▼
[ 6. USER APPROVAL ]
      │  Mandatory human-in-the-loop gate (APPROVE / REJECT / REGENERATE)
      ▼
[ 7. APPLY PATCH ]
      │  Atomic file application in controlled workspace with backup creation
      ▼
[ 8. RUN TESTS ]
      │  Execute relevant unit and integration test suites in bounded environment
      ▼
[ 9. RETEST ORIGINAL VULNERABILITY ]
      │  Re-probe target endpoint with original attack fixture and re-evaluate detector
      ▼
[ 10. GENERATE REMEDIATION REPORT ]
         Persist conclusive outcome: FIXED, PARTIALLY_FIXED, or NOT_FIXED
```

Each stage has an explicitly persisted state in the database (`ANALYZING`, `FIX_PROPOSED`, `VALIDATION_FAILED`, `AWAITING_APPROVAL`, `APPROVED`, `REJECTED`, `PATCH_APPLYING`, `PATCH_APPLIED`, `TESTING`, `RETEST_COMPLETED`, `FAILED`, `ROLLED_BACK`). If any step fails, execution halts and unsafe progression is blocked.

---

## 3. Remediation Library & Common LLM Templates

The remediation engine includes a production library (`app/services/remediation_library.py`) mapping common LLM vulnerabilities to defensive software patterns:

| Vulnerability Category | Mitigation Strategy | Target Components |
| :--- | :--- | :--- |
| **Direct Prompt Injection** | Input delimiter fencing (`<user_query>`), instruction hierarchy demarcation, and guardrail pre-filtering | `app/demo_rag/routes.py`, `app/demo_rag/guardrails.py` |
| **Indirect Prompt Injection** | Context sanitization, stripping system override comments from retrieved documents, and metadata isolation | `app/demo_rag/retrieval.py`, `app/demo_rag/guardrails.py` |
| **Sensitive Data Leakage** | Post-generation regex scrubbing, canary token redaction (`[REDACTED_SECRET]`), and output validation | `app/demo_rag/routes.py`, `app/demo_rag/generator.py` |
| **RAG Authorization Failure** | Pre-retrieval tenant filtering, document-level ownership validation | `app/demo_rag/retrieval.py` |
| **Unsafe Tool Invocation** | Tool allowlisting, argument schema enforcement, human-in-the-loop gates | Agent dispatch handlers |
| **Input Validation Failure** | Strict Pydantic schema validation, maximum length clamping, character filtering | API input models |
| **Output Validation Failure** | Structured JSON schema validation, disallowed token filtering | Post-generation filters |

---

## 4. Controlled Workspace Abstraction

All filesystem operations are isolated inside `ControlledWorkspace` (`app/services/remediation_workspace.py`):
1. **Workspace Boundary**: All file accesses are resolved relative to a designated workspace directory (e.g. project root or sandbox). Paths escaping the root are rejected immediately.
2. **Path Traversal Defense**: Rejects `..`, absolute paths (`/`, `C:\`), and symlink escapes.
3. **Sensitive File Protections**: Strictly forbids modifying `.env`, `.git/`, `.pem`, `.key`, or credentials.
4. **Allowed Extensions**: Restricts modifications to text and source files (`.py`, `.json`, `.yaml`, `.yml`, `.md`, `.txt`, `.toml`, `.ini`, `.cfg`).
5. **Atomic Replacement**: Writes patched code to an adjacent temporary file before replacing the target.
6. **Automatic Backups**: Pre-patch contents are recorded in `RemediationExecution.backup_manifest` enabling one-click rollback.

---

## 5. REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/remediations/findings/{id}` | Analyze finding and initiate remediation workflow |
| `GET` | `/api/v1/remediations/{id}` | Get remediation status and latest patch |
| `POST` | `/api/v1/remediations/{id}/generate-fix` | Synthesize (or regenerate) patch for remediation |
| `GET` | `/api/v1/remediations/{id}/patches` | List all patch versions for a remediation |
| `GET` | `/api/v1/remediations/patches/{id}` | Get patch details, file diffs, risks, and validation |
| `POST` | `/api/v1/remediations/patches/{id}/validate` | Validate patch safety, scope, and source file drift |
| `POST` | `/api/v1/remediations/patches/{id}/approve` | Record human approval (`APPROVED`) |
| `POST` | `/api/v1/remediations/patches/{id}/reject` | Record human rejection (`REJECTED`) |
| `POST` | `/api/v1/remediations/patches/{id}/apply` | Apply approved patch in controlled workspace |
| `POST` | `/api/v1/remediations/{id}/verify` | Run unit tests and retest vulnerability against target |
| `POST` | `/api/v1/remediations/{id}/rollback` | Revert applied patch to pre-patch state from backup |
| `GET` | `/api/v1/remediations/projects/{id}/history`| List historical remediation records for a project |
| `GET` | `/api/v1/remediations/patches/{id}/download`| Download unified `.patch` file |

