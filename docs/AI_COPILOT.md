# AI Security Copilot: Architecture & Usage Guide

## 1. Executive Overview

The **AI Security Copilot** is a context-aware, evidence-grounded cybersecurity assistant embedded directly into the LLM Security Scanner. It bridges the gap between raw vulnerability scan telemetry and actionable software remediation. 

Rather than acting as a generic open-ended chatbot, the Copilot functions as an intelligent cybersecurity analyst that inspects real scan results, correlates multi-stage attack paths, explains vulnerabilities using a structured 6-part schema, compares historical scans for security regressions, and provides verified code mitigations with reproducible retesting instructions.

---

## 2. Key Capabilities & Functional Highlights

1. **Context-Aware Investigation**: Directly queries scans, test executions, findings, and project configurations through 11 deterministic, read-only inspection tools.
2. **Standardized 6-Part Finding Analysis**:
   - **Executive Summary**: Clear, high-level risk overview for developers and managers.
   - **Observed Evidence**: Exact target component, detection methodology, and matched indicator payload.
   - **Why It Matters**: Production impact analysis (data exfiltration, safety alignment bypass, privilege escalation).
   - **Root-Cause Analysis**: Fundamental vulnerability mechanism (instruction hierarchy collapse, unvalidated delimiters, missing output encoding).
   - **Actionable Remediation**: Concrete code snippets and guardrail implementations.
   - **Retesting Guidance**: Step-by-step verification instructions to confirm mitigation efficacy.
3. **Historical Scan Comparison & Regression Analysis**: Computes differential metrics between two scans (new findings, resolved findings, persistent issues, and severity shifts).
4. **Attack-Path Correlation**: Maps related findings into multi-stage attack chains (e.g. Indirect Injection $\rightarrow$ Context Smuggling $\rightarrow$ Data Leakage $\rightarrow$ Privilege Escalation).
5. **Zero-Cost Offline Operation**: Features an intelligent `DeterministicMockProvider` enabling 100% test coverage and local development with $0 API overhead.
6. **Live Provider Extensibility**: Supports external OpenAI-compatible endpoints (OpenAI, Ollama, vLLM, LocalAI) configured via environment variables.

---

## 3. Architecture & System Design

```
+-----------------------------------------------------------------------------------+
|                           STREAMLIT DASHBOARD UI                                  |
|   +--------------------------+  +------------------------+  +-----------------+   |
|   | 💬 Copilot Assistant     |  | 📊 ML Model Performance|  | ⚡ Threat Matrix |   |
|   +--------------------------+  +------------------------+  +-----------------+   |
+----------------------------------------+------------------------------------------+
                                         | REST API (HTTP + JSON)
                                         v
+-----------------------------------------------------------------------------------+
|                               FASTAPI BACKEND                                     |
|   app/api/copilot.py          -> Route Handlers & Authorization Filters           |
|   app/services/copilot_service.py -> Orchestrator & Multi-Turn State Manager      |
|   app/services/copilot_tools.py   -> 11 Deterministic Security Inspection Tools   |
|   app/services/copilot_knowledge.py -> Curated RAG Security Knowledge Base       |
|   app/services/copilot_llm.py     -> Deterministic Mock & OpenAI Compatible Engine|
+----------------------------------------+------------------------------------------+
                                         | SQLAlchemy ORM
                                         v
+-----------------------------------------------------------------------------------+
|                             SQLITE / POSTGRESQL DB                                |
|   copilot_conversations: [id, user_id, project_id, title, created_at, updated_at] |
|   copilot_messages:      [id, conversation_id, role, content, evidence, timestamp]|
|   projects, scans, findings, test_executions, scan_events                         |
+-----------------------------------------------------------------------------------+
```

---

## 4. Deterministic Context Tools

The Copilot interacts with the scanner database exclusively through 11 strongly-typed, read-only tools defined in `app/services/copilot_tools.py`:

| Tool Function | Description | Access Boundaries |
| :--- | :--- | :--- |
| `get_project_summary` | Fetches project metadata, target config, and scan statistics | Owner-scoped (`project.owner_id == user_id`) |
| `get_latest_scan` | Retrieves the most recent scan record and telemetry summary | Owner-scoped |
| `get_scan_history` | Lists historical scans for a project | Owner-scoped |
| `get_scan_details` | Inspects scan configuration snapshot and severity distribution | Owner-scoped (`scan.user_id` / `owner_id`) |
| `get_scan_findings` | Lists confirmed vulnerability findings with filters | Owner-scoped |
| `get_finding_details` | Retrieves deep evidence payload, confidence score, and remediation | Owner-scoped |
| `get_test_execution_details` | Inspects observed input/output payloads and latency for individual tests | Owner-scoped |
| `compare_scans` | Computes differential findings and regression summary between two scans | Owner-scoped (both scans) |
| `get_mitigation_history` | Retrieves remediation guidance and retest status for a finding | Owner-scoped |
| `get_attack_path` | Correlates findings into sequential multi-stage attack chains | Owner-scoped |
| `get_ml_evaluation` | Retrieves offline classifier accuracy, precision, recall, and ROC-AUC metrics | Global read-only model metrics |

---

## 5. Security Knowledge Base (RAG)

The knowledge base (`app/services/copilot_knowledge.py`) contains curated enterprise security documentation covering:
- **OWASP LLM Top 10** (LLM01: Prompt Injection, LLM03: Training Data Poisoning, LLM06: Sensitive Information Disclosure, LLM08: Excessive Agency).
- **Jailbreak Defense Techniques** (Persona override mitigation, instruction hierarchy demarcation).
- **Canary Token Generation & Detection** (Synthesized entropy tokens, response filtering).
- **Delimiter Fencing & Input Normalization** (XML/Markdown structural isolation).

All retrieved knowledge is strictly isolated using `<security_knowledge_document>` boundary tags to prevent indirect prompt injection.

---

## 6. Configuration & Environment Variables

The Copilot can run in two modes controlled by environment variables:

```bash
# 1. Deterministic Mock Engine (Default: $0 cost, offline, 100% reproducible)
COPILOT_LLM_PROVIDER=deterministic_mock

# 2. OpenAI-Compatible Live Engine (OpenAI, Ollama, vLLM, LocalAI)
COPILOT_LLM_PROVIDER=openai_compatible
COPILOT_LLM_API_KEY=sk-your-api-key-here
COPILOT_LLM_BASE_URL=https://api.openai.com/v1
COPILOT_LLM_MODEL=gpt-4o-mini
COPILOT_LLM_TEMPERATURE=0.2
COPILOT_LLM_MAX_TOKENS=1500
```

---

## 7. REST API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/copilot/conversations` | Create a new conversational session bound to an optional project |
| `GET` | `/api/v1/copilot/conversations` | List conversation sessions owned by the authenticated tenant |
| `GET` | `/api/v1/copilot/conversations/{id}` | Retrieve conversation session metadata |
| `DELETE` | `/api/v1/copilot/conversations/{id}` | Delete conversation session and historical messages |
| `POST` | `/api/v1/copilot/conversations/{id}/messages` | Send message, run context tools, and receive AI advisory |
| `GET` | `/api/v1/copilot/conversations/{id}/messages` | Retrieve chronological message history |
| `POST` | `/api/v1/copilot/explain-finding/{finding_id}` | Generate structured 6-part finding explanation |
| `POST` | `/api/v1/copilot/compare-scans` | Compute differential security comparison between two scans |

