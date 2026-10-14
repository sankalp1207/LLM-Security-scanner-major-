# System Architecture & Technical Specification

## 1. Executive Architecture Overview

The **LLM Security Scanner** is an enterprise-grade automated security auditing and red-teaming platform designed specifically for evaluating, detecting, and mitigating vulnerabilities in applications powered by Large Language Models (LLMs) and Retrieval-Augmented Generation (RAG).

```
+-----------------------------------------------------------------------------------+
|                            STREAMLIT DASHBOARD (UI)                               |
|   - Real-time Telemetry      - Finding Details & Retest    - Audit Report Exports |
+-----------------------------------------+-----------------------------------------+
                                          | HTTP (REST)
+-----------------------------------------v-----------------------------------------+
|                              FASTAPI BACKEND SERVICE                              |
|  /health   /api/v1/detect   /api/v1/scans   /api/v1/findings   /api/v1/demo-rag   |
+-------------------+---------------------+--------------------+--------------------+
                    |                     |                    |
        +-----------v-----------+         |        +-----------v-----------+
        |   SCANNER ORCHESTRATOR|         |        |   RUNTIME GUARDRAILS  |
        |  - TargetClient (SSRF)|         |        |  - Input Validation   |
        |  - TestRunner (Async) |         |        |  - Context Inspection |
        |  - SeverityEngine     |         |        |  - Output Masking     |
        +-----------+-----------+         |        +-----------+-----------+
                    |                     |                    |
        +-----------v-----------+         |        +-----------v-----------+
        |   DETECTOR MODULES    |         |        |   DEMO RAG TARGET     |
        |  - Prompt Injection   |         |        |  - Synthetic Docs     |
        |  - Indirect Injection |         |        |  - TF-IDF Retrieval   |
        |  - Jailbreak Detector |         |        |  - Mock Generator     |
        |  - Data Leakage (Can) |         |        +-----------------------+
        +-----------+-----------+         |
                    |                     |
        +-----------v-----------+         |
        | BASELINE ML CLASSIFIER|         |
        |  - TF-IDF Vectorizer  |         |
        |  - LogisticRegression |         |
        +-----------------------+         |
                                          |
                        +-----------------v-----------------+
                        |       PERSISTENCE LAYER           |
                        |  - SQLAlchemy 2.x Models          |
                        |  - SQLite (Local) / PostgreSQL    |
                        +-----------------------------------+
```

---

## 2. Core Subsystems and Design Decisions

### 2.1 Scanner Engine & Target Client (`app/scanner/`)
* **SSRF and Anti-Exploitation Protections**:
  * Destination validation restricts requests to HTTP/HTTPS only.
  * Direct blocking of link-local cloud metadata IPs (`169.254.169.254`, `metadata.google.internal`).
  * Loopback addresses (`127.0.0.1`, `localhost`) are designated safe for local demonstration.
  * Non-local destinations require explicit, verified user authorization flags (`external_target_authorized=True`).
* **Bounded Concurrency & Fault Tolerance**:
  * Utilizes `asyncio.Semaphore` (configurable 1–10 concurrent requests) to prevent resource exhaustion or Denial of Service against target systems.
  * Individual request timeouts prevent pipeline hangs.
  * Test execution errors are isolated; failures in individual test probes do not abort the overall scan.

### 2.2 Modular Threat Detectors (`app/detectors/`)
* **Prompt Injection Detector**:
  * Dual-layer detection combining compiled regular expression heuristics with the trained baseline ML classifier.
  * Distinguishes between suspicious input and verified exploit execution (e.g. system prompt secret exposure).
* **Indirect Prompt Injection Detector**:
  * Analyzes retrieved context and third-party documents for embedded instructional payloads (`[SYSTEM DIRECTIVE:`, `<!-- INSTRUCTION:`).
  * Evaluates LLM responses to verify whether the injected instructions hijacked the generation output.
* **Jailbreak Detector**:
  * Identifies adversarial framing (persona adoption, hypothetical bypass, opposite twin, unmoderated modes).
  * Analyzes target responses to verify whether safety filters were actually deactivated.
* **Data Leakage & Canary Detector**:
  * Monitors target responses for predefined synthetic canary tokens (`CANARY_SEC_TOKEN_9981`, etc.) and generic credential regex patterns.
  * Automatically masks intermediate characters of leaked credentials in evidence logs to avoid exposing secrets in security reports.

### 2.3 Baseline Machine Learning Pipeline (`app/ml/`)
* **Feature Extraction**: TF-IDF vectorization with unigrams and bigrams, sublinear term frequency scaling, and custom token boundaries capturing security characters (`<>/=[]_-`).
* **Classifier**: Balanced Logistic Regression with L2 regularization.
* **Explainability**: Extracts highest-contributing token weights for each prediction to provide human-interpretable rationale for detection alerts.

### 2.4 Intentionally Vulnerable RAG Demonstration Service (`app/demo_rag/`)
* **Synthetic Corpus**: Complete synthetic document store containing corporate policies, confidential credential records, and poisoned document test cases.
* **Dual Execution Modes**:
  * **Vulnerable Mode**: Simulates naive LLM application without defenses, allowing automated demonstration of prompt injection and credential leaks.
  * **Defensive Mode**: Enforces pre-execution input guardrails, context document filtering, and post-generation canary token redaction.
* **Zero Cost**: Employs a deterministic mock generator for reproducible testing without requiring paid external API subscriptions or dedicated GPU hardware.

### 2.5 Security Reporting & Anti-Injection Protection (`app/reports/`)
* **JSON Audit Export**: Machine-readable full scan report containing execution metadata, finding details, severity distributions, and documented evaluation limitations.
* **Sanitized CSV Export**:
  * Enforces strict defenses against **Spreadsheet Formula Injection (CWE-1236)**.
  * Any field beginning with dangerous formula characters (`=`, `+`, `-`, `@`, `\t`, `\r`) is automatically prefixed with a single quote (`'`), preventing remote code execution via DDE when opened in Microsoft Excel or LibreOffice.

---

## 3. Data Flow Lifecycle

1. **Scan Initiation**: User defines scan target, category filters, concurrency, and timeout via REST API or Streamlit Dashboard.
2. **Validation**: TargetClient validates destination host against SSRF policies and authorization constraints.
3. **Execution**: TestRunner dispatches test probes with bounded concurrency against the target.
4. **Analysis**: Response payloads, status codes, and latency telemetry are routed through the modular detectors.
5. **Severity Scoring**: SeverityEngine assigns objective severity ratings based on observed impact and exploit realization.
6. **Persistence**: Scan records and structured Findings are committed to the relational database.
7. **Reporting & Retesting**: Exportable reports are generated, and individual findings can be retested after applying defensive guardrails to verify remediation.
