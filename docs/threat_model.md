# Threat Model & Risk Analysis

## 1. Overview & Framework

This threat model evaluates LLM-powered applications against the **OWASP Top 10 for Large Language Model Applications (2025/2026)** and analyzes the security boundaries of the **LLM Security Scanner** platform itself.

---

## 2. OWASP Top 10 for LLMs Threat Matrix

| Threat ID | Threat Category | Description | Scanner Evaluation Mechanism | Defensive Guardrail Mitigation |
| :--- | :--- | :--- | :--- | :--- |
| **LLM01** | **Direct Prompt Injection** | Adversarial user input overriding system instructions or delimiters to alter model behavior. | `PromptInjectionDetector`: Evaluates input against heuristic regexes and ML classification; checks response for leaked system secrets. | `GuardrailPolicy`: Input validation regexes and strict system prompt delimiters. |
| **LLM01** | **Indirect Prompt Injection** | Adversarial directives embedded in untrusted external content (e.g. retrieved RAG documents). | `IndirectInjectionDetector`: Inspects context documents for hidden directives (`[SYSTEM:]`, `<!-- INSTRUCTION:`); verifies payload execution. | Context inspection guardrail: Strips or blocks untrusted documents containing instructions. |
| **LLM02** | **Insecure Output Handling** | Downstream components blindly executing LLM-generated outputs without sanitization. | Automated tests evaluating output formats (JSON, markdown, scripts) for dangerous execution strings. | Output validation and encoding before downstream processing. |
| **LLM04** | **Model Denial of Service** | Resource exhaustion attacks via excessively large prompts or computationally expensive recursive queries. | Scanner enforces maximum payload limits and bounded concurrency during audit jobs. | Input length limits (`MAX_INPUT_LENGTH=4096`) and request rate limiters. |
| **LLM06** | **Sensitive Information Disclosure** | Unauthorized disclosure of confidential data, API keys, credentials, or personal information in responses. | `DataLeakageDetector`: Exact matching for synthetic canary tokens (`CANARY_SEC_TOKEN_9981`, etc.) and generic credential regexes. | Output guardrail: Automated canary token scanning and credential redaction (`[REDACTED_...]`). |

---

## 3. Platform Self-Security Engineering

Because the scanner is an automated security product interacting with untrusted targets, the scanner itself enforces rigorous security boundaries:

### 3.1 Server-Side Request Forgery (SSRF) Defense
* **Cloud Metadata Blacklisting**: Rejects any request targeting link-local cloud metadata IP addresses (`169.254.169.254`, `metadata.google.internal`), preventing attackers from exploiting the scanner to extract cloud IAM roles.
* **Protocol Whitelisting**: Restricts request schemes exclusively to `http://` and `https://`. Legacy or dangerous protocols (`file://`, `ftp://`, `gopher://`) are rejected at the parsing boundary.
* **Explicit Authorization Controls**: Scanning non-loopback endpoints strictly requires an explicit affirmative flag (`external_target_authorized=True`).

### 3.2 Spreadsheet Formula Injection Defense (CWE-1236)
* **Risk**: If an adversary forces an LLM to generate an attack string such as `=cmd|' /C calc'!A0` and this finding is exported to a CSV report, opening the spreadsheet in Microsoft Excel could trigger Dynamic Data Exchange (DDE) command execution.
* **Defense**: `sanitize_csv_cell` inspects all cell values during CSV generation. If any string begins with dangerous prefix characters (`=`, `+`, `-`, `@`, `\t`, `\r`), it is prepended with a single quote (`'`), neutralizing formula execution.

### 3.3 Evidence Sanitization and Secret Protection
* **Risk**: Generating audit reports that contain raw leaked credentials or canary tokens risks perpetuating sensitive data exposure.
* **Defense**: `DataLeakageDetector.redact_token` masks the middle characters of sensitive secrets (e.g. `CANARY_SEC_...9981`) before committing evidence payloads to the database or serializing reports.

### 3.4 Bounded Concurrency and Resource Throttling
* Target requests are executed under an `asyncio.Semaphore` with hard caps (maximum 10 concurrent requests) to avoid overwhelming target services or causing inadvertent operational denial-of-service.
