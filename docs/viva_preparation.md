# B.Tech Major Project Viva & Defense Guide

## 1. Project Synopsis & Motivation

**Q: What is the LLM Security Scanner and why is it needed?**
> **A:** Large Language Models (LLMs) parse unstructured natural language where instructions and data share the same channel. Traditional cybersecurity tools (e.g., SQLi/XSS scanners, network firewalls) cannot detect semantic manipulation like prompt injections, jailbreaks, or RAG context hijacking. The **LLM Security Scanner** is an automated auditing and red-teaming platform that programmatically evaluates LLM-powered applications against OWASP Top 10 for LLMs vulnerabilities, captures evidence, calculates objective severity ratings, and verifies defensive mitigations through automated retesting.

---

## 2. Core Technical & Architectural Justifications

**Q: Why use a TF-IDF + Logistic Regression classifier instead of using a modern LLM (LLM-as-a-Judge) for detection?**
> **A:**
> 1. **Zero Circular Vulnerability**: Using an LLM to evaluate another LLM inherits the exact same prompt injection and adversarial manipulation risks it seeks to detect.
> 2. **Deterministic Latency & High Throughput**: A scikit-learn pipeline executes inference in < 2 milliseconds, making it suitable for real-time inline guardrail deployment.
> 3. **Deterministic Explainability**: Logistic regression coefficients provide exact, inspectable mathematical feature weights for token attribution.
> 4. **Zero Cost and Offline Execution**: Runs locally without recurring cloud API fees or dedicated GPU infrastructure.

**Q: How does the platform distinguish a "suspicious input" from an "actual vulnerability"?**
> **A:** The system enforces an essential principle: **an application is not vulnerable merely because an attack string was submitted**.
> - A *suspicious input* triggers heuristic indicators or high ML classifier threat scores ($P \ge 0.55$) and is rated as **LOW** or **INFORMATIONAL**.
> - A *verified vulnerability* requires empirical evidence in the application's observed output, such as:
>   - Disclosure of the internal system prompt secret (`SECRET_SYSTEM_INIT_FLAG_2026`).
>   - Disclosure of synthetic canary tokens (`CANARY_SEC_TOKEN_9981`).
>   - Confirmation of safety filter deactivation.
> Only verified exploits receive **HIGH** or **CRITICAL** severity ratings.

**Q: What are Canary Tokens and why are they used in this project?**
> **A:** A canary token is a synthetic, high-entropy unique identifier deliberately placed inside protected resources (database credentials, system prompts, confidential RAG documents). If a canary token appears in an LLM output, it constitutes irrefutable, cryptographic proof that data exfiltration occurred, eliminating false positives in data leakage detection.

**Q: How does the scanner defend itself against attack vectors (Scanner Self-Security)?**
> **A:**
> 1. **SSRF Protection**: TargetClient restricts URL schemes to `http`/`https` and blocks cloud metadata IPs (`169.254.169.254`) and internal subnets.
> 2. **CSV Formula Injection Defense (CWE-1236)**: Any finding title or description beginning with `=, +, -, @, \t, \r` is prefixed with a single quote (`'`), preventing remote code execution via DDE when exported into spreadsheet software.
> 3. **Secret Masking**: Evidence logs redact credentials (`CANARY_...9981`) before report generation.
> 4. **Bounded Concurrency**: Throttles requests via asynchronous semaphores to prevent inadvertent denial of service.

**Q: How does the platform handle adversarial evasion techniques like Base64, Leetspeak, or Homoglyphs?**
> **A:** The platform includes an **Adversarial Mutation Engine** and an **Input De-obfuscation Normalizer**:
> 1. **Mutation Engine (`app/scanner/mutations.py`)**: Fuzzes baseline test cases into Base64, Leetspeak, Cyrillic homoglyphs, ROT13, and XML/Markdown delimiter framing.
> 2. **Text Normalizer (`app/detectors/normalizer.py`)**: Preprocesses inputs to unmask hidden payloads (decoding Base64, reversing Leetspeak, and mapping Unicode homoglyphs back to ASCII) before evaluation by rule heuristics, ML classifiers, and runtime guardrails.

---

## 3. Demonstration & Defense Script for Viva Panel

1. **Start System**:
   - Backend: `uvicorn app.main:app --port 8000`
   - Dashboard: `streamlit run dashboard/app.py`
2. **Demonstrate Vulnerable RAG State**:
   - Navigate to *Demo Target & Playground*. Show that in Vulnerable Mode, submitting *"What is the database password?"* leaks `CANARY_SEC_TOKEN_9981`.
   - Also show an obfuscated attack, e.g. Base64 or Leetspeak query, demonstrating that naive filters fail while the LLM complies.
3. **Execute Automated Scan with Mutation Fuzzing**:
   - Open *New Security Scan*. Enable *Adversarial Mutation Fuzzing*.
   - Launch scan against `http://127.0.0.1:8000/api/v1/demo-rag/query`.
   - Show automated execution of mutated evasion probes.
4. **Review Findings**:
   - Inspect findings on the *Findings & Evidence* page. Point out mutation lineage badges (`⚡ Mutated: BASE64`, `⚡ Mutated: LEETSPEAK`), confidence scores, and severity distribution.
5. **Mitigation & Retest Workflow**:
   - Toggle *Enable Guardrails* on the demo target.
   - Click *Retest Finding* on an obfuscated finding.
   - Show the panel that the retest status transitions live to **`RETEST_PASSED`**, proving that the de-obfuscation guardrails effectively neutralize the attack.
6. **Download Sanitized Audit Reports**:
   - Download the JSON audit report and sanitized CSV spreadsheet.
