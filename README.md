# LLM Security Scanner
### An Automated Vulnerability Detection and Security Testing Platform for Large Language Model Applications

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/release/python-3120/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.38+-FF4B4B.svg)](https://streamlit.io)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

An end-to-end, reproducible security auditing and automated red-teaming platform designed for evaluating, detecting, and defending Large Language Model (LLM) powered systems against adversarial manipulation, data leakage, and system vulnerabilities.

---

## 🎯 Key Capabilities

* **Prompt Injection Detection**: Hybrid rule-based heuristic and Machine Learning threat classification (TF-IDF + Logistic Regression) distinguishing suspicious inputs from safe commands.
* **Indirect Prompt Injection Detection**: Inspection of untrusted retrieved documents in RAG pipelines to prevent hidden instruction hijacking.
* **Jailbreak Analysis**: Detection of policy bypasses, role-playing exploits, and adversarial instruction patterns.
* **Sensitive Information Disclosure (Canary & Secrets)**: Automated detection of synthetic credentials, API keys, canary tokens, and private data in LLM outputs.
* **Adversarial Attack Mutation & Fuzzing**: Automated evasion payload generator mutating test probes via Base64, Leetspeak, Cyrillic homoglyphs, ROT13, and XML/Markdown delimiter framing.
* **Input De-obfuscation Normalizer**: Defense-in-depth pipeline unmasking encoded and obfuscated prompts before threat classification and guardrail enforcement.
* **Automated Red-Team Scanner**: Structured, rate-limited, non-destructive security test runner executing against authorized LLM endpoints.
* **Runtime Guardrails**: Defensive pre-execution and post-generation filtering policies demonstrating attack mitigation.
* **Premium AI Cybersecurity SaaS Platform (Phase 1 UI/UX)**: Enterprise-grade dark charcoal operations console featuring dynamic Security Posture Scoring, Vulnerability Trends analytics, interactive multi-stage Attack Graph, and expandable finding exploration with 1-click mitigation retesting.
* **Comprehensive Reporting**: Multi-format reporting (JSON, CSV with spreadsheet formula injection protection).

---

## 🏗️ Architecture

```
llm-security-scanner/
├── app/
│   ├── api/            # FastAPI route handlers (Health, Scans, Detection, Reports)
│   ├── config.py       # Pydantic Settings configuration
│   ├── database/       # SQLAlchemy models, sessions, and repositories
│   ├── demo_rag/       # Synthetic vulnerable and defended RAG demonstration app
│   ├── detectors/      # Modular security analyzers (Direct, Indirect, Jailbreak, Secrets)
│   ├── ml/             # ML pipeline (Dataset, Training, Evaluation, Inference)
│   ├── reports/        # Report generation (JSON, sanitized CSV)
│   ├── scanner/        # Automated test orchestrator, runner, and target client
│   ├── schemas/        # Pydantic request/response schemas
│   └── services/       # Core business logic layer
├── dashboard/          # Streamlit security operations dashboard
├── datasets/           # Synthetic adversarial and benign test datasets
├── models/             # Trained serialized machine learning models
├── tests/              # Pytest suite (Unit, Integration, Evaluation)
├── docs/               # System documentation, Threat Model, API specification
└── scripts/            # Training, evaluation, and database seeding utilities
```

---

## 🚀 Quick Start

### 1. Prerequisites
* Python 3.12
* Git

### 2. Environment Setup
```bash
# Clone the repository
git clone https://github.com/sankalp1207/LLM-Security-scanner-major-.git
cd LLM-Security-scanner-major-

# Create virtual environment
python -m venv .venv
# On Windows:
.\.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements-dev.txt
```

### 3. Configuration
Copy the sample environment file:
```bash
cp .env.example .env
```

### 4. Run the Backend API
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
Interactive API documentation will be available at:
* Swagger UI: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
* Health Check: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

### 5. Run the Security Dashboard
```bash
streamlit run dashboard/app.py
```

### 6. Run Test Suite
```bash
pytest
```

---

## 🔒 Security Principles
* **Synthetic Data Only**: All test secrets, canary tokens, and corporate documents are 100% fictional. Real credentials are never stored, transmitted, or evaluated.
* **Controlled Scope**: Scanning is restricted to local demonstration applications and explicitly authorized targets. Unrestricted internet scanning and destructive testing are prohibited.
* **Zero Cost**: Requires no paid external API keys or heavy GPU hardware to run the complete demonstration and evaluation pipeline.

---

## 📜 Academic Project
Developed as a B.Tech Major Project in Computer Science and Engineering / AI & Cybersecurity.
