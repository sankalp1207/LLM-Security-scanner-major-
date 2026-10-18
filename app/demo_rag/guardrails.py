"""Runtime security guardrails protecting input, retrieved context, and generated output."""

import re
from typing import List, Tuple

from app.demo_rag.documents import SYNTHETIC_CANARIES, Document


class GuardrailPolicy:
    """Configurable defensive policies for LLM RAG pipelines."""

    MAX_INPUT_LENGTH: int = 4096

    # Suspicious prompt injection and instruction override patterns
    INJECTION_PATTERNS = [
        re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?", re.IGNORECASE),
        re.compile(r"disregard\s+(?:all\s+)?(?:prior|previous|initial)\s+(?:rules|directives|guidelines)", re.IGNORECASE),
        re.compile(r"forget\s+(?:your\s+)?(?:rules|instructions|safety)", re.IGNORECASE),
        re.compile(r"system\s+prompt\s+verbatim", re.IGNORECASE),
        re.compile(r"you\s+are\s+now\s+(?:in\s+debug\s+mode|unrestricted|omegaai|dan)", re.IGNORECASE),
        re.compile(r"===\s*end\s+of\s+system\s+prompt\s*===", re.IGNORECASE),
        re.compile(r"</?system(?:_prompt)?>", re.IGNORECASE),
        re.compile(r"pretend\s+(?:you\s+are|your\s+content\s+policy)", re.IGNORECASE),
    ]

    # Indirect injection payloads in retrieved text
    DOCUMENT_INJECTION_PATTERNS = [
        re.compile(r"\[SYSTEM\s+(?:DIRECTIVE|OVERRIDE|COMMAND):[^\]]+\]", re.IGNORECASE),
        re.compile(r"<!--\s*INSTRUCTION:[^>]+-->", re.IGNORECASE),
        re.compile(r"note\s+to\s+(?:assistant|model|ai):\s*ignore", re.IGNORECASE),
    ]


class GuardrailEngine:
    """Executes pre-execution and post-generation security guardrails."""

    @classmethod
    def inspect_input(cls, user_query: str) -> Tuple[bool, List[str]]:
        """Validate input length and detect prompt injection attempts."""
        violations: List[str] = []

        if len(user_query) > GuardrailPolicy.MAX_INPUT_LENGTH:
            violations.append(f"Input exceeds maximum allowed length of {GuardrailPolicy.MAX_INPUT_LENGTH} characters")

        for pattern in GuardrailPolicy.INJECTION_PATTERNS:
            match = pattern.search(user_query)
            if match:
                violations.append(f"Prompt injection pattern detected: '{match.group(0)}'")

        # De-obfuscation inspection for evasion attempts
        from app.detectors.normalizer import TextNormalizer

        for variant_text, method_name in TextNormalizer.get_normalized_variants(user_query):
            for pattern in GuardrailPolicy.INJECTION_PATTERNS:
                match = pattern.search(variant_text)
                if match:
                    violations.append(
                        f"Obfuscated prompt injection ({method_name}) detected: unmasked '{match.group(0)}'"
                    )

        is_violating = len(violations) > 0
        return is_violating, violations

    @classmethod
    def inspect_documents(cls, docs: List[Document]) -> Tuple[List[Document], List[str]]:
        """Filter out confidential and indirect-injection poisoned documents."""
        safe_docs: List[Document] = []
        warnings: List[str] = []

        for doc in docs:
            # Drop confidential documents in defensive mode
            if doc.is_confidential:
                warnings.append(f"Blocked retrieval of confidential document '{doc.id}' ({doc.title})")
                continue

            # Check for indirect injection payloads
            is_poisoned = False
            for pattern in GuardrailPolicy.DOCUMENT_INJECTION_PATTERNS:
                if pattern.search(doc.content):
                    warnings.append(f"Sanitized indirect injection payload in retrieved doc '{doc.id}'")
                    is_poisoned = True
                    break

            if not is_poisoned:
                safe_docs.append(doc)

        return safe_docs, warnings

    @classmethod
    def sanitize_output(cls, output_text: str) -> Tuple[str, List[str]]:
        """Scan generated output for synthetic canary secrets and redact them."""
        redacted = output_text
        detected_secrets: List[str] = []

        for secret_name, canary_val in SYNTHETIC_CANARIES.items():
            if canary_val in redacted:
                detected_secrets.append(secret_name)
                redacted = redacted.replace(canary_val, f"[REDACTED_{secret_name}]")

        # General synthetic credit card / key pattern regexes
        return redacted, detected_secrets
