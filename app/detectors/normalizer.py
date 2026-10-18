"""De-obfuscation and input normalization pipeline for evasion-resilient threat detection."""

import base64
import codecs
import re
import string
import unicodedata
from typing import List, Optional, Set, Tuple


class TextNormalizer:
    """Detects and normalizes adversarial obfuscations (Homoglyphs, Leetspeak, Base64, ROT13)."""

    # Cyrillic and Greek homoglyphs mapped to ASCII equivalents
    HOMOGLYPH_MAP = {
        "\u0430": "a", "\u0410": "A",  # Cyrillic a/A
        "\u0435": "e", "\u0415": "E",  # Cyrillic e/E
        "\u043e": "o", "\u041e": "O",  # Cyrillic o/O
        "\u0440": "p", "\u0420": "P",  # Cyrillic p/P
        "\u0441": "c", "\u0421": "C",  # Cyrillic c/C
        "\u0443": "y", "\u0423": "Y",  # Cyrillic y/Y
        "\u0445": "x", "\u0425": "X",  # Cyrillic x/X
        "\u0456": "i", "\u0406": "I",  # Cyrillic i/I
        "\u0458": "j", "\u0408": "J",  # Cyrillic j/J
        "\u0455": "s", "\u0405": "S",  # Cyrillic s/S
        "\u0412": "B", "\u041a": "K",  # Cyrillic B, K
        "\u041c": "M", "\u041d": "H",  # Cyrillic M, H
        "\u0422": "T",                 # Cyrillic T
        "\u03bf": "o", "\u039f": "O",  # Greek Omicron
        "\u03c1": "p", "\u03a1": "P",  # Greek Rho
    }

    # Leetspeak translation table
    LEET_MAP = {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
    }

    # Base64 candidate regex pattern
    BASE64_PATTERN = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b")

    # Delimiter wrapper patterns
    DELIMITER_PATTERNS = [
        re.compile(r"<\s*system_override[^>]*>(.*?)<\s*/\s*system_override\s*>", re.DOTALL | re.IGNORECASE),
        re.compile(r"<\s*admin_override[^>]*>(.*?)<\s*/\s*admin_override\s*>", re.DOTALL | re.IGNORECASE),
        re.compile(r"===\s*BEGIN\s+INSTRUCTION\s*===(.*?)===\s*END\s+INSTRUCTION\s*===", re.DOTALL | re.IGNORECASE),
        re.compile(r"```(?:json|xml)?\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE),
    ]

    @classmethod
    def normalize_homoglyphs(cls, text: str) -> Optional[str]:
        """Convert Cyrillic and Unicode homoglyphs to standard ASCII characters."""
        has_homoglyph = False
        chars = []
        for ch in text:
            if ch in cls.HOMOGLYPH_MAP:
                chars.append(cls.HOMOGLYPH_MAP[ch])
                has_homoglyph = True
            else:
                chars.append(ch)

        if not has_homoglyph:
            # Check NFKD normalization
            normalized_nfkd = unicodedata.normalize("NFKD", text)
            if normalized_nfkd != text:
                return normalized_nfkd
            return None

        result = "".join(chars)
        return unicodedata.normalize("NFKD", result)

    @classmethod
    def normalize_leetspeak(cls, text: str) -> Optional[str]:
        """Convert leetspeak numbers/symbols to corresponding alphabet characters."""
        chars = []
        substituted = False
        for ch in text:
            if ch in cls.LEET_MAP:
                chars.append(cls.LEET_MAP[ch])
                substituted = True
            else:
                chars.append(ch)

        if substituted:
            return "".join(chars)
        return None

    @classmethod
    def extract_and_decode_base64(cls, text: str) -> List[str]:
        """Find and decode candidate Base64 strings embedded within text."""
        decoded_strings: List[str] = []
        candidates = cls.BASE64_PATTERN.findall(text)

        for candidate in candidates:
            # Only test plausible base64 strings with reasonable length
            if len(candidate) < 8:
                continue
            try:
                raw_bytes = base64.b64decode(candidate, validate=True)
                decoded = raw_bytes.decode("utf-8", errors="ignore").strip()
                # Check if decoded string looks like human-readable text
                if len(decoded) >= 4 and cls._is_printable_ascii(decoded):
                    decoded_strings.append(decoded)
            except Exception:
                continue

        return decoded_strings

    @classmethod
    def extract_and_decode_rot13(cls, text: str) -> Optional[str]:
        """Decode ROT13 text if indicators or high-entropy cipher structures are present."""
        lower = text.lower()
        if "rot13" in lower or "rot-13" in lower or "caesar" in lower:
            # Attempt to decode text excluding command words
            decoded = codecs.encode(text, "rot_13")
            return decoded

        # Also attempt decoding if decoded text uncovers security keywords
        decoded = codecs.encode(text, "rot_13")
        dec_lower = decoded.lower()
        if any(kw in dec_lower for kw in ["ignore previous", "system prompt", "disregard all", "canary"]):
            return decoded

        return None

    @classmethod
    def unwrap_delimiters(cls, text: str) -> List[str]:
        """Extract inner content from deceptive tag enclosures."""
        unwrapped: List[str] = []
        for pat in cls.DELIMITER_PATTERNS:
            for match in pat.finditer(text):
                inner = match.group(1).strip()
                if inner and inner != text.strip():
                    unwrapped.append(inner)
        return unwrapped

    @classmethod
    def get_normalized_variants(cls, text: str) -> List[Tuple[str, str]]:
        """
        Produce candidate de-obfuscated variants of the input text along with the technique name.
        Returns a list of tuples: (unmasked_text, technique_used).
        """
        variants: List[Tuple[str, str]] = []
        seen: Set[str] = {text.strip().lower()}

        # 1. Base64 Decoding
        for b64_dec in cls.extract_and_decode_base64(text):
            norm_key = b64_dec.strip().lower()
            if norm_key not in seen:
                seen.add(norm_key)
                variants.append((b64_dec, "base64"))

        # 2. Homoglyph Normalization
        homo_dec = cls.normalize_homoglyphs(text)
        if homo_dec:
            norm_key = homo_dec.strip().lower()
            if norm_key not in seen:
                seen.add(norm_key)
                variants.append((homo_dec, "homoglyph"))

        # 3. Leetspeak Normalization
        leet_dec = cls.normalize_leetspeak(text)
        if leet_dec:
            norm_key = leet_dec.strip().lower()
            if norm_key not in seen:
                seen.add(norm_key)
                variants.append((leet_dec, "leetspeak"))

        # 4. ROT13 Decoding
        rot_dec = cls.extract_and_decode_rot13(text)
        if rot_dec:
            norm_key = rot_dec.strip().lower()
            if norm_key not in seen:
                seen.add(norm_key)
                variants.append((rot_dec, "rot13"))

        # 5. Delimiter Unwrapping
        for unwrapped in cls.unwrap_delimiters(text):
            norm_key = unwrapped.strip().lower()
            if norm_key not in seen:
                seen.add(norm_key)
                variants.append((unwrapped, "delimiter_unwrapping"))

        return variants

    @staticmethod
    def _is_printable_ascii(s: str) -> bool:
        """Check if a string contains predominantly printable ASCII characters."""
        if not s:
            return False
        printable_count = sum(1 for ch in s if ch in string.printable)
        return (printable_count / len(s)) >= 0.85
