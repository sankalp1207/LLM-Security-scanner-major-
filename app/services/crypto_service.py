"""Secure secrets management and credential encryption service."""

import base64
import hashlib
from typing import Optional

from cryptography.fernet import Fernet

from app.config import get_settings


class CryptoService:
    """Provides authenticated symmetric encryption (Fernet) for API keys and target credentials."""

    @classmethod
    def _get_fernet(cls) -> Fernet:
        """Derive a consistent 32-byte URL-safe base64 Fernet key."""
        settings = get_settings()
        raw_key = getattr(settings, "ENCRYPTION_KEY", "") or f"{settings.PROJECT_NAME}:{settings.DATABASE_URL}:secret_salt"
        # Derive 32-byte key using SHA-256
        key_bytes = hashlib.sha256(raw_key.encode("utf-8")).digest()
        fernet_key = base64.urlsafe_b64encode(key_bytes)
        return Fernet(fernet_key)

    @classmethod
    def encrypt_credential(cls, secret_text: Optional[str]) -> str:
        """Encrypt plain text credential into a base64 ciphertext string."""
        if not secret_text or not secret_text.strip():
            return ""
        try:
            f = cls._get_fernet()
            cipher_bytes = f.encrypt(secret_text.strip().encode("utf-8"))
            return cipher_bytes.decode("utf-8")
        except Exception:
            return ""

    @classmethod
    def decrypt_credential(cls, cipher_text: Optional[str]) -> str:
        """Decrypt ciphertext back to plain text."""
        if not cipher_text or not cipher_text.strip():
            return ""
        try:
            f = cls._get_fernet()
            plain_bytes = f.decrypt(cipher_text.strip().encode("utf-8"))
            return plain_bytes.decode("utf-8")
        except Exception:
            return ""

    @classmethod
    def mask_credential(cls, secret_text: Optional[str]) -> str:
        """Mask a credential string for secure display in the UI (e.g. sk-••••••••1234)."""
        if not secret_text or not secret_text.strip():
            return ""
        s = secret_text.strip()
        if len(s) <= 8:
            return "••••••••"
        prefix = s[:3]
        suffix = s[-4:]
        return f"{prefix}••••••••{suffix}"

