"""Authentication helpers for API user identity."""

import base64
import hashlib
import hmac
import json
import time
from typing import Optional

from fastapi import Depends, Header, HTTPException

from app.config import Settings, get_settings


def _decode_jwt_part(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def verify_bearer_token(authorization: Optional[str], secret: str) -> str:
    """Verify a compact HS256 JWT and return its subject."""
    unauthorized = HTTPException(
        status_code=401,
        detail="A valid Bearer access token is required.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not authorization or not authorization.startswith("Bearer ") or len(secret) < 32:
        raise unauthorized

    token = authorization[7:].strip()
    if len(token) > 8192:
        raise unauthorized
    try:
        header_part, payload_part, signature_part = token.split(".")
        header = json.loads(_decode_jwt_part(header_part))
        claims = json.loads(_decode_jwt_part(payload_part))
        supplied_signature = _decode_jwt_part(signature_part)
    except Exception:
        raise unauthorized

    signing_input = f"{header_part}.{payload_part}".encode("ascii")
    expected_signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    if (
        not isinstance(header, dict)
        or not isinstance(claims, dict)
        or header.get("alg") != "HS256"
        or not hmac.compare_digest(supplied_signature, expected_signature)
    ):
        raise unauthorized

    subject = claims.get("sub")
    expires_at = claims.get("exp")
    if (
        not isinstance(subject, str)
        or not subject.strip()
        or not isinstance(expires_at, (int, float))
        or expires_at <= time.time()
    ):
        raise unauthorized
    return subject.strip()


def get_current_user_id(
    authorization: Optional[str] = Header(None),
    x_user_id: Optional[str] = Header(None),
    settings: Settings = Depends(get_settings),
) -> str:
    """Resolve identity from a signed token in production; allow local dev identities only."""
    return resolve_user_identity(authorization, x_user_id, settings)


def resolve_user_identity(
    authorization: Optional[str], x_user_id: Optional[str], settings: Settings
) -> str:
    """Resolve identity for dependencies and the production API-wide auth guard."""
    environment = settings.ENVIRONMENT.strip().lower()
    if environment == "production":
        if len(settings.JWT_SECRET_KEY) < 32:
            raise HTTPException(
                status_code=503,
                detail="Production JWT authentication requires a secret of at least 32 characters.",
            )
        return verify_bearer_token(authorization, settings.JWT_SECRET_KEY)

    # X-User-ID is only a local development/testing convenience, never an auth mechanism.
    return x_user_id.strip() if x_user_id and x_user_id.strip() else "default_user"
