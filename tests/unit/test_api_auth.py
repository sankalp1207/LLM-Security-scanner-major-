"""Authentication boundary tests."""

import base64
import hashlib
import hmac
import json
import time

import pytest
from fastapi import HTTPException

from app.api.auth import get_current_user_id, verify_bearer_token
from app.config import Settings


def _jwt(secret: str, claims: dict, algorithm: str = "HS256") -> str:
    def encode(value):
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    header = encode(json.dumps({"alg": algorithm, "typ": "JWT"}).encode())
    payload = encode(json.dumps(claims).encode())
    body = f"{header}.{payload}"
    signature = hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest()
    return f"{body}.{encode(signature)}"


def test_production_identity_comes_from_signed_bearer_not_user_header():
    secret = "a-test-secret-that-is-at-least-32-bytes-long"
    token = _jwt(secret, {"sub": "alice", "exp": time.time() + 60})
    assert get_current_user_id(
        authorization=f"Bearer {token}",
        x_user_id="mallory",
        settings=Settings(ENVIRONMENT="production", JWT_SECRET_KEY=secret),
    ) == "alice"


def test_production_rejects_user_header_without_bearer_token():
    with pytest.raises(HTTPException) as exc:
        get_current_user_id(
            authorization=None,
            x_user_id="victim",
            settings=Settings(ENVIRONMENT="production", JWT_SECRET_KEY="a" * 32),
        )
    assert exc.value.status_code == 401


def test_jwt_rejects_expired_or_wrong_algorithm_tokens():
    secret = "a-test-secret-that-is-at-least-32-bytes-long"
    expired = _jwt(secret, {"sub": "alice", "exp": time.time() - 1})
    wrong_alg = _jwt(secret, {"sub": "alice", "exp": time.time() + 60}, algorithm="none")
    with pytest.raises(HTTPException):
        verify_bearer_token(f"Bearer {expired}", secret)
    with pytest.raises(HTTPException):
        verify_bearer_token(f"Bearer {wrong_alg}", secret)
