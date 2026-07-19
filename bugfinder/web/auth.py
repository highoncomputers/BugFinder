from __future__ import annotations

import hashlib
import hmac
import time

from fastapi import HTTPException, Request, status
from itsdangerous import URLSafeTimedSerializer

from bugfinder.web.config import WebSettings

settings = WebSettings()
serializer = URLSafeTimedSerializer(settings.web_secret_key, salt="bugfinder-session")


def create_session_token(user_id: str = "admin") -> str:
    payload = {"user_id": user_id, "iat": int(time.time())}
    return serializer.dumps(payload)


def verify_session_token(token: str, max_age: int | None = None) -> str | None:
    if max_age is None:
        max_age = settings.web_session_expiry_hours * 3600
    try:
        payload = serializer.loads(token, max_age=max_age)
        return payload.get("user_id")
    except Exception:
        return None


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def validate_api_key(key: str, expected_hash: str) -> bool:
    return hmac.compare_digest(hash_api_key(key), expected_hash)


async def get_current_user(request: Request) -> str:
    token = request.cookies.get("session")
    if token:
        user_id = verify_session_token(token)
        if user_id:
            return user_id

    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        api_key = auth_header[7:]
        from bugfinder.core.config import Settings

        cfg = Settings()
        valid_keys = [
            cfg.nvidia_api_key,
            cfg.openai_api_key,
            cfg.anthropic_api_key,
            cfg.github_token,
        ]
        if any(k and api_key == k for k in valid_keys):
            return "api-user"

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )
