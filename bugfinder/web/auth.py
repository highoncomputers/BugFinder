from __future__ import annotations

import hashlib
import hmac
import time
from typing import Optional

from fastapi import HTTPException, Request, status
from itsdangerous import URLSafeTimedSerializer

from bugfinder.web.config import WebSettings

settings = WebSettings()
serializer = URLSafeTimedSerializer(settings.web_secret_key, salt="bugfinder-session")


def create_session_token(user_id: str = "admin") -> str:
    payload = {"user_id": user_id, "iat": int(time.time())}
    return serializer.dumps(payload)


def verify_session_token(token: str, max_age: int | None = None) -> Optional[str]:
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
        if cfg.nvidia_api_key and api_key == cfg.nvidia_api_key:
            return "api-user"

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )
