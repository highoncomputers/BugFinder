from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel

from bugfinder.web.auth import create_session_token

router = APIRouter()


class LoginRequest(BaseModel):
    api_key: str


class LoginResponse(BaseModel):
    success: bool
    token: str


@router.post("/login", response_model=LoginResponse)
async def login(req: LoginRequest, response: Response):
    from bugfinder.core.config import Settings

    cfg = Settings()
    valid_keys = [
        cfg.nvidia_api_key,
        cfg.openai_api_key,
        cfg.anthropic_api_key,
        cfg.github_token,
    ]
    if any(k and req.api_key == k for k in valid_keys):
        token = create_session_token()
        max_age = cfg.web_settings.web_session_expiry_hours * 3600 if hasattr(cfg, "web_settings") else 86400
        response.set_cookie(
            key="session",
            value=token,
            httponly=True,
            samesite="lax",
            max_age=max_age,
        )
        return LoginResponse(success=True, token=token)
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")


@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie("session")
    return {"success": True}
