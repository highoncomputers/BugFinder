from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel

from bugfinder.web.auth import create_session_token

router = APIRouter()


class LoginRequest(BaseModel):
    api_key: str


class LoginResponse(BaseModel):
    success: bool
    token: str
    first_time: bool = False


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
    has_any_key = any(k for k in valid_keys)

    # First-time setup: no keys configured — accept any key and save it
    if not has_any_key and req.api_key:
        cfg.nvidia_api_key = req.api_key
        env_path = Path(".env")
        cfg.save_to_env(str(env_path))
        token = create_session_token()
        response.set_cookie(key="session", value=token, httponly=True, samesite="lax", max_age=86400)
        return LoginResponse(success=True, token=token, first_time=True)

    if any(k and req.api_key == k for k in valid_keys):
        token = create_session_token()
        max_age = getattr(cfg, "web_session_expiry_hours", 24) * 3600
        response.set_cookie(
            key="session",
            value=token,
            httponly=True,
            samesite="lax",
            max_age=max_age,
        )
        return LoginResponse(success=True, token=token)
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")


@router.post("/api/validate-key")
async def validate_key(req: LoginRequest):
    from bugfinder.core.config import Settings
    cfg = Settings()
    valid_keys = [
        cfg.nvidia_api_key,
        cfg.openai_api_key,
        cfg.anthropic_api_key,
        cfg.github_token,
    ]
    if any(k and req.api_key == k for k in valid_keys):
        return {"valid": True}
    return {"valid": False, "error": "API key not found in configuration. Save it via Settings first."}


@router.post("/api/test-connection")
async def test_connection(req: LoginRequest):
    from bugfinder.core.config import Settings
    cfg = Settings()
    import httpx
    base_url = (cfg.nvidia_base_url or "https://integrate.api.nvidia.com/v1").rstrip("/")
    try:
        async with httpx.AsyncClient(
            base_url=base_url,
            timeout=httpx.Timeout(15),
            headers={"Authorization": f"Bearer {req.api_key}", "Content-Type": "application/json"},
        ) as client:
            resp = await client.get("/models")
            if resp.status_code == 200:
                models = resp.json()
                available = [m["id"] for m in models.get("data", [])]
                return {"success": True, "models": available}
            return {"success": False, "error": f"API returned {resp.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie("session")
    return {"success": True}
