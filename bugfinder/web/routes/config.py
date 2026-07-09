from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from bugfinder.web.auth import get_current_user

router = APIRouter()


class ConfigValue(BaseModel):
    key: str
    value: str


class ConfigUpdateRequest(BaseModel):
    values: list[ConfigValue]


class ConfigResponse(BaseModel):
    config: dict[str, Any]
    env_path: str


@router.get("/config", response_model=ConfigResponse)
async def get_config(user: str = Depends(get_current_user)):
    from bugfinder.core.config import settings

    masked = {}
    for k, v in settings.model_dump().items():
        if any(secret in k.lower() for secret in ("key", "token", "password", "secret")):
            masked[k] = mask_value(str(v))
        else:
            masked[k] = v

    env_path = str(Path.cwd() / ".env")
    return ConfigResponse(config=masked, env_path=env_path)


@router.put("/config", response_model=ConfigResponse)
async def update_config(req: ConfigUpdateRequest, user: str = Depends(get_current_user)):
    from bugfinder.core.config import settings

    scalar_fields = {k for k in settings.model_fields if k not in ("allowed_domains", "model_config")}

    for cv in req.values:
        if cv.key in scalar_fields:
            field_info = settings.model_fields.get(cv.key)
            if field_info is None:
                continue
            current = getattr(settings, cv.key)
            if isinstance(current, bool):
                setattr(settings, cv.key, cv.value.lower() in ("true", "1", "yes"))
            elif isinstance(current, int):
                setattr(settings, cv.key, int(cv.value))
            else:
                setattr(settings, cv.key, cv.value)

    settings.save_to_env()

    masked = {}
    for k, v in settings.model_dump().items():
        if any(secret in k.lower() for secret in ("key", "token", "password", "secret")):
            masked[k] = mask_value(str(v))
        else:
            masked[k] = v

    env_path = str(Path.cwd() / ".env")
    return ConfigResponse(config=masked, env_path=env_path)


def mask_value(value: str) -> str:
    if len(value) <= 4:
        return "****"
    return value[:4] + "****" + value[-2:] if len(value) > 8 else value[:4] + "****"
