from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from bugfinder.web.auth import get_current_user

router = APIRouter()


class PluginInfo(BaseModel):
    name: str
    version: str
    description: str
    type: str  # entry_point or directory or builtin
    hooks: list[str] = []


class InstallRequest(BaseModel):
    name: str
    source: str  # URL to plugin .py file


@router.get("", response_model=list[PluginInfo])
async def list_plugins(user: str = Depends(get_current_user)):
    from bugfinder.core.registry import registry
    from bugfinder.plugins.loader import load_all_plugins

    load_all_plugins()
    plugin_names = registry.list_plugins()
    result = []
    for name in plugin_names:
        p = registry.get_plugin(name)
        version = "0.1.0"
        description = ""
        hooks = []

        if hasattr(p, "version"):
            version = p.version
        if hasattr(p, "description"):
            description = p.description
        if hasattr(p, "name"):
            name = p.name

        hook_list = registry._hooks
        for hook_name, fns in hook_list.items():
            for fn in fns:
                mod = getattr(fn, "__module__", "")
                if mod and name in mod:
                    hooks.append(hook_name)

        result.append(
            PluginInfo(
                name=name,
                version=version,
                description=description,
                type="builtin",
                hooks=hooks,
            )
        )
    return result


@router.get("/{name}", response_model=PluginInfo)
async def get_plugin(name: str, user: str = Depends(get_current_user)):
    from bugfinder.core.registry import registry

    p = registry.get_plugin(name)
    if not p:
        raise HTTPException(status_code=404, detail="Plugin not found")

    version = getattr(p, "version", "0.1.0")
    description = getattr(p, "description", "")
    return PluginInfo(
        name=name,
        version=version,
        description=description,
        type="builtin",
        hooks=[],
    )


@router.post("/install", status_code=201)
async def install_plugin(data: InstallRequest, user: str = Depends(get_current_user)):
    from bugfinder.plugins.loader import install_plugin as _install

    try:
        _install(data.name, data.source)
        return {"success": True, "name": data.name, "message": f"Plugin '{data.name}' installed from {data.source}"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/{name}")
async def remove_plugin(name: str, user: str = Depends(get_current_user)):

    from bugfinder.core.config import settings

    plugin_file = settings.plugins_path / f"{name}.py"
    if plugin_file.exists():
        plugin_file.unlink()
        return {"success": True, "message": f"Plugin '{name}' removed"}
    raise HTTPException(status_code=404, detail="Plugin file not found")


@router.get("/builtin/list")
async def list_builtin_plugins():
    plugins = [
        {
            "name": "example",
            "version": "0.1.0",
            "description": "Example plugin demonstrating BugFinder plugin SDK",
            "source": "https://raw.githubusercontent.com/highoncomputers/BugFinder/main/bugfinder/plugins/example.py",
        },
    ]
    return plugins
