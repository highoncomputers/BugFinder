from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path
from typing import Any

from bugfinder.core.exceptions import PluginError
from bugfinder.core.registry import registry


def discover_entry_point_plugins(group: str = "bugfinder.plugins") -> dict[str, Any]:
    plugins = {}
    try:
        from importlib.metadata import entry_points

        eps = entry_points(group=group)
        for ep in eps:
            try:
                plugin = ep.load()
                plugins[ep.name] = plugin
                registry.register_plugin(ep.name, plugin)
            except Exception as e:
                raise PluginError(f"Failed to load plugin '{ep.name}': {e}") from e
    except ImportError:
        pass
    return plugins


def discover_directory_plugins(plugins_dir: str | Path | None = None) -> dict[str, Any]:
    plugins = {}
    if plugins_dir is None:
        from bugfinder.core.config import settings

        plugins_dir = settings.plugins_path

    plugins_path = Path(plugins_dir)
    if not plugins_path.exists():
        plugins_path.mkdir(parents=True, exist_ok=True)
        return plugins

    if str(plugins_path) not in sys.path:
        sys.path.insert(0, str(plugins_path))

    for fname in os.listdir(plugins_path):
        if fname.endswith(".py") and not fname.startswith("_"):
            modname = fname[:-3]
            try:
                mod = importlib.import_module(modname)
                if hasattr(mod, "register"):
                    mod.register(registry)
                    plugins[modname] = mod
            except Exception as e:
                raise PluginError(f"Failed to load plugin '{modname}': {e}") from e

    return plugins


def load_all_plugins() -> dict[str, Any]:
    plugins = {}
    plugins.update(discover_entry_point_plugins())
    plugins.update(discover_directory_plugins())
    return plugins


def install_plugin(name: str, source: str) -> None:
    from bugfinder.core.config import settings

    plugins_dir = Path(settings.plugins_dir)
    plugins_dir.mkdir(parents=True, exist_ok=True)

    import httpx

    resp = httpx.get(source)
    resp.raise_for_status()

    target = plugins_dir / f"{name}.py"
    target.write_text(resp.text, encoding="utf-8")
