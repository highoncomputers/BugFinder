from __future__ import annotations

import importlib
import pkgutil
from typing import Any


class Registry:
    def __init__(self) -> None:
        self._agents: dict[str, type] = {}
        self._plugins: dict[str, Any] = {}
        self._hooks: dict[str, list[callable]] = {}

    def register_agent(self, name: str, agent_cls: type) -> None:
        self._agents[name] = agent_cls

    def get_agent(self, name: str) -> type | None:
        return self._agents.get(name)

    def list_agents(self) -> list[str]:
        return list(self._agents.keys())

    def register_plugin(self, name: str, plugin: Any) -> None:
        self._plugins[name] = plugin

    def get_plugin(self, name: str) -> Any | None:
        return self._plugins.get(name)

    def list_plugins(self) -> list[str]:
        return list(self._plugins.keys())

    def register_hook(self, hook_name: str, fn: callable) -> None:
        self._hooks.setdefault(hook_name, []).append(fn)

    def run_hooks(self, hook_name: str, **kwargs: Any) -> list[Any]:
        results = []
        for fn in self._hooks.get(hook_name, []):
            results.append(fn(**kwargs))
        return results

    def discover_agents(self, package: str = "bugfinder.agents") -> None:
        try:
            pkg = importlib.import_module(package)
            for importer, modname, ispkg in pkgutil.walk_packages(
                pkg.__path__, prefix=f"{package}."
            ):
                try:
                    importlib.import_module(modname)
                except ImportError:
                    continue
        except ImportError:
            pass

    def discover_plugins(self, entry_point_group: str = "bugfinder.plugins") -> None:
        try:
            from importlib.metadata import entry_points

            eps = entry_points(group=entry_point_group)
            for ep in eps:
                try:
                    plugin = ep.load()
                    self.register_plugin(ep.name, plugin)
                except ImportError:
                    continue
        except ImportError:
            pass

    def discover_directory_plugins(self, plugins_dir: str | None = None) -> None:
        if not plugins_dir:
            return
        import sys

        path = str(plugins_dir)
        if path not in sys.path:
            sys.path.insert(0, path)

        import os

        for fname in os.listdir(plugins_dir):
            if fname.endswith(".py") and not fname.startswith("_"):
                modname = fname[:-3]
                try:
                    mod = importlib.import_module(modname)
                    if hasattr(mod, "register"):
                        mod.register(self)
                except ImportError:
                    continue


registry = Registry()
