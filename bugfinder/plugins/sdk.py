from __future__ import annotations

from typing import Any, Callable

from bugfinder.core.registry import registry


def hook(name: str) -> Callable:
    def decorator(fn: Callable) -> Callable:
        registry.register_hook(name, fn)
        return fn
    return decorator


def pre_scan(fn: Callable) -> Callable:
    return hook("pre_scan")(fn)


def post_scan(fn: Callable) -> Callable:
    return hook("post_scan")(fn)


def pre_agent(fn: Callable) -> Callable:
    return hook("pre_agent")(fn)


def post_agent(fn: Callable) -> Callable:
    return hook("post_agent")(fn)


def on_finding(fn: Callable) -> Callable:
    return hook("on_finding")(fn)


def on_report(fn: Callable) -> Callable:
    return hook("on_report")(fn)


class PluginBase:
    name: str = ""
    version: str = "0.1.0"
    description: str = ""

    def register(self, registry_: Any) -> None:
        pass
