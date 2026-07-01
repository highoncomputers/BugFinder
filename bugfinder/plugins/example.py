from __future__ import annotations


class ExamplePlugin:
    name = "example"
    version = "0.1.0"
    description = "Example plugin for BugFinder"


def register(registry_: Any) -> None:
    registry_.register_plugin("example", ExamplePlugin())
