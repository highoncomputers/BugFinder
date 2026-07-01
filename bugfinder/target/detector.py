from __future__ import annotations

import pathlib
import re

from bugfinder.core.types import TargetType

IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
CIDR_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$")
DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
URL_RE = re.compile(r"^https?://", re.IGNORECASE)
SWAGGER_FILE = re.compile(r"(swagger|openapi|api-spec)\.(json|yaml|yml)$", re.IGNORECASE)


def detect_target_type(target: str) -> TargetType:
    target = target.strip()

    if _is_apk(target):
        return TargetType.ANDROID
    if _is_dockerfile(target):
        return TargetType.DOCKER
    if _is_kubernetes_manifest(target):
        return TargetType.KUBERNETES
    if _is_swagger_file(target):
        return TargetType.API
    if _is_source_directory(target):
        return TargetType.SOURCE_CODE
    if _is_cidr(target):
        return TargetType.CIDR
    if _is_ip(target):
        return TargetType.IP_ADDRESS
    if _is_url(target):
        return _detect_url_type(target)
    if _is_domain(target):
        return TargetType.DOMAIN

    return TargetType.UNKNOWN


def _is_apk(target: str) -> bool:
    return target.endswith(".apk")


def _is_dockerfile(target: str) -> bool:
    p = pathlib.Path(target)
    return p.name == "Dockerfile" or target.endswith(".dockerfile")


def _is_kubernetes_manifest(target: str) -> bool:
    if not (target.endswith(".yaml") or target.endswith(".yml")):
        return False
    try:
        text = pathlib.Path(target).read_text(encoding="utf-8", errors="ignore")
        return "apiVersion" in text and "kind" in text
    except OSError:
        return False


def _is_swagger_file(target: str) -> bool:
    return bool(SWAGGER_FILE.search(target))


def _is_source_directory(target: str) -> bool:
    p = pathlib.Path(target)
    if not p.is_dir():
        return False
    indicators = [
        "setup.py",
        "pyproject.toml",
        "package.json",
        "Cargo.toml",
        "go.mod",
        "Gemfile",
        "pom.xml",
        "build.gradle",
        "CMakeLists.txt",
        "Makefile",
    ]
    return any((p / ind).exists() for ind in indicators)


def _is_cidr(target: str) -> bool:
    return bool(CIDR_RE.match(target))


def _is_ip(target: str) -> bool:
    if IPV4_RE.match(target):
        parts = [int(x) for x in target.split(".")]
        return all(0 <= p <= 255 for p in parts)
    return False


def _is_url(target: str) -> bool:
    if URL_RE.match(target) or "://" in target:
        return True
    if "/" in target:
        domain_part = target.split("/")[0]
        return bool(DOMAIN_RE.match(domain_part))
    return False


def _is_domain(target: str) -> bool:
    return bool(DOMAIN_RE.match(target))


def _detect_url_type(target: str) -> TargetType:
    from urllib.parse import urlparse

    if target.lower().startswith("graphql") or "/graphql" in target.lower():
        return TargetType.GRAPHQL
    if "graphql" in target.lower():
        return TargetType.GRAPHQL

    parsed = urlparse(target)
    hostname = parsed.hostname or parsed.path.split("/")[0] or ""

    if hostname and "api" in hostname.split(".")[0].lower():
        return TargetType.API
    if "/api/" in target.lower() or target.lower().startswith("api."):
        return TargetType.API

    return TargetType.WEBSITE


def normalize_target(target: str) -> str:
    target = target.strip()
    if not URL_RE.match(target) and "/" not in target and _is_domain(target):
        target = f"https://{target}"
    if not URL_RE.match(target) and "/" in target:
        domain_part = target.split("/")[0]
        if _is_domain(domain_part):
            target = f"https://{target}"
    return target
