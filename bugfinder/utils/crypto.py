from __future__ import annotations

import hashlib
import math
import re
from typing import Any


def sha256(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def md5(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.md5(data).hexdigest()


def shannon_entropy(data: str | bytes) -> float:
    if isinstance(data, str):
        data = data.encode("utf-8")
    if not data:
        return 0.0
    entropy = 0.0
    for x in range(256):
        p_x = data.count(x) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    return entropy


_HIGH_ENTROPY_PATTERNS: list[tuple[str, float, str]] = [
    (r"[A-Za-z0-9+/=]{40,}", 3.5, "base64"),
    (r"[A-Fa-f0-9]{32}", 3.0, "md5_hash"),
    (r"[A-Fa-f0-9]{40}", 3.0, "sha1_hash"),
    (r"[A-Fa-f0-9]{64}", 3.0, "sha256_hash"),
    (r"gh[ps]_[A-Za-z0-9]{36}", 2.0, "github_token"),
    (r"sk-[A-Za-z0-9]{32,}", 3.0, "openai_key"),
    (r"AKIA[0-9A-Z]{16}", 2.5, "aws_access_key"),
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", 2.0, "jwt"),
]


def detect_high_entropy_strings(text: str, min_entropy: float = 3.5) -> list[dict[str, Any]]:
    results = []
    for pattern, threshold, label in _HIGH_ENTROPY_PATTERNS:
        for match in re.finditer(pattern, text):
            entropy = shannon_entropy(match.group())
            if entropy >= threshold:
                results.append(
                    {
                        "value": match.group()[:50],
                        "entropy": round(entropy, 2),
                        "pattern": label,
                        "start": match.start(),
                        "end": match.end(),
                    }
                )
    return results
