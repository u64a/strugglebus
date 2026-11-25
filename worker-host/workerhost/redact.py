"""Redaction for anything that reaches a log: bus secrets (sb*1_...) and GitHub tokens."""
from __future__ import annotations

import re

PATTERNS = [
    re.compile(r"\bsb[a-z0-9]{1,4}1_[A-Za-z0-9._~+/=-]{6,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"(?i)\b(bearer|authorization:)\s+[A-Za-z0-9._~+/=-]{12,}"),
]


def redact(text: str) -> str:
    for pattern in PATTERNS:
        text = pattern.sub("[redacted]", text)
    return text
