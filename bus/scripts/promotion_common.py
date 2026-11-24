"""Shared, deliberately non-sensitive operator promotion failures."""

from __future__ import annotations


class PromotionError(RuntimeError):
    """An operator-safe failure with a stable CLI exit code."""

    def __init__(self, message: str, *, code: int = 6) -> None:
        super().__init__(message)
        self.code = code
