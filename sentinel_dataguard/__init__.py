"""Sentinel DataGuard incremental PII masking library."""

from .masker import REDACTED_TOKEN, Masker

__all__ = ["Masker", "REDACTED_TOKEN"]
