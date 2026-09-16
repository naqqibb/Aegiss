"""Typed exception hierarchy for APEX.

Error messages are constructed so they never contain secret material: provider
code passes redacted text (see :func:`apex.security.redact`) when an underlying
error might quote a URL or header carrying a token.
"""

from __future__ import annotations


class ApexError(Exception):
    """Base class for every APEX error."""


class ConfigError(ApexError):
    """Missing or invalid configuration (e.g. absent credentials)."""


class AuthError(ApexError):
    """Provider rejected our credentials (HTTP 401/403)."""


class RateLimitError(ApexError):
    """Provider rate limit hit and retries were exhausted (HTTP 429)."""

    def __init__(self, message: str, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class TransportError(ApexError):
    """A network-level failure (DNS, TLS, connection, timeout)."""


class ProviderError(ApexError):
    """A provider returned an unexpected or unparseable response."""
