"""Security primitives for APEX: secret handling and redaction.

The single most important property here is that **a secret's value never leaks
into a log line, a repr, a traceback frame, or an exception message**. Provider
code carries credentials only as :class:`Secret` and redacts free-form text
through :func:`redact` before it is logged or raised.
"""

from __future__ import annotations

import hmac
import ssl
from typing import Iterable

_MASK = "***REDACTED***"


class Secret:
    """An opaque wrapper around sensitive text.

    The wrapped value is available only through :meth:`reveal`, which callers
    use at the exact moment they hand it to the transport. Every other code
    path — ``str``, ``repr``, f-strings, logging — sees a mask, so a secret can
    never be printed by accident.
    """

    __slots__ = ("_value", "_label")

    def __init__(self, value: str, label: str = "secret") -> None:
        if not isinstance(value, str):
            raise TypeError("Secret value must be a string")
        self._value = value
        self._label = label

    def reveal(self) -> str:
        """Return the underlying secret. Call only when handing it to a sink."""
        return self._value

    def __bool__(self) -> bool:
        return bool(self._value)

    def __len__(self) -> int:
        return len(self._value)

    def __eq__(self, other: object) -> bool:
        # Constant-time comparison to avoid leaking length/prefix via timing.
        if isinstance(other, Secret):
            return hmac.compare_digest(self._value, other._value)
        if isinstance(other, str):
            return hmac.compare_digest(self._value, other)
        return NotImplemented

    def __hash__(self) -> int:  # so Secrets can live in sets/dicts safely
        return hash((self._label, len(self._value)))

    def __repr__(self) -> str:
        return f"Secret(label={self._label!r}, value={_MASK})"

    __str__ = __repr__


def redact(text: str, secrets: Iterable[object]) -> str:
    """Replace every secret value found in ``text`` with a mask.

    Accepts a mix of :class:`Secret` and plain strings. Empty/short values are
    skipped so we never mask trivial substrings like an empty string.
    """
    out = text
    for s in secrets:
        raw = s.reveal() if isinstance(s, Secret) else s
        if isinstance(raw, str) and len(raw) >= 4:
            out = out.replace(raw, _MASK)
    return out


def hardened_ssl_context() -> ssl.SSLContext:
    """A TLS client context with verification and hostname checking enforced.

    TLS 1.2 is the floor. There is deliberately no switch to disable
    verification — a misconfiguration cannot silently downgrade APEX to an
    insecure connection.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except (AttributeError, ValueError):  # pragma: no cover - old runtimes
        pass
    return ctx
