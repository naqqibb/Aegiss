"""A small, hardened HTTP client for APEX.

Design points:

- **Injectable transport.** The client talks to a ``Transport`` callable, not
  to ``urllib`` directly, so every retry/parse path is unit-tested with a fake
  transport and no real sockets. The default transport is
  :class:`UrllibTransport`, which pins a hardened TLS context.
- **Retries with jittered backoff.** Only idempotent methods retry, only on
  connection errors and status 429/5xx, capped by ``max_retries`` and honouring
  ``Retry-After``.
- **Rate limiting.** A :class:`~apex.ratelimit.TokenBucket` gates every send.
- **No secret leakage.** Errors are redacted through the caller-supplied
  secrets before being raised.
"""

from __future__ import annotations

import random
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Mapping, Optional

from .errors import AuthError, RateLimitError, TransportError
from .ratelimit import TokenBucket
from .security import Secret, hardened_ssl_context, redact


@dataclass
class HttpRequest:
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[bytes] = None
    timeout: float = 20.0


@dataclass
class HttpResponse:
    status: int
    headers: Dict[str, str]
    body: bytes

    def header(self, name: str, default: Optional[str] = None) -> Optional[str]:
        # case-insensitive lookup
        low = name.lower()
        for k, v in self.headers.items():
            if k.lower() == low:
                return v
        return default


# A transport turns a request into a response (or raises TransportError).
Transport = Callable[[HttpRequest], HttpResponse]

_RETRY_STATUS = {429, 500, 502, 503, 504}
_IDEMPOTENT = {"GET", "HEAD"}


class UrllibTransport:
    """Default transport backed by ``urllib`` with a hardened TLS context."""

    def __init__(self) -> None:
        self._ssl = hardened_ssl_context()

    def __call__(self, req: HttpRequest) -> HttpResponse:
        request = urllib.request.Request(
            req.url, data=req.body, method=req.method, headers=req.headers
        )
        try:
            with urllib.request.urlopen(
                request, timeout=req.timeout, context=self._ssl
            ) as resp:
                return HttpResponse(
                    status=resp.status,
                    headers={k: v for k, v in resp.headers.items()},
                    body=resp.read(),
                )
        except urllib.error.HTTPError as exc:  # 4xx/5xx still carry a body
            return HttpResponse(
                status=exc.code,
                headers={k: v for k, v in (exc.headers or {}).items()},
                body=exc.read() if hasattr(exc, "read") else b"",
            )
        except (urllib.error.URLError, OSError) as exc:
            raise TransportError(f"transport failure: {exc}") from None


class HttpClient:
    def __init__(
        self,
        transport: Optional[Transport] = None,
        *,
        rate_per_sec: float = 5.0,
        max_retries: int = 3,
        backoff_base: float = 0.5,
        backoff_cap: float = 30.0,
        sleep: Callable[[float], None] = time.sleep,
        rng: Optional[random.Random] = None,
        secrets: Optional[List[Secret]] = None,
    ) -> None:
        self.transport = transport or UrllibTransport()
        self.bucket = TokenBucket(rate=rate_per_sec, sleep=sleep)
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.backoff_cap = backoff_cap
        self._sleep = sleep
        self._rng = rng or random.Random()
        self._secrets = secrets or []

    def _redact(self, text: str) -> str:
        return redact(text, self._secrets)

    def _backoff(self, attempt: int, retry_after: Optional[float]) -> float:
        if retry_after is not None:
            return min(retry_after, self.backoff_cap)
        # exponential backoff with full jitter
        ceiling = min(self.backoff_cap, self.backoff_base * (2 ** attempt))
        return self._rng.uniform(0, ceiling)

    @staticmethod
    def _retry_after(resp: HttpResponse) -> Optional[float]:
        raw = resp.header("Retry-After")
        if raw is None:
            return None
        try:
            return max(0.0, float(raw))
        except ValueError:
            return None

    def request(self, req: HttpRequest) -> HttpResponse:
        attempt = 0
        while True:
            self.bucket.acquire()
            try:
                resp = self.transport(req)
            except TransportError as exc:
                if req.method.upper() in _IDEMPOTENT and attempt < self.max_retries:
                    self._sleep(self._backoff(attempt, None))
                    attempt += 1
                    continue
                raise TransportError(self._redact(str(exc))) from None

            if resp.status in (401, 403):
                raise AuthError(
                    self._redact(f"{req.method} {req.url}: authentication failed "
                                 f"(HTTP {resp.status})")
                )
            if resp.status in _RETRY_STATUS:
                retry_after = self._retry_after(resp)
                if req.method.upper() in _IDEMPOTENT and attempt < self.max_retries:
                    self._sleep(self._backoff(attempt, retry_after))
                    attempt += 1
                    continue
                if resp.status == 429:
                    raise RateLimitError(
                        self._redact(f"{req.url}: rate limited (429), retries exhausted"),
                        retry_after=retry_after,
                    )
                raise TransportError(
                    self._redact(f"{req.url}: server error HTTP {resp.status}")
                )
            return resp

    def get(self, url: str, headers: Mapping[str, str], timeout: float) -> HttpResponse:
        return self.request(HttpRequest("GET", url, dict(headers), None, timeout))
