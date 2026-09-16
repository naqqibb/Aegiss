"""
APEX — Aegis Provider EXchange
==============================

APEX is Aegis CyberNet's threat-intelligence integration layer. It ingests
indicators and detections from external security providers and normalises them
into a single, provider-agnostic schema the rest of the platform can consume.

Bundled providers
------------------
- **hunt.io**  — the C2 Feed / IOC Hunter feeds of malicious infrastructure
  (https://apidocs.hunt.io/docs/c2-feed).
- **Huntress** — managed EDR incident reports and agent inventory
  (https://api.huntress.io/docs).

Security posture
----------------
APEX is built defensively, because it holds provider API credentials and talks
to the public internet:

- Credentials are read **only** from the environment and wrapped in
  :class:`~apex.security.Secret`, which never renders its value in logs, reprs,
  or tracebacks.
- Every outbound request pins **TLS certificate verification on** (a hardened
  ``ssl`` context; ``verify=False`` is impossible by construction).
- Every request has an explicit timeout; transient failures retry with capped
  exponential backoff **plus jitter** and honour ``Retry-After``.
- A token-bucket rate limiter keeps APEX within each provider's quota.
- Responses are parsed defensively — malformed records are dropped, never
  trusted — and secret material is redacted from any error surfaced to a caller.
- The network transport is injectable, so the whole stack is unit-tested with
  **zero** real network access.
"""

from .apex import ApexModule, AggregatedFeed
from .models import (
    Indicator, IndicatorType, Confidence, Severity, IncidentReport,
)
from .providers import HuntIoProvider, HuntressProvider
from .config import ProviderConfig, load_config
from .security import Secret
from .errors import (
    ApexError, AuthError, RateLimitError, TransportError, ProviderError,
)

__all__ = [
    "ApexModule", "AggregatedFeed",
    "Indicator", "IndicatorType", "Confidence", "Severity", "IncidentReport",
    "HuntIoProvider", "HuntressProvider",
    "ProviderConfig", "load_config", "Secret",
    "ApexError", "AuthError", "RateLimitError", "TransportError", "ProviderError",
    "__version__",
]

__version__ = "1.0.0"
