"""Configuration loading for APEX providers.

Credentials come from the process environment and nowhere else — never from a
file committed to the repo, never a constructor default. Each value is wrapped
in :class:`~apex.security.Secret` the moment it is read.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, Mapping, Optional

from .errors import ConfigError
from .security import Secret


@dataclass
class ProviderConfig:
    """Connection settings for a single provider."""

    name: str
    base_url: str
    # Header name -> Secret (e.g. {"token": Secret(...)}) OR basic auth pair.
    token: Optional[Secret] = None
    basic_user: Optional[Secret] = None
    basic_pass: Optional[Secret] = None
    timeout: float = 20.0
    rate_per_sec: float = 5.0
    max_retries: int = 3
    extra: Dict[str, str] = field(default_factory=dict)

    def require_token(self) -> Secret:
        if not self.token:
            raise ConfigError(f"{self.name}: missing API token")
        return self.token

    def require_basic(self) -> tuple[Secret, Secret]:
        if not (self.basic_user and self.basic_pass):
            raise ConfigError(f"{self.name}: missing basic-auth credentials")
        return self.basic_user, self.basic_pass


def _get(env: Mapping[str, str], key: str) -> Optional[str]:
    val = env.get(key)
    return val if val else None


def load_config(env: Optional[Mapping[str, str]] = None) -> Dict[str, ProviderConfig]:
    """Build provider configs from the environment.

    Recognised variables::

        HUNTIO_API_TOKEN         hunt.io API token
        HUNTIO_BASE_URL          override (default https://api.hunt.io/v1)
        HUNTRESS_API_KEY         Huntress API key   (basic-auth user)
        HUNTRESS_API_SECRET      Huntress API secret (basic-auth pass)
        HUNTRESS_BASE_URL        override (default https://api.huntress.io/v1)

    Providers with no credentials present are simply omitted, so a deployment
    can run with only the subset it has keys for.
    """
    env = env if env is not None else os.environ
    configs: Dict[str, ProviderConfig] = {}

    huntio_token = _get(env, "HUNTIO_API_TOKEN")
    if huntio_token:
        configs["huntio"] = ProviderConfig(
            name="huntio",
            base_url=_get(env, "HUNTIO_BASE_URL") or "https://api.hunt.io/v1",
            token=Secret(huntio_token, "huntio-token"),
            rate_per_sec=float(_get(env, "HUNTIO_RATE") or 5.0),
        )

    hkey = _get(env, "HUNTRESS_API_KEY")
    hsec = _get(env, "HUNTRESS_API_SECRET")
    if hkey and hsec:
        configs["huntress"] = ProviderConfig(
            name="huntress",
            base_url=_get(env, "HUNTRESS_BASE_URL") or "https://api.huntress.io/v1",
            basic_user=Secret(hkey, "huntress-key"),
            basic_pass=Secret(hsec, "huntress-secret"),
            rate_per_sec=float(_get(env, "HUNTRESS_RATE") or 5.0),
        )

    return configs
