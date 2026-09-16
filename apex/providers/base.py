"""Abstract provider interface for APEX.

A provider wraps one vendor API and yields normalised
:class:`~apex.models.Indicator` / :class:`~apex.models.IncidentReport` objects.
Concrete providers implement only the capabilities their vendor exposes;
unsupported calls raise ``NotImplementedError`` and the orchestrator skips them.
"""

from __future__ import annotations

import abc
from typing import Iterator, List

from ..config import ProviderConfig
from ..http import HttpClient
from ..models import IncidentReport, Indicator


class Provider(abc.ABC):
    #: short, stable provider identifier (also used as Indicator.source)
    name: str = "provider"

    def __init__(self, config: ProviderConfig, client: HttpClient) -> None:
        self.config = config
        self.client = client

    # Capability flags — the orchestrator consults these before calling.
    supports_indicators: bool = False
    supports_incidents: bool = False

    def fetch_indicators(self, *, limit: int | None = None) -> Iterator[Indicator]:
        raise NotImplementedError(f"{self.name} does not provide indicators")

    def fetch_incidents(self, *, limit: int | None = None) -> Iterator[IncidentReport]:
        raise NotImplementedError(f"{self.name} does not provide incidents")

    # -- helpers shared by concrete providers ------------------------------

    def _auth_headers(self) -> dict:  # overridden per provider
        return {}

    def collect_indicators(self, *, limit: int | None = None) -> List[Indicator]:
        return list(self.fetch_indicators(limit=limit))
