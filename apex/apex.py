"""The APEX orchestrator.

Binds provider configs to a shared, rate-limited HTTP stack, pulls from every
configured provider, and normalises the union into a single
:class:`AggregatedFeed` — de-duplicating indicators across providers so the same
IP reported by hunt.io and Huntress collapses to one enriched record.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List, Mapping, Optional

from .config import ProviderConfig, load_config
from .http import HttpClient
from .models import IncidentReport, Indicator, IndicatorType
from .providers import HuntIoProvider, HuntressProvider, Provider
from .security import Secret

# Registry mapping a config name to its provider implementation.
_PROVIDERS = {
    "huntio": HuntIoProvider,
    "huntress": HuntressProvider,
}


@dataclass
class AggregatedFeed:
    """The normalised, de-duplicated output of an APEX collection run."""

    indicators: List[Indicator] = field(default_factory=list)
    incidents: List[IncidentReport] = field(default_factory=list)
    errors: Dict[str, str] = field(default_factory=dict)

    def by_type(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for ind in self.indicators:
            counts[ind.type.value] = counts.get(ind.type.value, 0) + 1
        return counts

    def stats(self) -> Dict[str, object]:
        return {
            "indicators": len(self.indicators),
            "incidents": len(self.incidents),
            "by_type": self.by_type(),
            "errors": dict(self.errors),
        }

    def to_json(self, indent: Optional[int] = 2) -> str:
        return json.dumps({
            "indicators": [i.as_dict() for i in self.indicators],
            "incidents": [r.as_dict() for r in self.incidents],
            "stats": self.stats(),
        }, indent=indent, sort_keys=True)


class ApexModule:
    """Top-level entry point: build from env, collect, aggregate."""

    def __init__(
        self,
        configs: Mapping[str, ProviderConfig],
        *,
        client_factory=None,
    ) -> None:
        self._configs = dict(configs)
        self.providers: Dict[str, Provider] = {}
        self._client_factory = client_factory or self._default_client
        self._build()

    # -- construction -------------------------------------------------------

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None, **kwargs) -> "ApexModule":
        return cls(load_config(env), **kwargs)

    @staticmethod
    def _secrets_of(cfg: ProviderConfig) -> List[Secret]:
        return [s for s in (cfg.token, cfg.basic_user, cfg.basic_pass) if s is not None]

    def _default_client(self, cfg: ProviderConfig) -> HttpClient:
        return HttpClient(
            rate_per_sec=cfg.rate_per_sec,
            max_retries=cfg.max_retries,
            secrets=self._secrets_of(cfg),
        )

    def _build(self) -> None:
        for name, cfg in self._configs.items():
            impl = _PROVIDERS.get(name)
            if impl is None:
                continue
            self.providers[name] = impl(cfg, self._client_factory(cfg))

    # -- collection ---------------------------------------------------------

    def collect(
        self,
        *,
        indicator_limit: Optional[int] = None,
        incident_limit: Optional[int] = None,
    ) -> AggregatedFeed:
        """Run every configured provider and return a de-duplicated feed.

        A failing provider is isolated: its error is recorded in
        ``feed.errors`` and the other providers still contribute.
        """
        feed = AggregatedFeed()
        dedup: Dict[str, Indicator] = {}

        for name, provider in self.providers.items():
            try:
                if provider.supports_indicators:
                    for ind in provider.fetch_indicators(limit=indicator_limit):
                        self._merge_indicator(dedup, ind)
                if provider.supports_incidents:
                    for rep in provider.fetch_incidents(limit=incident_limit):
                        feed.incidents.append(rep)
                        for ind in rep.indicators:
                            self._merge_indicator(dedup, ind)
            except Exception as exc:  # provider isolation
                feed.errors[name] = type(exc).__name__ + ": " + str(exc)

        feed.indicators = sorted(
            dedup.values(),
            key=lambda i: (-int(i.severity), -int(i.confidence), i.value),
        )
        return feed

    @staticmethod
    def _merge_indicator(dedup: Dict[str, Indicator], ind: Indicator) -> None:
        existing = dedup.get(ind.key)
        if existing is None:
            dedup[ind.key] = ind
            return
        # Merge: keep the strongest signal, union tags/sources.
        if int(ind.confidence) > int(existing.confidence):
            existing.confidence = ind.confidence
        if int(ind.severity) > int(existing.severity):
            existing.severity = ind.severity
        existing.malware = existing.malware or ind.malware
        existing.actor = existing.actor or ind.actor
        for tag in ind.tags:
            if tag not in existing.tags:
                existing.tags.append(tag)
        srcs = set(existing.source.split("+")) | {ind.source}
        existing.source = "+".join(sorted(srcs))
        if ind.last_seen and (not existing.last_seen or ind.last_seen > existing.last_seen):
            existing.last_seen = ind.last_seen
