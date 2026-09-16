"""Huntress provider — managed EDR incident reports and agents.

API: https://api.huntress.io/docs
- Base URL:  https://api.huntress.io/v1
- Endpoint:  GET /incident_reports  (paginated)
- Auth:      HTTP Basic — API key as username, API secret as password.
- Payload:   JSON envelope ``{"pagination": {...}, "incident_reports": [...]}``.

Incident severities are mapped onto Aegis' :class:`~apex.models.Severity`, and
any indicator strings the report carries are normalised into
:class:`~apex.models.Indicator` objects.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict, Iterator, List, Optional

from ..errors import ProviderError
from ..models import (
    IncidentReport, Indicator, Severity, classify_indicator, parse_timestamp,
)
from .base import Provider

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}


class HuntressProvider(Provider):
    name = "huntress"
    supports_incidents = True

    def _auth_headers(self) -> Dict[str, str]:
        user, pwd = self.config.require_basic()
        raw = f"{user.reveal()}:{pwd.reveal()}".encode("utf-8")
        token = base64.b64encode(raw).decode("ascii")
        return {
            "Authorization": f"Basic {token}",
            "Accept": "application/json",
            "User-Agent": "Aegis-APEX/1.0",
        }

    def fetch_incidents(self, *, limit: Optional[int] = None) -> Iterator[IncidentReport]:
        base = self.config.base_url.rstrip("/")
        page = 1
        emitted = 0
        page_limit = 50 if limit is None else min(50, limit)
        while True:
            url = f"{base}/incident_reports?page={page}&limit={page_limit}"
            resp = self.client.get(url, self._auth_headers(), self.config.timeout)
            try:
                envelope = json.loads(resp.body.decode("utf-8", errors="replace"))
            except json.JSONDecodeError as exc:
                raise ProviderError(f"huntress: invalid JSON on page {page}: {exc}") from None
            if not isinstance(envelope, dict):
                raise ProviderError("huntress: unexpected response shape")

            reports = envelope.get("incident_reports") or []
            if not isinstance(reports, list):
                raise ProviderError("huntress: 'incident_reports' is not a list")

            for rec in reports:
                if not isinstance(rec, dict):
                    continue
                report = self._to_incident(rec)
                if report is None:
                    continue
                yield report
                emitted += 1
                if limit is not None and emitted >= limit:
                    return

            pagination = envelope.get("pagination") or {}
            next_page = pagination.get("next_page") if isinstance(pagination, dict) else None
            if not next_page or not reports:
                return
            page = int(next_page)

    def _to_incident(self, rec: Dict[str, Any]) -> Optional[IncidentReport]:
        rid = rec.get("id") or rec.get("report_id")
        if rid is None:
            return None
        sev_raw = str(rec.get("severity", "medium")).lower()
        severity = _SEVERITY_MAP.get(sev_raw, Severity.MEDIUM)
        summary = (
            rec.get("summary") or rec.get("subject")
            or rec.get("title") or "Huntress incident report"
        )
        indicators = self._extract_indicators(rec)
        try:
            return IncidentReport(
                report_id=str(rid),
                source=self.name,
                severity=severity,
                status=str(rec.get("status", "unknown")),
                summary=str(summary),
                organization=self._as_str(rec.get("organization_id") or rec.get("organization")),
                agent=self._as_str(rec.get("agent_id") or rec.get("agent")),
                indicators=indicators,
                created_at=parse_timestamp(rec.get("created_at") or rec.get("sent_at")),
                raw=rec,
            )
        except (ValueError, TypeError):
            return None

    def _extract_indicators(self, rec: Dict[str, Any]) -> List[Indicator]:
        out: List[Indicator] = []
        candidates = rec.get("indicators") or rec.get("iocs") or []
        if not isinstance(candidates, list):
            return out
        for c in candidates:
            value = c if isinstance(c, str) else (c.get("value") if isinstance(c, dict) else None)
            if not isinstance(value, str) or not value.strip():
                continue
            try:
                out.append(Indicator(
                    type=classify_indicator(value),
                    value=value.strip(),
                    source=self.name,
                    severity=_SEVERITY_MAP.get(str(rec.get("severity", "")).lower(), Severity.MEDIUM),
                    raw=c if isinstance(c, dict) else {"value": value},
                ))
            except (ValueError, TypeError):
                continue
        return out

    @staticmethod
    def _as_str(v: Any) -> Optional[str]:
        return str(v) if v is not None else None
