"""hunt.io provider — the C2 Feed of malicious infrastructure.

API: https://apidocs.hunt.io/docs/c2-feed
- Base URL:  https://api.hunt.io/v1
- Endpoint:  GET /feeds/c2
- Auth:      request header ``token: <API_TOKEN>``
- Payload:   NDJSON (one JSON object per line), optionally gzip-compressed.

The parser is deliberately tolerant: unknown or malformed lines are skipped so a
single bad record never aborts an ingest.
"""

from __future__ import annotations

import gzip
import json
from typing import Any, Dict, Iterator, Optional

from ..models import (
    Confidence, Indicator, IndicatorType, Severity, classify_indicator,
    parse_timestamp,
)
from .base import Provider


def _maybe_gunzip(body: bytes) -> bytes:
    if len(body) >= 2 and body[0] == 0x1F and body[1] == 0x8B:
        try:
            return gzip.decompress(body)
        except OSError:
            return body
    return body


class HuntIoProvider(Provider):
    name = "huntio"
    supports_indicators = True

    def _auth_headers(self) -> Dict[str, str]:
        token = self.config.require_token()
        return {
            "token": token.reveal(),
            "Accept": "application/x-ndjson",
            "User-Agent": "Aegis-APEX/1.0",
        }

    def fetch_indicators(self, *, limit: Optional[int] = None) -> Iterator[Indicator]:
        url = f"{self.config.base_url.rstrip('/')}/feeds/c2"
        resp = self.client.get(url, self._auth_headers(), self.config.timeout)
        payload = _maybe_gunzip(resp.body).decode("utf-8", errors="replace")

        count = 0
        for line in payload.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue  # skip malformed record, keep ingesting
            if not isinstance(record, dict):
                continue
            indicator = self._to_indicator(record)
            if indicator is None:
                continue
            yield indicator
            count += 1
            if limit is not None and count >= limit:
                return

    def _to_indicator(self, rec: Dict[str, Any]) -> Optional[Indicator]:
        # hunt.io C2 records key the host under 'ip' (sometimes 'domain'/'host').
        value = (
            rec.get("ip") or rec.get("domain") or rec.get("host")
            or rec.get("hostname") or rec.get("indicator")
        )
        if not isinstance(value, str) or not value.strip():
            return None
        itype = classify_indicator(value)
        malware = rec.get("malware") or rec.get("malware_family") or rec.get("family")
        try:
            return Indicator(
                type=itype,
                value=value.strip(),
                source=self.name,
                confidence=Confidence.from_score(rec.get("confidence")),
                severity=Severity.HIGH,  # active C2 is high severity by default
                first_seen=parse_timestamp(rec.get("first_seen") or rec.get("seen_first")),
                last_seen=parse_timestamp(rec.get("last_seen") or rec.get("seen_last")),
                malware=malware if isinstance(malware, str) else None,
                actor=rec.get("actor") if isinstance(rec.get("actor"), str) else None,
                tags=[t for t in rec.get("tags", []) if isinstance(t, str)],
                raw=rec,
            )
        except (ValueError, TypeError):
            return None
