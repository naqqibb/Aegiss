"""Provider-agnostic threat-intelligence models.

Every provider normalises its native payload into these types so downstream
Aegis consumers never care which vendor a datum came from. All parsing is
defensive: malformed records are rejected by the provider layer, and these
constructors validate their own invariants.
"""

from __future__ import annotations

import enum
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class IndicatorType(enum.Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    SHA256 = "sha256"
    SHA1 = "sha1"
    MD5 = "md5"
    EMAIL = "email"
    UNKNOWN = "unknown"


class Severity(enum.IntEnum):
    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


class Confidence(enum.IntEnum):
    """Coarse confidence bands (0-100 mapped)."""

    LOW = 25
    MEDIUM = 50
    HIGH = 75
    CONFIRMED = 100

    @classmethod
    def from_score(cls, score: Optional[float]) -> "Confidence":
        if score is None:
            return cls.MEDIUM
        s = max(0.0, min(100.0, float(score)))
        if s >= 90:
            return cls.CONFIRMED
        if s >= 65:
            return cls.HIGH
        if s >= 40:
            return cls.MEDIUM
        return cls.LOW


_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,}$", re.I)
_HASH_RE = {
    IndicatorType.MD5: re.compile(r"^[a-f0-9]{32}$", re.I),
    IndicatorType.SHA1: re.compile(r"^[a-f0-9]{40}$", re.I),
    IndicatorType.SHA256: re.compile(r"^[a-f0-9]{64}$", re.I),
}


def classify_indicator(value: str) -> IndicatorType:
    """Best-effort classification of a raw indicator string."""
    v = value.strip()
    if not v:
        return IndicatorType.UNKNOWN
    # IP addresses
    try:
        ip = ipaddress.ip_address(v)
        return IndicatorType.IPV4 if ip.version == 4 else IndicatorType.IPV6
    except ValueError:
        pass
    if v.lower().startswith(("http://", "https://")):
        return IndicatorType.URL
    for htype, rx in _HASH_RE.items():
        if rx.match(v):
            return htype
    if "@" in v and "." in v.split("@")[-1]:
        return IndicatorType.EMAIL
    if _DOMAIN_RE.match(v):
        return IndicatorType.DOMAIN
    return IndicatorType.UNKNOWN


def _parse_ts(value: Any) -> Optional[datetime]:
    """Parse an ISO-8601 or epoch timestamp into an aware UTC datetime."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        text = value.strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(text)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


@dataclass
class Indicator:
    """A single normalised indicator of compromise."""

    type: IndicatorType
    value: str
    source: str
    confidence: Confidence = Confidence.MEDIUM
    severity: Severity = Severity.MEDIUM
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    malware: Optional[str] = None
    actor: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.value or not isinstance(self.value, str):
            raise ValueError("Indicator.value must be a non-empty string")
        if not isinstance(self.type, IndicatorType):
            raise TypeError("Indicator.type must be an IndicatorType")

    @property
    def key(self) -> str:
        """Stable identity for de-duplication across providers."""
        return f"{self.type.value}:{self.value.lower()}"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type.value,
            "value": self.value,
            "source": self.source,
            "confidence": int(self.confidence),
            "severity": self.severity.name,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "malware": self.malware,
            "actor": self.actor,
            "tags": list(self.tags),
        }


@dataclass
class IncidentReport:
    """A normalised EDR/MDR incident (e.g. from Huntress)."""

    report_id: str
    source: str
    severity: Severity
    status: str
    summary: str
    organization: Optional[str] = None
    agent: Optional[str] = None
    indicators: List[Indicator] = field(default_factory=list)
    created_at: Optional[datetime] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "source": self.source,
            "severity": self.severity.name,
            "status": self.status,
            "summary": self.summary,
            "organization": self.organization,
            "agent": self.agent,
            "indicators": [i.as_dict() for i in self.indicators],
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


def parse_timestamp(value: Any) -> Optional[datetime]:
    """Public re-export used by provider parsers."""
    return _parse_ts(value)
