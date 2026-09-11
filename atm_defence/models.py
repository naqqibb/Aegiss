"""Core data models for the ATM defence system.

All models are lightweight, immutable-ish dataclasses. Times are UNIX epoch
seconds (float) to keep the engine timezone-agnostic and easy to test.
"""

from __future__ import annotations

import enum
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional


class Severity(enum.IntEnum):
    """Ordered alert severity; higher is worse."""

    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


class TxnType(enum.Enum):
    WITHDRAWAL = "withdrawal"
    BALANCE = "balance"
    DEPOSIT = "deposit"
    TRANSFER = "transfer"
    PIN_CHANGE = "pin_change"


@dataclass(frozen=True)
class ATM:
    """A physical ATM terminal."""

    atm_id: str
    lat: float
    lon: float
    branch: str = ""
    # Operating hours as (open_hour, close_hour) in 24h local time.
    # (0, 24) means always open.
    open_hour: int = 0
    close_hour: int = 24


@dataclass(frozen=True)
class Transaction:
    """A single card transaction observed at an ATM."""

    card_id: str
    atm_id: str
    amount: float
    txn_type: TxnType = TxnType.WITHDRAWAL
    ts: float = field(default_factory=time.time)
    pin_attempts: int = 1
    approved: bool = True
    txn_id: str = field(default_factory=lambda: uuid.uuid4().hex)


@dataclass(frozen=True)
class TamperEvent:
    """A physical sensor reading from an ATM chassis."""

    atm_id: str
    kind: str  # e.g. "card_reader", "chassis", "vibration", "camera_block"
    value: float  # normalised 0..1 reading; higher is more anomalous
    ts: float = field(default_factory=time.time)


@dataclass(frozen=True)
class Alert:
    """An explainable detection result."""

    rule: str
    severity: Severity
    message: str
    card_id: Optional[str] = None
    atm_id: Optional[str] = None
    ts: float = field(default_factory=time.time)
    alert_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def as_line(self) -> str:
        who = self.card_id or "-"
        where = self.atm_id or "-"
        return f"[{self.severity.name:8}] {self.rule:22} card={who} atm={where} :: {self.message}"
