"""Detection rules for the ATM defence engine.

Each rule inspects an incoming :class:`Transaction` together with recent
history exposed via :class:`RuleContext` and optionally returns an
:class:`Alert`. Rules are pure with respect to the context they are given:
the engine owns and mutates the history, rules only read it.
"""

from __future__ import annotations

import math
from typing import Dict, List, Optional, Sequence, Set

from .models import ATM, Alert, Severity, Transaction, TxnType

# Mean Earth radius in kilometres.
_EARTH_RADIUS_KM = 6371.0088


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two lat/lon points, in kilometres."""

    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * _EARTH_RADIUS_KM * math.asin(math.sqrt(a))


class RuleContext:
    """Read-only view of state that rules use to make decisions."""

    def __init__(
        self,
        atms: Dict[str, ATM],
        card_history: Sequence[Transaction],
        card_blacklist: Set[str],
        atm_blacklist: Set[str],
    ) -> None:
        self.atms = atms
        # History for the current card, oldest -> newest, excluding current txn.
        self.card_history: List[Transaction] = list(card_history)
        self.card_blacklist = card_blacklist
        self.atm_blacklist = atm_blacklist

    def atm(self, atm_id: str) -> Optional[ATM]:
        return self.atms.get(atm_id)

    def recent(self, txn: Transaction, window_s: float) -> List[Transaction]:
        """Transactions for this card within ``window_s`` before ``txn``."""

        lo = txn.ts - window_s
        return [t for t in self.card_history if lo <= t.ts <= txn.ts]


class Rule:
    """Base class for detection rules."""

    name: str = "rule"

    def evaluate(self, txn: Transaction, ctx: RuleContext) -> Optional[Alert]:
        raise NotImplementedError


class BlacklistRule(Rule):
    """Fire when a known-bad card or terminal is involved."""

    name = "blacklist"

    def evaluate(self, txn: Transaction, ctx: RuleContext) -> Optional[Alert]:
        if txn.card_id in ctx.card_blacklist:
            return Alert(self.name, Severity.CRITICAL,
                         "card is on the blacklist", txn.card_id, txn.atm_id, txn.ts)
        if txn.atm_id in ctx.atm_blacklist:
            return Alert(self.name, Severity.HIGH,
                         "transaction at a flagged terminal", txn.card_id, txn.atm_id, txn.ts)
        return None


class HighAmountRule(Rule):
    """Fire on a single withdrawal above a threshold."""

    name = "high_amount"

    def __init__(self, threshold: float = 2000.0) -> None:
        self.threshold = threshold

    def evaluate(self, txn: Transaction, ctx: RuleContext) -> Optional[Alert]:
        if txn.txn_type is TxnType.WITHDRAWAL and txn.amount >= self.threshold:
            sev = Severity.HIGH if txn.amount >= self.threshold * 2 else Severity.MEDIUM
            return Alert(self.name, sev,
                         f"withdrawal of {txn.amount:.2f} >= {self.threshold:.2f}",
                         txn.card_id, txn.atm_id, txn.ts)
        return None


class VelocityRule(Rule):
    """Fire when too many transactions occur in a short window."""

    name = "velocity"

    def __init__(self, max_count: int = 3, window_s: float = 300.0) -> None:
        self.max_count = max_count
        self.window_s = window_s

    def evaluate(self, txn: Transaction, ctx: RuleContext) -> Optional[Alert]:
        recent = ctx.recent(txn, self.window_s)
        count = len(recent) + 1  # include current
        if count > self.max_count:
            return Alert(self.name, Severity.HIGH,
                         f"{count} txns within {int(self.window_s)}s "
                         f"(limit {self.max_count})",
                         txn.card_id, txn.atm_id, txn.ts)
        return None


class DailyCapRule(Rule):
    """Fire when total withdrawn in a rolling window exceeds a cap."""

    name = "daily_cap"

    def __init__(self, cap: float = 5000.0, window_s: float = 86400.0) -> None:
        self.cap = cap
        self.window_s = window_s

    def evaluate(self, txn: Transaction, ctx: RuleContext) -> Optional[Alert]:
        if txn.txn_type is not TxnType.WITHDRAWAL:
            return None
        total = txn.amount + sum(
            t.amount for t in ctx.recent(txn, self.window_s)
            if t.txn_type is TxnType.WITHDRAWAL
        )
        if total > self.cap:
            return Alert(self.name, Severity.HIGH,
                         f"rolling withdrawals {total:.2f} exceed cap {self.cap:.2f}",
                         txn.card_id, txn.atm_id, txn.ts)
        return None


class ImpossibleTravelRule(Rule):
    """Fire when the implied travel speed between two ATMs is impossible."""

    name = "impossible_travel"

    def __init__(self, max_speed_kmh: float = 900.0) -> None:
        # 900 km/h ~ commercial jet cruise; anything faster is physically implausible.
        self.max_speed_kmh = max_speed_kmh

    def evaluate(self, txn: Transaction, ctx: RuleContext) -> Optional[Alert]:
        here = ctx.atm(txn.atm_id)
        if here is None or not ctx.card_history:
            return None
        prev = ctx.card_history[-1]
        there = ctx.atm(prev.atm_id)
        if there is None or prev.atm_id == txn.atm_id:
            return None
        dt_h = (txn.ts - prev.ts) / 3600.0
        if dt_h <= 0:
            return None
        dist = haversine_km(there.lat, there.lon, here.lat, here.lon)
        speed = dist / dt_h
        if speed > self.max_speed_kmh:
            return Alert(self.name, Severity.CRITICAL,
                         f"{dist:.0f} km in {dt_h * 60:.0f} min "
                         f"=> {speed:.0f} km/h between {prev.atm_id} and {txn.atm_id}",
                         txn.card_id, txn.atm_id, txn.ts)
        return None


class PinRetryRule(Rule):
    """Fire on repeated PIN failures indicative of guessing."""

    name = "pin_retry"

    def __init__(self, max_attempts: int = 3) -> None:
        self.max_attempts = max_attempts

    def evaluate(self, txn: Transaction, ctx: RuleContext) -> Optional[Alert]:
        if txn.pin_attempts > self.max_attempts:
            return Alert(self.name, Severity.HIGH,
                         f"{txn.pin_attempts} PIN attempts (limit {self.max_attempts})",
                         txn.card_id, txn.atm_id, txn.ts)
        return None


class OffHoursRule(Rule):
    """Fire on withdrawals outside a terminal's operating hours."""

    name = "off_hours"

    def evaluate(self, txn: Transaction, ctx: RuleContext) -> Optional[Alert]:
        atm = ctx.atm(txn.atm_id)
        if atm is None or (atm.open_hour == 0 and atm.close_hour == 24):
            return None
        import time as _time
        hour = _time.gmtime(txn.ts).tm_hour
        if not (atm.open_hour <= hour < atm.close_hour):
            return Alert(self.name, Severity.LOW,
                         f"activity at {hour:02d}:00 UTC outside "
                         f"{atm.open_hour:02d}-{atm.close_hour:02d}",
                         txn.card_id, txn.atm_id, txn.ts)
        return None


def default_ruleset() -> List[Rule]:
    """A sensible default set of rules for a typical deployment."""

    return [
        BlacklistRule(),
        PinRetryRule(),
        ImpossibleTravelRule(),
        VelocityRule(),
        DailyCapRule(),
        HighAmountRule(),
        OffHoursRule(),
    ]
