"""The ATM defence engine.

The engine owns per-card transaction history, an ATM registry and blacklists,
runs every registered rule against each incoming transaction, and publishes any
resulting alerts onto an :class:`AlertBus`.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Deque, Dict, Iterable, List, Optional, Set

from .alerting import AlertBus
from .models import ATM, Alert, Severity, Transaction
from .rules import Rule, RuleContext, default_ruleset


class DefenceEngine:
    """Stateful, rule-driven monitor for a fleet of ATMs."""

    def __init__(
        self,
        atms: Optional[Iterable[ATM]] = None,
        rules: Optional[List[Rule]] = None,
        bus: Optional[AlertBus] = None,
        history_per_card: int = 50,
    ) -> None:
        self.atms: Dict[str, ATM] = {a.atm_id: a for a in (atms or [])}
        self.rules: List[Rule] = rules if rules is not None else default_ruleset()
        self.bus = bus or AlertBus()
        self._history_per_card = history_per_card
        self._history: Dict[str, Deque[Transaction]] = defaultdict(
            lambda: deque(maxlen=self._history_per_card)
        )
        self.card_blacklist: Set[str] = set()
        self.atm_blacklist: Set[str] = set()

    # -- registry management -------------------------------------------------

    def register_atm(self, atm: ATM) -> None:
        self.atms[atm.atm_id] = atm

    def blacklist_card(self, card_id: str) -> None:
        self.card_blacklist.add(card_id)

    def blacklist_atm(self, atm_id: str) -> None:
        self.atm_blacklist.add(atm_id)

    # -- processing ----------------------------------------------------------

    def process(self, txn: Transaction) -> List[Alert]:
        """Evaluate one transaction. Returns all alerts it produced.

        History is kept ordered oldest -> newest per card. The current
        transaction is appended only after evaluation so rules see a clean
        "prior" history.
        """

        history = self._history[txn.card_id]
        ctx = RuleContext(
            atms=self.atms,
            card_history=list(history),
            card_blacklist=self.card_blacklist,
            atm_blacklist=self.atm_blacklist,
        )

        alerts: List[Alert] = []
        for rule in self.rules:
            try:
                alert = rule.evaluate(txn, ctx)
            except Exception as exc:  # a broken rule must not stop the pipeline
                alert = Alert(
                    rule=getattr(rule, "name", "unknown"),
                    severity=Severity.LOW,
                    message=f"rule error: {exc!r}",
                    card_id=txn.card_id,
                    atm_id=txn.atm_id,
                    ts=txn.ts,
                )
            if alert is not None:
                alerts.append(alert)
                self.bus.publish(alert)

        history.append(txn)
        return alerts

    def process_stream(self, txns: Iterable[Transaction]) -> List[Alert]:
        """Process an ordered iterable of transactions; return all alerts."""

        out: List[Alert] = []
        for txn in txns:
            out.extend(self.process(txn))
        return out
