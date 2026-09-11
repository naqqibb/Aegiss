"""Command-line demo / simulator for the ATM defence system.

Run a scripted stream of transactions and tamper events through the engine and
print the alerts it raises. Useful for smoke-testing rules and for demos.

    python -m atm_defence.cli
    python -m atm_defence.cli --min-severity HIGH
"""

from __future__ import annotations

import argparse

from .alerting import AlertBus, ConsoleSink
from .engine import DefenceEngine
from .models import ATM, Severity, TamperEvent, Transaction, TxnType
from .tamper import TamperMonitor


def _demo_fleet() -> list[ATM]:
    # A small fleet spanning Kuala Lumpur, Putrajaya and Johor Bahru.
    return [
        ATM("KL-001", 3.1390, 101.6869, branch="Kuala Lumpur HQ"),
        ATM("PJ-014", 2.9264, 101.6964, branch="Putrajaya - Kem. Pertahanan", open_hour=6, close_hour=22),
        ATM("JB-207", 1.4927, 103.7414, branch="Johor Bahru"),
    ]


def run_demo(min_severity: Severity = Severity.INFO) -> int:
    bus = AlertBus(min_severity=min_severity)
    bus.subscribe(ConsoleSink())
    engine = DefenceEngine(atms=_demo_fleet(), bus=bus)
    engine.blacklist_card("CARD-STOLEN-9999")

    tamper = TamperMonitor()
    t0 = 1_700_000_000.0  # fixed base time for deterministic output

    # 1) Normal activity.
    engine.process(Transaction("CARD-ALICE", "KL-001", 200.0, ts=t0))

    # 2) PIN guessing.
    engine.process(Transaction("CARD-BOB", "KL-001", 0.0, TxnType.BALANCE,
                               ts=t0 + 60, pin_attempts=5, approved=False))

    # 3) Impossible travel: KL then JB (~300km) five minutes later.
    engine.process(Transaction("CARD-ALICE", "JB-207", 300.0, ts=t0 + 300))

    # 4) Rapid-fire velocity + daily cap breach.
    for i in range(4):
        engine.process(Transaction("CARD-CAROL", "KL-001", 1800.0, ts=t0 + 400 + i * 30))

    # 5) Blacklisted card.
    engine.process(Transaction("CARD-STOLEN-9999", "PJ-014", 500.0, ts=t0 + 700))

    # 6) Physical tamper on a card reader (skimmer overlay).
    for v in (0.05, 0.04, 0.06, 0.95):
        alert = tamper.observe(TamperEvent("PJ-014", "card_reader", v, ts=t0 + 800))
        if alert:
            bus.publish(alert)

    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="ATM defence system demo")
    parser.add_argument(
        "--min-severity",
        default="INFO",
        choices=[s.name for s in Severity],
        help="only show alerts at or above this severity",
    )
    args = parser.parse_args(argv)
    return run_demo(Severity[args.min_severity])


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
