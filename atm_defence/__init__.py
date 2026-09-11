"""
ATM Defence Systems
===================

A defensive monitoring toolkit for Automated Teller Machine (ATM) networks.

Provides real-time fraud/anomaly detection over transaction streams,
physical tamper/skimmer signal monitoring, and structured alerting.

Design goals
------------
- Pure standard library (no external dependencies).
- Deterministic, testable rule engine.
- Explainable alerts: every alert names the rule that fired and why.

This is a *defensive* tool: it detects and reports suspicious activity so an
operator can respond. It performs no offensive action and stores no PII beyond
opaque identifiers supplied by the caller.
"""

from .models import ATM, Transaction, TamperEvent, Alert, Severity, TxnType
from .engine import DefenceEngine
from .tamper import TamperMonitor
from .alerting import AlertBus, ConsoleSink, MemorySink

__all__ = [
    "ATM",
    "Transaction",
    "TamperEvent",
    "Alert",
    "Severity",
    "TxnType",
    "DefenceEngine",
    "TamperMonitor",
    "AlertBus",
    "ConsoleSink",
    "MemorySink",
]

__version__ = "1.0.0"
