"""Integration tests for the engine, tamper monitor and alert bus."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from atm_defence.alerting import AlertBus, MemorySink
from atm_defence.engine import DefenceEngine
from atm_defence.models import ATM, Alert, Severity, TamperEvent, Transaction, TxnType
from atm_defence.rules import Rule
from atm_defence.tamper import TamperMonitor

KL = ATM("KL-001", 3.1390, 101.6869)
JB = ATM("JB-207", 1.4927, 103.7414)


def build_engine(min_severity=Severity.INFO):
    sink = MemorySink()
    bus = AlertBus(min_severity=min_severity)
    bus.subscribe(sink)
    engine = DefenceEngine(atms=[KL, JB], bus=bus)
    return engine, sink


class TestEngine(unittest.TestCase):
    def test_clean_txn_no_alerts(self):
        engine, sink = build_engine()
        alerts = engine.process(Transaction("c", "KL-001", 100.0, ts=0))
        self.assertEqual(alerts, [])
        self.assertEqual(sink.alerts, [])

    def test_history_ordering_and_travel(self):
        engine, sink = build_engine()
        engine.process(Transaction("c", "KL-001", 100.0, ts=0))
        alerts = engine.process(Transaction("c", "JB-207", 100.0, ts=120))
        rules_fired = {a.rule for a in alerts}
        self.assertIn("impossible_travel", rules_fired)

    def test_blacklist_flow(self):
        engine, sink = build_engine()
        engine.blacklist_card("stolen")
        alerts = engine.process(Transaction("stolen", "KL-001", 10.0, ts=0))
        self.assertTrue(any(a.rule == "blacklist" for a in alerts))

    def test_bus_severity_filter(self):
        engine, sink = build_engine(min_severity=Severity.CRITICAL)
        # High-amount MEDIUM/HIGH should be filtered out of the sink,
        # but still returned by process().
        alerts = engine.process(Transaction("c", "KL-001", 2500.0, ts=0))
        self.assertTrue(any(a.rule == "high_amount" for a in alerts))
        self.assertEqual(sink.alerts, [])  # nothing >= CRITICAL

    def test_broken_rule_is_isolated(self):
        class Boom(Rule):
            name = "boom"
            def evaluate(self, txn, ctx):
                raise RuntimeError("kaboom")

        engine, sink = build_engine()
        engine.rules.insert(0, Boom())
        alerts = engine.process(Transaction("c", "KL-001", 100.0, ts=0))
        self.assertTrue(any(a.rule == "boom" and "kaboom" in a.message for a in alerts))

    def test_process_stream(self):
        engine, sink = build_engine()
        txns = [Transaction("c", "KL-001", 100.0, ts=t) for t in range(0, 200, 30)]
        alerts = engine.process_stream(txns)
        # 7 rapid txns within window -> velocity should fire
        self.assertTrue(any(a.rule == "velocity" for a in alerts))

    def test_history_is_per_card(self):
        engine, sink = build_engine()
        engine.process(Transaction("a", "KL-001", 10.0, ts=0))
        # Different card at JB shortly after must NOT trip impossible travel.
        alerts = engine.process(Transaction("b", "JB-207", 10.0, ts=1))
        self.assertFalse(any(a.rule == "impossible_travel" for a in alerts))


class TestTamperMonitor(unittest.TestCase):
    def test_absolute_trip(self):
        mon = TamperMonitor()
        alert = mon.observe(TamperEvent("KL-001", "card_reader", 0.99))
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, Severity.CRITICAL)

    def test_baseline_then_spike(self):
        mon = TamperMonitor(sensitivity=0.35)
        for _ in range(5):
            self.assertIsNone(mon.observe(TamperEvent("KL-001", "vibration", 0.05)))
        spike = mon.observe(TamperEvent("KL-001", "vibration", 0.6))
        self.assertIsNotNone(spike)
        self.assertEqual(spike.severity, Severity.MEDIUM)

    def test_steady_no_alert(self):
        mon = TamperMonitor()
        alerts = [mon.observe(TamperEvent("KL-001", "vibration", 0.1)) for _ in range(10)]
        self.assertTrue(all(a is None for a in alerts))

    def test_invalid_sensitivity(self):
        with self.assertRaises(ValueError):
            TamperMonitor(sensitivity=0)


class TestAlerting(unittest.TestCase):
    def test_publish_returns_true_when_emitted(self):
        sink = MemorySink()
        bus = AlertBus()
        bus.subscribe(sink)
        self.assertTrue(bus.publish(Alert("r", Severity.HIGH, "m")))
        self.assertEqual(len(sink.alerts), 1)

    def test_publish_filtered(self):
        bus = AlertBus(min_severity=Severity.HIGH)
        self.assertFalse(bus.publish(Alert("r", Severity.LOW, "m")))


if __name__ == "__main__":
    unittest.main()
