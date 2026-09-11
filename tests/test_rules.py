"""Unit tests for individual detection rules."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from atm_defence.models import ATM, Severity, Transaction, TxnType
from atm_defence.rules import (
    BlacklistRule, DailyCapRule, HighAmountRule, ImpossibleTravelRule,
    OffHoursRule, PinRetryRule, RuleContext, VelocityRule, haversine_km,
)

KL = ATM("KL-001", 3.1390, 101.6869)
JB = ATM("JB-207", 1.4927, 103.7414)
NIGHT = ATM("PJ-014", 2.9, 101.7, open_hour=6, close_hour=22)
ATMS = {a.atm_id: a for a in (KL, JB, NIGHT)}


def ctx(history=(), card_bl=frozenset(), atm_bl=frozenset()):
    return RuleContext(ATMS, list(history), set(card_bl), set(atm_bl))


class TestHelpers(unittest.TestCase):
    def test_haversine_kl_to_jb(self):
        d = haversine_km(KL.lat, KL.lon, JB.lat, JB.lon)
        self.assertTrue(280 < d < 330, f"unexpected distance {d}")

    def test_haversine_zero(self):
        self.assertAlmostEqual(haversine_km(1, 2, 1, 2), 0.0)


class TestBlacklist(unittest.TestCase):
    def test_card_blacklist_is_critical(self):
        a = BlacklistRule().evaluate(Transaction("bad", "KL-001", 10), ctx(card_bl={"bad"}))
        self.assertIsNotNone(a)
        self.assertEqual(a.severity, Severity.CRITICAL)

    def test_atm_blacklist(self):
        a = BlacklistRule().evaluate(Transaction("c", "KL-001", 10), ctx(atm_bl={"KL-001"}))
        self.assertEqual(a.severity, Severity.HIGH)

    def test_clean(self):
        self.assertIsNone(BlacklistRule().evaluate(Transaction("c", "KL-001", 10), ctx()))


class TestHighAmount(unittest.TestCase):
    def test_below_threshold(self):
        self.assertIsNone(HighAmountRule(2000).evaluate(Transaction("c", "KL-001", 1999), ctx()))

    def test_at_threshold_medium(self):
        a = HighAmountRule(2000).evaluate(Transaction("c", "KL-001", 2000), ctx())
        self.assertEqual(a.severity, Severity.MEDIUM)

    def test_double_threshold_high(self):
        a = HighAmountRule(2000).evaluate(Transaction("c", "KL-001", 4000), ctx())
        self.assertEqual(a.severity, Severity.HIGH)

    def test_balance_check_ignored(self):
        t = Transaction("c", "KL-001", 9999, TxnType.BALANCE)
        self.assertIsNone(HighAmountRule(2000).evaluate(t, ctx()))


class TestVelocity(unittest.TestCase):
    def test_fires_over_limit(self):
        hist = [Transaction("c", "KL-001", 10, ts=t) for t in (0, 30, 60)]
        a = VelocityRule(max_count=3, window_s=300).evaluate(
            Transaction("c", "KL-001", 10, ts=90), ctx(hist))
        self.assertEqual(a.severity, Severity.HIGH)

    def test_ok_within_limit(self):
        hist = [Transaction("c", "KL-001", 10, ts=0)]
        self.assertIsNone(VelocityRule(3, 300).evaluate(
            Transaction("c", "KL-001", 10, ts=60), ctx(hist)))

    def test_old_txns_outside_window(self):
        hist = [Transaction("c", "KL-001", 10, ts=t) for t in (0, 1, 2)]
        # current at ts=1000 -> old ones fall outside 300s window
        self.assertIsNone(VelocityRule(3, 300).evaluate(
            Transaction("c", "KL-001", 10, ts=1000), ctx(hist)))


class TestDailyCap(unittest.TestCase):
    def test_cap_breach(self):
        hist = [Transaction("c", "KL-001", 3000, ts=0)]
        a = DailyCapRule(cap=5000, window_s=86400).evaluate(
            Transaction("c", "KL-001", 2500, ts=10), ctx(hist))
        self.assertEqual(a.severity, Severity.HIGH)

    def test_deposits_do_not_count(self):
        hist = [Transaction("c", "KL-001", 9000, TxnType.DEPOSIT, ts=0)]
        self.assertIsNone(DailyCapRule(5000, 86400).evaluate(
            Transaction("c", "KL-001", 100, ts=10), ctx(hist)))


class TestImpossibleTravel(unittest.TestCase):
    def test_impossible(self):
        prev = Transaction("c", "KL-001", 10, ts=0)
        # ~300 km in 5 minutes -> ~3600 km/h
        a = ImpossibleTravelRule(max_speed_kmh=900).evaluate(
            Transaction("c", "JB-207", 10, ts=300), ctx([prev]))
        self.assertEqual(a.severity, Severity.CRITICAL)

    def test_plausible_when_slow(self):
        prev = Transaction("c", "KL-001", 10, ts=0)
        # 300 km in 5 hours -> 60 km/h
        self.assertIsNone(ImpossibleTravelRule(900).evaluate(
            Transaction("c", "JB-207", 10, ts=5 * 3600), ctx([prev])))

    def test_same_atm_no_alert(self):
        prev = Transaction("c", "KL-001", 10, ts=0)
        self.assertIsNone(ImpossibleTravelRule(900).evaluate(
            Transaction("c", "KL-001", 10, ts=1), ctx([prev])))

    def test_no_history(self):
        self.assertIsNone(ImpossibleTravelRule(900).evaluate(
            Transaction("c", "JB-207", 10, ts=1), ctx()))


class TestPinRetry(unittest.TestCase):
    def test_over_limit(self):
        a = PinRetryRule(3).evaluate(Transaction("c", "KL-001", 0, pin_attempts=5), ctx())
        self.assertEqual(a.severity, Severity.HIGH)

    def test_ok(self):
        self.assertIsNone(PinRetryRule(3).evaluate(
            Transaction("c", "KL-001", 0, pin_attempts=2), ctx()))


class TestOffHours(unittest.TestCase):
    def test_off_hours(self):
        # ts=1700000000 -> 2023-11-14 22:13 UTC, hour 22, closed (6-22)
        a = OffHoursRule().evaluate(Transaction("c", "PJ-014", 10, ts=1_700_000_000), ctx())
        self.assertEqual(a.severity, Severity.LOW)

    def test_24h_atm_never_fires(self):
        self.assertIsNone(OffHoursRule().evaluate(
            Transaction("c", "KL-001", 10, ts=1_700_000_000), ctx()))


if __name__ == "__main__":
    unittest.main()
