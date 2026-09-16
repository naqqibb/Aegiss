import os, sys, gzip, json, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from apex.config import ProviderConfig
from apex.security import Secret
from apex.http import HttpClient, HttpResponse
from apex.providers import HuntIoProvider, HuntressProvider
from apex.models import IndicatorType, Severity, Confidence, classify_indicator, parse_timestamp


def static_client(body, headers=None):
    return HttpClient(lambda req: HttpResponse(200, headers or {}, body), sleep=lambda d: None)


class TestModels(unittest.TestCase):
    def test_classification(self):
        self.assertEqual(classify_indicator("8.8.8.8"), IndicatorType.IPV4)
        self.assertEqual(classify_indicator("2001:db8::1"), IndicatorType.IPV6)
        self.assertEqual(classify_indicator("evil.example.com"), IndicatorType.DOMAIN)
        self.assertEqual(classify_indicator("https://x.io/p"), IndicatorType.URL)
        self.assertEqual(classify_indicator("d41d8cd98f00b204e9800998ecf8427e"), IndicatorType.MD5)
        self.assertEqual(classify_indicator("garbage here"), IndicatorType.UNKNOWN)

    def test_confidence_bands(self):
        self.assertEqual(Confidence.from_score(95), Confidence.CONFIRMED)
        self.assertEqual(Confidence.from_score(70), Confidence.HIGH)
        self.assertEqual(Confidence.from_score(None), Confidence.MEDIUM)
        self.assertEqual(Confidence.from_score(5), Confidence.LOW)

    def test_timestamp_parsing(self):
        self.assertIsNotNone(parse_timestamp("2026-09-16T00:00:00Z"))
        self.assertIsNotNone(parse_timestamp(1700000000))
        self.assertIsNone(parse_timestamp("not a date"))


class TestHuntIo(unittest.TestCase):
    def cfg(self):
        return ProviderConfig("huntio", "https://api.hunt.io/v1", token=Secret("tok12345", "t"))

    def test_parses_gzip_ndjson(self):
        body = gzip.compress(
            b'{"ip":"1.2.3.4","malware":"X","confidence":95}\n'
            b'{"domain":"c2.bad.example","malware":"Y"}\n'
        )
        p = HuntIoProvider(self.cfg(), static_client(body, {"Content-Encoding": "gzip"}))
        inds = p.collect_indicators()
        self.assertEqual(len(inds), 2)
        self.assertEqual(inds[0].type, IndicatorType.IPV4)
        self.assertEqual(inds[0].confidence, Confidence.CONFIRMED)

    def test_parses_plain_ndjson(self):
        body = b'{"ip":"9.9.9.9"}\n'
        p = HuntIoProvider(self.cfg(), static_client(body))
        self.assertEqual(p.collect_indicators()[0].value, "9.9.9.9")

    def test_skips_malformed_lines(self):
        body = b'{"ip":"1.1.1.1"}\n{ not json }\n\n{"ip":"2.2.2.2"}\n'
        p = HuntIoProvider(self.cfg(), static_client(body))
        self.assertEqual([i.value for i in p.collect_indicators()], ["1.1.1.1", "2.2.2.2"])

    def test_limit(self):
        body = b"".join(b'{"ip":"1.2.3.%d"}\n' % i for i in range(1, 10))
        p = HuntIoProvider(self.cfg(), static_client(body))
        self.assertEqual(len(p.collect_indicators(limit=3)), 3)

    def test_active_c2_is_high_severity(self):
        p = HuntIoProvider(self.cfg(), static_client(b'{"ip":"5.5.5.5"}\n'))
        self.assertEqual(p.collect_indicators()[0].severity, Severity.HIGH)


class TestHuntress(unittest.TestCase):
    def cfg(self):
        return ProviderConfig("huntress", "https://api.huntress.io/v1",
                              basic_user=Secret("key", "u"), basic_pass=Secret("sec", "p"))

    def paged_client(self, pages):
        state = {"i": 0}
        def t(req):
            i = min(state["i"], len(pages) - 1)
            state["i"] += 1
            return HttpResponse(200, {}, pages[i])
        return HttpClient(t, sleep=lambda d: None)

    def test_pagination_and_mapping(self):
        pages = [
            json.dumps({"pagination": {"next_page": 2}, "incident_reports": [
                {"id": 1, "severity": "high", "status": "sent", "summary": "A",
                 "indicators": ["1.2.3.4"]}]}).encode(),
            json.dumps({"pagination": {"next_page": 3}, "incident_reports": [
                {"id": 2, "severity": "critical", "status": "resolved", "summary": "B"}]}).encode(),
            json.dumps({"pagination": {"next_page": None}, "incident_reports": []}).encode(),
        ]
        p = HuntressProvider(self.cfg(), self.paged_client(pages))
        reps = list(p.fetch_incidents())
        self.assertEqual([r.report_id for r in reps], ["1", "2"])
        self.assertEqual(reps[0].severity, Severity.HIGH)
        self.assertEqual(reps[1].severity, Severity.CRITICAL)
        self.assertEqual(len(reps[0].indicators), 1)

    def test_auth_header_is_basic(self):
        p = HuntressProvider(self.cfg(), self.paged_client([b'{"incident_reports":[]}']))
        headers = p._auth_headers()
        self.assertTrue(headers["Authorization"].startswith("Basic "))

    def test_limit_stops_early(self):
        pages = [json.dumps({"pagination": {"next_page": 2}, "incident_reports": [
            {"id": i, "severity": "low", "status": "x", "summary": "s"} for i in range(10)]}).encode()]
        p = HuntressProvider(self.cfg(), self.paged_client(pages))
        self.assertEqual(len(list(p.fetch_incidents(limit=4))), 4)

    def test_bad_id_skipped(self):
        pages = [json.dumps({"pagination": {"next_page": None}, "incident_reports": [
            {"severity": "low"}, {"id": 7, "severity": "low", "status": "x", "summary": "ok"}]}).encode()]
        p = HuntressProvider(self.cfg(), self.paged_client(pages))
        self.assertEqual([r.report_id for r in p.fetch_incidents()], ["7"])


if __name__ == "__main__":
    unittest.main()
