import os, sys, gzip, json, io, contextlib, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from apex import ApexModule
from apex.apex import AggregatedFeed
from apex.config import ProviderConfig
from apex.security import Secret
from apex.http import HttpClient, HttpResponse
from apex.models import Indicator, IndicatorType, Severity, Confidence
from apex.cli import main, cmd_demo, cmd_status


def factory(name_to_body):
    def make(cfg: ProviderConfig) -> HttpClient:
        body = name_to_body[cfg.name]
        return HttpClient(lambda req: HttpResponse(200, {}, body), sleep=lambda d: None)
    return make


class TestAggregation(unittest.TestCase):
    def configs(self):
        return {
            "huntio": ProviderConfig("huntio", "https://api.hunt.io/v1", token=Secret("t1234", "t")),
            "huntress": ProviderConfig("huntress", "https://api.huntress.io/v1",
                                       basic_user=Secret("k", "u"), basic_pass=Secret("s", "p")),
        }

    def test_cross_provider_dedup(self):
        huntio_body = gzip.compress(b'{"ip":"185.234.72.10","malware":"CobaltStrike","confidence":95}\n')
        huntress_body = json.dumps({"pagination": {"next_page": None}, "incident_reports": [
            {"id": 1, "severity": "critical", "status": "sent", "summary": "S",
             "indicators": ["185.234.72.10"]}]}).encode()
        apex = ApexModule(self.configs(),
                          client_factory=factory({"huntio": huntio_body, "huntress": huntress_body}))
        feed = apex.collect()
        # same IP from both -> one indicator, merged source, strongest signal
        matches = [i for i in feed.indicators if i.value == "185.234.72.10"]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].source, "huntio+huntress")
        self.assertEqual(matches[0].confidence, Confidence.CONFIRMED)
        self.assertEqual(matches[0].severity, Severity.CRITICAL)
        self.assertEqual(matches[0].malware, "CobaltStrike")

    def test_provider_isolation_on_error(self):
        # huntress returns invalid JSON -> its error is recorded, huntio still works
        huntio_body = gzip.compress(b'{"ip":"1.2.3.4"}\n')
        apex = ApexModule(self.configs(),
                          client_factory=factory({"huntio": huntio_body, "huntress": b"NOT JSON"}))
        feed = apex.collect()
        self.assertTrue(any(i.value == "1.2.3.4" for i in feed.indicators))
        self.assertIn("huntress", feed.errors)

    def test_from_env_builds_providers(self):
        apex = ApexModule.from_env({"HUNTIO_API_TOKEN": "tok12345"})
        self.assertIn("huntio", apex.providers)
        self.assertNotIn("huntress", apex.providers)

    def test_empty_env_no_providers(self):
        self.assertEqual(ApexModule.from_env({}).providers, {})


class TestFeed(unittest.TestCase):
    def test_stats_and_json(self):
        feed = AggregatedFeed(indicators=[
            Indicator(IndicatorType.IPV4, "1.1.1.1", "huntio"),
            Indicator(IndicatorType.DOMAIN, "a.b", "huntio"),
        ])
        self.assertEqual(feed.by_type(), {"ipv4": 1, "domain": 1})
        payload = json.loads(feed.to_json())
        self.assertEqual(payload["stats"]["indicators"], 2)


class TestCli(unittest.TestCase):
    def _quiet(self, fn, *a):
        with contextlib.redirect_stdout(io.StringIO()):
            return fn(*a)

    def test_status_no_config(self):
        self.assertEqual(self._quiet(cmd_status, {}), 0)

    def test_demo_runs(self):
        self.assertEqual(self._quiet(cmd_demo), 0)

    def test_main_default_status(self):
        self.assertEqual(self._quiet(main, ["--status"]), 0)

    def test_main_demo(self):
        self.assertEqual(self._quiet(main, ["--demo"]), 0)


if __name__ == "__main__":
    unittest.main()
