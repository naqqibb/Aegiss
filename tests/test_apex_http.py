import os, sys, random, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from apex.http import HttpClient, HttpRequest, HttpResponse
from apex.ratelimit import TokenBucket
from apex.security import Secret
from apex.errors import AuthError, RateLimitError, TransportError


class TestTokenBucket(unittest.TestCase):
    def test_blocks_when_empty(self):
        t = [0.0]
        tb = TokenBucket(rate=2, capacity=2,
                         clock=lambda: t[0], sleep=lambda d: t.__setitem__(0, t[0] + d))
        self.assertEqual(tb.acquire(), 0.0)
        self.assertEqual(tb.acquire(), 0.0)
        self.assertAlmostEqual(tb.acquire(), 0.5)  # 1 token / 2 per sec

    def test_rejects_impossible_request(self):
        with self.assertRaises(ValueError):
            TokenBucket(rate=1, capacity=1).acquire(5)

    def test_positive_rate_required(self):
        with self.assertRaises(ValueError):
            TokenBucket(rate=0)


class TestHttpClient(unittest.TestCase):
    def client(self, transport, **kw):
        kw.setdefault("sleep", lambda d: None)
        kw.setdefault("rate_per_sec", 1000)
        kw.setdefault("rng", random.Random(1))
        return HttpClient(transport, **kw)

    def test_success_passthrough(self):
        c = self.client(lambda req: HttpResponse(200, {}, b"ok"))
        self.assertEqual(c.get("https://x/y", {}, 5).body, b"ok")

    def test_retries_5xx_then_succeeds(self):
        n = {"i": 0}
        def t(req):
            n["i"] += 1
            return HttpResponse(503, {"Retry-After": "0"}, b"") if n["i"] < 3 else HttpResponse(200, {}, b"ok")
        c = self.client(t, max_retries=3)
        self.assertEqual(c.get("https://x/y", {}, 5).status, 200)
        self.assertEqual(n["i"], 3)

    def test_auth_error_not_retried(self):
        n = {"i": 0}
        def t(req):
            n["i"] += 1
            return HttpResponse(401, {}, b"")
        c = self.client(t, max_retries=5)
        with self.assertRaises(AuthError):
            c.get("https://x/y", {}, 5)
        self.assertEqual(n["i"], 1)  # never retried

    def test_rate_limit_exhausted(self):
        c = self.client(lambda req: HttpResponse(429, {"Retry-After": "0"}, b""), max_retries=2)
        with self.assertRaises(RateLimitError) as ctx:
            c.get("https://x/y", {}, 5)
        self.assertEqual(ctx.exception.retry_after, 0.0)

    def test_transport_error_retries_then_raises(self):
        def t(req):
            raise TransportError("boom")
        c = self.client(t, max_retries=2)
        with self.assertRaises(TransportError):
            c.get("https://x/y", {}, 5)

    def test_secret_redacted_in_error(self):
        s = Secret("supersecrettoken123")
        def t(req):
            return HttpResponse(401, {}, b"")
        c = self.client(t, secrets=[s])
        try:
            # url carries the secret; error must not
            c.get("https://x/supersecrettoken123", {}, 5)
            self.fail("expected AuthError")
        except AuthError as e:
            self.assertNotIn("supersecrettoken123", str(e))

    def test_non_idempotent_not_retried(self):
        n = {"i": 0}
        def t(req):
            n["i"] += 1
            return HttpResponse(503, {"Retry-After": "0"}, b"")
        c = self.client(t, max_retries=3)
        with self.assertRaises(TransportError):
            c.request(HttpRequest("POST", "https://x/y", {}, None, 5))
        self.assertEqual(n["i"], 1)  # POST not retried


if __name__ == "__main__":
    unittest.main()
