import os, sys, ssl, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from apex.security import Secret, redact, hardened_ssl_context
from apex.config import load_config, ProviderConfig
from apex.errors import ConfigError


class TestSecret(unittest.TestCase):
    def test_never_reveals_in_repr_or_str(self):
        s = Secret("hunter2-very-secret", "pw")
        self.assertNotIn("hunter2", repr(s))
        self.assertNotIn("hunter2", str(s))
        self.assertNotIn("hunter2", f"{s}")
        self.assertIn("REDACTED", repr(s))

    def test_reveal_returns_value(self):
        self.assertEqual(Secret("abc").reveal(), "abc")

    def test_constant_time_equality(self):
        s = Secret("token-value-1234")
        self.assertTrue(s == "token-value-1234")
        self.assertFalse(s == "wrong")
        self.assertTrue(s == Secret("token-value-1234"))

    def test_type_validation(self):
        with self.assertRaises(TypeError):
            Secret(1234)  # type: ignore

    def test_hash_does_not_expose_value(self):
        s = Secret("secretvalue")
        # hashable (usable in sets) and hash isn't the raw value's hash
        self.assertIn(s, {s})
        self.assertNotEqual(hash(s), hash("secretvalue"))


class TestRedact(unittest.TestCase):
    def test_masks_secret_in_text(self):
        s = Secret("api-token-abcdef")
        out = redact("Authorization: token api-token-abcdef", [s])
        self.assertNotIn("api-token-abcdef", out)
        self.assertIn("REDACTED", out)

    def test_skips_short_values(self):
        out = redact("value ab here", ["ab"])  # too short to mask safely
        self.assertIn("ab", out)

    def test_accepts_plain_strings(self):
        self.assertNotIn("longsecretkey", redact("x longsecretkey y", ["longsecretkey"]))


class TestTLS(unittest.TestCase):
    def test_verification_enforced(self):
        ctx = hardened_ssl_context()
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)


class TestConfig(unittest.TestCase):
    def test_loads_only_present_providers(self):
        cfgs = load_config({"HUNTIO_API_TOKEN": "tok12345"})
        self.assertIn("huntio", cfgs)
        self.assertNotIn("huntress", cfgs)

    def test_huntress_needs_both_key_and_secret(self):
        cfgs = load_config({"HUNTRESS_API_KEY": "k"})  # secret missing
        self.assertNotIn("huntress", cfgs)

    def test_empty_env_yields_nothing(self):
        self.assertEqual(load_config({}), {})

    def test_require_token_raises_when_absent(self):
        cfg = ProviderConfig("x", "https://x")
        with self.assertRaises(ConfigError):
            cfg.require_token()

    def test_secrets_wrapped(self):
        cfgs = load_config({"HUNTIO_API_TOKEN": "tok12345"})
        self.assertIsInstance(cfgs["huntio"].token, Secret)


if __name__ == "__main__":
    unittest.main()
