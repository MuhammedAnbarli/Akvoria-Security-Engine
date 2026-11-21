"""API security unit tests: allowlist, rate limiting, bearer comparison, key handling."""
from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path

from core.api_security import ASEAPISecurity


class AllowlistTests(unittest.TestCase):
    def setUp(self):
        self.security = ASEAPISecurity(allowed_ips=["127.0.0.1", "::1"])

    def test_loopback_allowed(self):
        self.assertTrue(self.security.check_ip("127.0.0.1"))
        self.assertTrue(self.security.check_ip("::1"))

    def test_external_rejected(self):
        for ip in ("192.0.2.10", "10.0.0.1", "0.0.0.0"):
            self.assertFalse(self.security.check_ip(ip))

    def test_rejected_clients_counted(self):
        self.security.check_ip("203.0.113.1")
        self.assertEqual(self.security.get_health()["rejected_clients"], 1)


class RateLimitTests(unittest.TestCase):
    def test_allows_until_limit_then_blocks(self):
        security = ASEAPISecurity(max_requests=3, window_seconds=60)
        for _ in range(3):
            self.assertTrue(security.check_rate_limit("127.0.0.1"))
        self.assertFalse(security.check_rate_limit("127.0.0.1"))
        self.assertEqual(security.get_health()["blocked_requests"], 1)

    def test_clients_are_tracked_independently(self):
        security = ASEAPISecurity(max_requests=1, window_seconds=60)
        self.assertTrue(security.check_rate_limit("127.0.0.1"))
        self.assertTrue(security.check_rate_limit("::1"))

    def test_window_expiry_allows_new_requests(self):
        security = ASEAPISecurity(max_requests=1, window_seconds=1)
        self.assertTrue(security.check_rate_limit("127.0.0.1"))
        self.assertFalse(security.check_rate_limit("127.0.0.1"))
        import time
        time.sleep(1.1)
        self.assertTrue(security.check_rate_limit("127.0.0.1"))


class AuditTests(unittest.TestCase):
    def test_request_logging(self):
        security = ASEAPISecurity()
        security.log_request("127.0.0.1", "GET", "/api/health", 200)
        history = security.get_request_history()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["status"], 200)

    def test_history_limit_validation(self):
        security = ASEAPISecurity()
        with self.assertRaises(ValueError):
            security.get_request_history(0)
        with self.assertRaises(ValueError):
            security.get_request_history(500)

    def test_long_path_truncated(self):
        security = ASEAPISecurity()
        entry = security.log_request("127.0.0.1", "GET", "/" + "x" * 5000, 200)
        self.assertLessEqual(len(entry["path"]), 200)

    def test_health_snapshot(self):
        security = ASEAPISecurity()
        health = security.get_health()
        self.assertEqual(health["status"], "healthy")
        self.assertIn("window_seconds", health)


class ApiKeyHandlingTests(unittest.TestCase):
    """Key generation, permissions and constant-time comparison."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.previous = os.getcwd()
        os.chdir(self.root)
        (self.root / "config").mkdir()
        (self.root / "config" / "ase.json").write_text('{"api": {"port": 18790}}', "utf-8")

    def tearDown(self):
        os.chdir(self.previous)
        self.temp.cleanup()

    def _engine(self):
        from core.engine import ASEEngine
        return ASEEngine()

    def test_key_generated_with_secure_permissions(self):
        engine = self._engine()
        api = engine.api
        key = api._load_api_key()
        self.assertGreaterEqual(len(key), 32)
        mode = stat.S_IMODE(api.api_key_path.stat().st_mode)
        self.assertEqual(mode, 0o600)

    def test_key_is_stable_between_loads(self):
        engine = self._engine()
        first = engine.api._load_api_key()
        second = engine.api._load_api_key()
        self.assertEqual(first, second)

    def test_authorize_accepts_only_correct_token(self):
        api = self._engine().api
        api._load_api_key()
        self.assertTrue(api.authorize("Bearer " + api.api_key))
        self.assertFalse(api.authorize("Bearer wrong"))
        self.assertFalse(api.authorize("Basic " + api.api_key))
        self.assertFalse(api.authorize(""))
        self.assertFalse(api.authorize(None))

    def test_authorize_handles_missing_key(self):
        api = self._engine().api
        api.api_key = None
        self.assertFalse(api.authorize("Bearer anything"))

    def test_rotate_invalidates_old_key(self):
        api = self._engine().api
        old = api._load_api_key()
        new = api.rotate_api_key()
        self.assertNotEqual(old, new)
        self.assertTrue(api.authorize("Bearer " + new))
        self.assertFalse(api.authorize("Bearer " + old))

    def test_symlink_key_path_rejected(self):
        engine = self._engine()
        target = self.root / "real.key"
        target.write_text("x" * 64, "utf-8")
        link = self.root / "link.key"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        engine.api.api_key_path = link
        with self.assertRaises(RuntimeError):
            engine.api._load_api_key()

    def test_short_existing_key_rejected(self):
        engine = self._engine()
        engine.api.api_key_path.parent.mkdir(parents=True, exist_ok=True)
        engine.api.api_key_path.write_text("short", "utf-8")
        with self.assertRaises(RuntimeError):
            engine.api._load_api_key()

    def test_non_loopback_bind_refused(self):
        (self.root / "config" / "ase.json").write_text(
            '{"api": {"host": "0.0.0.0", "port": 18791}}', "utf-8")
        with self.assertRaises(Exception):
            self._engine()


if __name__ == "__main__":
    unittest.main()
