"""Threat intelligence tests: validation, normalization, expiry, import/export."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from core.database import ASEDatabase
from core.event_bus import EventBus
from core.exceptions import ASEIntelligenceError
from modules.intelligence import ASEIntelligence


class NormalizationTests(unittest.TestCase):
    def test_ip_normalized(self):
        self.assertEqual(ASEIntelligence.normalize(" 8.8.8.8 ", "ip"), "8.8.8.8")
        self.assertEqual(ASEIntelligence.normalize("::1", "ip"), "::1")

    def test_invalid_ip_rejected(self):
        for value in ("999.1.1.1", "not-an-ip", "8.8.8", ""):
            with self.assertRaises(ASEIntelligenceError):
                ASEIntelligence.normalize(value, "ip")

    def test_domain_normalized_and_validated(self):
        self.assertEqual(ASEIntelligence.normalize("Example.COM.", "domain"), "example.com")
        for value in ("no-tld", "-bad.com", "bad-.com", "a..b.com"):
            with self.assertRaises(ASEIntelligenceError):
                ASEIntelligence.normalize(value, "domain")

    def test_sha256_validated(self):
        digest = "a" * 64
        self.assertEqual(ASEIntelligence.normalize(digest.upper(), "sha256"), digest)
        with self.assertRaises(ASEIntelligenceError):
            ASEIntelligence.normalize("a" * 63, "sha256")
        with self.assertRaises(ASEIntelligenceError):
            ASEIntelligence.normalize("z" * 64, "sha256")

    def test_unsupported_type_rejected(self):
        with self.assertRaises(ASEIntelligenceError):
            ASEIntelligence.normalize("x", "url")

    def test_classify(self):
        engine = ASEIntelligence(EventBus())
        self.assertEqual(engine.classify("1.2.3.4"), "ip")
        self.assertEqual(engine.classify("example.com"), "domain")
        self.assertEqual(engine.classify("a" * 64), "sha256")
        with self.assertRaises(ASEIntelligenceError):
            engine.classify("!!! not valid !!!")


class IntelligenceStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = ASEDatabase(Path(self.temp.name) / "db.sqlite")
        self.db.start()
        self.engine = ASEIntelligence(EventBus(), self.db)
        self.engine.start()

    def tearDown(self):
        self.db.stop()
        self.temp.cleanup()

    def test_add_and_check(self):
        self.engine.add_indicator("198.51.100.7", "ip", "unit", "test")
        self.assertTrue(self.engine.check_indicator("198.51.100.7")["found"])

    def test_duplicate_prevents_duplication(self):
        self.engine.add_indicator("198.51.100.7", "ip", "first")
        self.engine.add_indicator("198.51.100.7", "ip", "second", confidence=80)
        indicators = self.engine.list_indicators()
        self.assertEqual(len(indicators), 1)
        self.assertEqual(indicators[0]["source"], "second")

    def test_confidence_clamped(self):
        result = self.engine.add_indicator("1.1.1.1", "ip", confidence=500)
        self.assertEqual(result["confidence"], 100)
        result = self.engine.add_indicator("1.1.1.2", "ip", confidence=-20)
        self.assertEqual(result["confidence"], 0)

    def test_expiry_removes_indicator(self):
        self.engine.add_indicator("1.1.1.1", "ip", ttl_days=0)
        self.engine.indicators["1.1.1.1"]["expires_at"] = "2000-01-01T00:00:00+00:00"
        result = self.engine.check_indicator("1.1.1.1")
        self.assertFalse(result["found"])
        self.assertTrue(result.get("expired"))

    def test_persistence_across_reload(self):
        self.engine.add_indicator("203.0.113.5", "ip", "persist")
        reloaded = ASEIntelligence(EventBus(), self.db)
        reloaded.start()
        self.assertTrue(reloaded.check_indicator("203.0.113.5")["found"])

    def test_remove_indicator(self):
        self.engine.add_indicator("203.0.113.6", "ip")
        self.assertTrue(self.engine.remove_indicator("203.0.113.6"))
        self.assertFalse(self.engine.check_indicator("203.0.113.6")["found"])

    def test_capacity_limit(self):
        self.engine.max_indicators = 2
        self.engine.add_indicator("1.1.1.1", "ip")
        self.engine.add_indicator("1.1.1.2", "ip")
        with self.assertRaises(ASEIntelligenceError):
            self.engine.add_indicator("1.1.1.3", "ip")

    def test_statistics(self):
        self.engine.add_indicator("1.1.1.1", "ip", "a")
        self.engine.add_indicator("example.com", "domain", "b")
        stats = self.engine.statistics()
        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["by_type"]["ip"], 1)

    def test_export_and_import_round_trip(self):
        self.engine.add_indicator("1.1.1.1", "ip", "export-test")
        target = Path(self.temp.name) / "export.json"
        result = self.engine.export_indicators(target)
        self.assertEqual(result["count"], 1)
        payload = json.loads(target.read_text("utf-8"))
        self.assertEqual(len(payload["indicators"]), 1)

        other = ASEIntelligence(EventBus(), self.db)
        other.start()
        other.remove_indicator("1.1.1.1")
        imported = other.import_indicators(target)
        self.assertEqual(imported["added"], 1)
        self.assertTrue(other.check_indicator("1.1.1.1")["found"])

    def test_unsigned_import_refused_when_signature_required(self):
        target = Path(self.temp.name) / "plain.json"
        target.write_text(json.dumps({"indicators": []}), "utf-8")
        with self.assertRaises(ASEIntelligenceError):
            self.engine.import_indicators(target, require_signed=True)

    def test_import_skips_invalid_entries(self):
        target = Path(self.temp.name) / "mixed.json"
        target.write_text(json.dumps([
            {"indicator": "1.1.1.1", "type": "ip"},
            {"indicator": "bad ip value", "type": "ip"},
        ]), "utf-8")
        result = self.engine.import_indicators(target)
        self.assertEqual(result["added"], 1)
        self.assertEqual(result["rejected"], 1)

    def test_purge_expired(self):
        self.engine.add_indicator("1.1.1.1", "ip")
        self.engine.indicators["1.1.1.1"]["expires_at"] = "2000-01-01T00:00:00+00:00"
        self.db.add_indicator("1.1.1.1", "ip", expires_at="2000-01-01T00:00:00+00:00")
        removed = self.engine.purge_expired()
        self.assertEqual(removed, 1)


if __name__ == "__main__":
    unittest.main()
