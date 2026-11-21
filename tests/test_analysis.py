"""Analysis, response and alerting tests: scoring, correlation, dedupe, persistence."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core.database import ASEDatabase
from core.event_bus import EventBus
from modules.analysis import ASEAnalysis, fingerprint, severity_for
from modules.response import ASEResponse


class SeverityTests(unittest.TestCase):
    def test_severity_bands(self):
        self.assertEqual(severity_for(0), "low")
        self.assertEqual(severity_for(35), "medium")
        self.assertEqual(severity_for(60), "high")
        self.assertEqual(severity_for(80), "critical")
        self.assertEqual(severity_for(100), "critical")

    def test_fingerprint_is_stable_and_distinct(self):
        one = {"event_type": "a", "subject": "s", "severity": "high"}
        two = {"event_type": "a", "subject": "s", "severity": "high"}
        three = {"event_type": "a", "subject": "different", "severity": "high"}
        self.assertEqual(fingerprint(one), fingerprint(two))
        self.assertNotEqual(fingerprint(one), fingerprint(three))


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.bus = EventBus()
        self.analysis = ASEAnalysis(self.bus)
        self.analysis.start()

    def tearDown(self):
        self.analysis.stop()

    def test_every_result_has_reasons(self):
        result = self.analysis.analyze_file_change({"file": "/tmp/a"})
        self.assertTrue(result["reasons"])
        self.assertIn("risk_score", result)
        self.assertIn("risk_level", result)

    def test_repeated_changes_escalate(self):
        scores = [self.analysis.analyze_file_change({"file": "same"})["risk_score"]
                  for _ in range(3)]
        self.assertGreater(scores[-1], scores[0])
        self.assertTrue(self.analysis.get_results()[-1]["correlation"]["repeated_changes"])

    def test_network_match_is_high_severity(self):
        result = self.analysis.analyze_network_indicator(
            {"indicator": "198.51.100.7", "remote_address": "198.51.100.7"})
        self.assertGreaterEqual(result["risk_score"], 60)
        self.assertIn(result["risk_level"], ("high", "critical"))
        self.assertTrue(result["requires_review"])

    def test_antivirus_detection_is_critical(self):
        result = self.analysis.analyze_antivirus_detection(
            {"file": "x.com", "status": "malicious_indicator", "explanations": ["EICAR"]})
        self.assertEqual(result["risk_level"], "critical")
        self.assertIn("EICAR", " ".join(result["reasons"]))

    def test_cross_module_correlation(self):
        self.analysis.analyze_file_change({"file": "subject"})
        result = self.analysis.analyze_network_indicator(
            {"indicator": "subject", "remote_address": "subject"})
        self.assertGreater(result["correlation"]["related_event_count"], 1)

    def test_non_dict_input_ignored(self):
        self.assertIsNone(self.analysis.analyze_file_change(None))
        self.assertIsNone(self.analysis.analyze_network_indicator("string"))

    def test_score_never_exceeds_100(self):
        for _ in range(10):
            result = self.analysis.analyze_antivirus_detection(
                {"file": "x", "status": "malicious_indicator", "confidence": 100})
        self.assertLessEqual(result["risk_score"], 100)


class ResponseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = ASEDatabase(Path(self.temp.name) / "db.sqlite")
        self.db.start()
        self.bus = EventBus()
        self.response = ASEResponse(self.bus, self.db, {"alert_dedupe_seconds": 300})
        self.analysis = ASEAnalysis(self.bus, self.db, self.response)
        self.response.start()
        self.analysis.start()

    def tearDown(self):
        self.analysis.stop()
        self.response.stop()
        self.db.stop()
        self.temp.cleanup()

    def test_alert_persisted_with_reasons(self):
        self.analysis.analyze_file_change({"file": "/tmp/x"})
        alerts = self.response.get_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertTrue(alerts[0]["reasons"])
        self.assertEqual(alerts[0]["status"], "open")
        self.assertIsNotNone(alerts[0]["id"])

    def test_duplicate_suppressed(self):
        for _ in range(3):
            self.analysis.analyze_file_change({"file": "/tmp/same"})
        self.assertGreaterEqual(self.response.suppressed, 2)

    def test_acknowledge_alert(self):
        self.analysis.analyze_file_change({"file": "/tmp/y"})
        alert_id = self.response.get_alerts()[0]["id"]
        self.assertTrue(self.response.acknowledge(alert_id, "tester"))
        acknowledged = self.response.get_alerts(status="acknowledged")
        self.assertEqual(len(acknowledged), 1)
        self.assertFalse(self.response.acknowledge(alert_id))

    def test_incident_grouping(self):
        self.analysis.analyze_file_change({"file": "/tmp/z"})
        incidents = self.response.get_incidents()
        self.assertGreaterEqual(len(incidents), 1)
        self.assertIn("id", incidents[0])

    def test_recommendation_present(self):
        self.analysis.analyze_antivirus_detection(
            {"file": "x.com", "status": "malicious_indicator"})
        alert = self.response.get_alerts()[0]
        self.assertTrue(alert["recommendation"])
        self.assertEqual(alert["action"], "manual_review_required")

    def test_no_destructive_action_taken(self):
        """The response engine must never quarantine on its own."""
        self.analysis.analyze_antivirus_detection({"file": "x.com", "status": "malicious_indicator"})
        alert = self.response.get_alerts()[0]
        self.assertEqual(alert["action"], "manual_review_required")
        self.assertEqual(self.db.count_quarantined(), 0)

    def test_severity_filter(self):
        self.analysis.analyze_antivirus_detection({"file": "x", "status": "malicious_indicator"})
        self.analysis.analyze_file_change({"file": "y"})
        critical = self.response.get_alerts(severity="critical")
        self.assertTrue(all(item["severity"] == "critical" for item in critical))

    def test_works_without_database(self):
        bus = EventBus()
        response = ASEResponse(bus)
        analysis = ASEAnalysis(bus, None, response)
        response.start()
        analysis.start()
        try:
            analysis.analyze_file_change({"file": "/tmp/nodb"})
            self.assertEqual(len(response.get_alerts()), 1)
        finally:
            analysis.stop()
            response.stop()


if __name__ == "__main__":
    unittest.main()
