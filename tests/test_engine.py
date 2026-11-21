"""Engine integration tests: lifecycle, wiring, persistence, reports, recovery."""
from __future__ import annotations

import json
import socket
import time
import unittest
from pathlib import Path

from tests.helpers import IsolatedWorkspace

EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class EngineLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.workspace = IsolatedWorkspace(api_port=_free_port())
        self.root = self.workspace.__enter__()

    def tearDown(self):
        self.workspace.__exit__(None, None, None)

    def _engine(self):
        from core.engine import ASEEngine
        return ASEEngine()

    def test_start_and_stop(self):
        engine = self._engine()
        self.assertTrue(engine.start())
        self.assertTrue(engine.running)
        self.assertFalse(engine.start(), "double start must be refused")
        self.assertTrue(engine.stop())
        self.assertFalse(engine.running)

    def test_all_core_modules_running(self):
        engine = self._engine()
        engine.start()
        try:
            modules = engine.module_manager.get_status()
            for name in ("monitor", "detect", "intelligence", "response",
                         "analysis", "network", "process"):
                self.assertEqual(modules[name], "running", name)
        finally:
            engine.stop()

    def test_file_monitor_idle_without_paths(self):
        engine = self._engine()
        engine.start()
        try:
            self.assertEqual(engine.module_manager.get_status()["file_monitor"], "idle")
            self.assertEqual(engine.realtime.get_status()["mode"], "idle_no_paths")
        finally:
            engine.stop()

    def test_status_reports_truthful_scope(self):
        engine = self._engine()
        engine.start()
        try:
            status = engine.get_status()
            self.assertEqual(status["protection_scope"], "configured_directories_only")
            self.assertIn("api", status)
            self.assertIn("database", status)
        finally:
            engine.stop()

    def test_health_check_structure(self):
        engine = self._engine()
        engine.start()
        try:
            health = engine.health()
            self.assertIn(health["overall"], ("healthy", "healthy_with_unsupported_features"))
            self.assertIn("checks", health)
        finally:
            engine.stop()

    def test_event_persistence(self):
        engine = self._engine()
        engine.start()
        try:
            engine.analysis.analyze_file_change({"file": "/tmp/persisted"})
            time.sleep(0.2)
            events = engine.database.get_events()
            self.assertTrue(any(item["event_type"] == "analysis.completed" for item in events))
        finally:
            engine.stop()

    def test_data_survives_restart(self):
        engine = self._engine()
        engine.start()
        engine.analysis.analyze_file_change({"file": "/tmp/restart"})
        engine.database.create_scan("quick", "/tmp")
        engine.stop()

        reopened = self._engine()
        reopened.database.start()
        try:
            self.assertGreaterEqual(reopened.database.count_events(), 1)
            self.assertGreaterEqual(len(reopened.database.get_scans()), 1)
        finally:
            reopened.database.stop()

    def test_database_backup_and_restore(self):
        engine = self._engine()
        engine.start()
        try:
            engine.database.save_event("pre.backup", {})
            backup = engine.backup_database()
            self.assertTrue(Path(backup).exists())
            engine.database.save_event("post.backup", {})
            before = engine.database.count_events()
            engine.restore_database(backup)
            self.assertLess(engine.database.count_events(), before)
        finally:
            engine.stop()

    def test_report_export(self):
        engine = self._engine()
        engine.start()
        try:
            engine.database.create_scan("quick", "/tmp")
            target = Path(self.root) / "report.json"
            result = engine.export_report(target)
            self.assertTrue(target.exists())
            payload = json.loads(target.read_text("utf-8"))
            self.assertIn("status", payload)
            self.assertIn("scan_statistics", payload)
        finally:
            engine.stop()

    def test_set_watch_paths_updates_runtime_and_config(self):
        engine = self._engine()
        watch = Path(self.root) / "watched"
        watch.mkdir()
        engine.start()
        try:
            configured = engine.set_watch_paths([str(watch)])
            self.assertEqual(configured, [str(watch.resolve())])
            self.assertEqual(engine.realtime.get_status()["roots"], [str(watch.resolve())])
            persisted = json.loads((Path(self.root) / "config" / "ase.json").read_text("utf-8"))
            self.assertEqual(persisted["realtime"]["watch_paths"], [str(watch.resolve())])
        finally:
            engine.stop()

    def test_scan_allowlist_blocks_outside_paths(self):
        (Path(self.root) / "config" / "ase.json").write_text(json.dumps({
            "api": {"port": _free_port(), "allow_scan_paths": [str(Path(self.root) / "allowed")]}
        }), "utf-8")
        (Path(self.root) / "allowed").mkdir()
        (Path(self.root) / "outside").mkdir()
        engine = self._engine()
        try:
            self.assertTrue(engine.is_path_allowed(str(Path(self.root) / "allowed")))
            self.assertFalse(engine.is_path_allowed(str(Path(self.root) / "outside")))
            self.assertFalse(engine.is_path_allowed("/etc/passwd"))
        finally:
            engine.stop()

    def test_public_config_hides_scan_allowlist(self):
        engine = self._engine()
        try:
            public = engine.public_config()
            self.assertNotIn("allow_scan_paths", public["api"])
        finally:
            engine.stop()

    def test_diagnostics_has_no_secrets(self):
        engine = self._engine()
        engine.start()
        try:
            diagnostics = json.dumps(engine.diagnostics())
            self.assertNotIn(engine.api.api_key, diagnostics)
            self.assertNotIn("api_key", diagnostics.lower())
        finally:
            engine.stop()

    def test_scheduled_scan_task_registered(self):
        (Path(self.root) / "config" / "ase.json").write_text(json.dumps({
            "api": {"port": _free_port()},
            "scan": {"scheduled_enabled": True, "scheduled_interval_minutes": 60},
        }), "utf-8")
        engine = self._engine()
        tasks = engine.scheduler.get_status()["tasks"]
        self.assertIn("scheduled_scan", tasks)
        self.assertIn("monitor_health", tasks)

    def test_end_to_end_detection_flow(self):
        """Scan → alert → quarantine → restore across the full stack."""
        work = Path(self.root) / "work"
        work.mkdir()
        target = work / "test.com"
        target.write_text(EICAR, encoding="utf-8")

        engine = self._engine()
        engine.start()
        try:
            report = engine.antivirus.scan_path(work)
            self.assertEqual(report["detections"], 1)

            engine.analysis.analyze_antivirus_detection({
                "file": str(target), "status": "malicious_indicator",
                "explanations": ["EICAR"], "scan_id": report["scan_id"],
            })
            alerts = engine.response.get_alerts()
            self.assertTrue(alerts)
            self.assertTrue(alerts[0]["reasons"])

            qid = engine.antivirus.quarantine_file(target, authorized=True)["quarantine_id"]
            self.assertFalse(target.exists())
            engine.antivirus.restore_file(qid)
            self.assertTrue(target.exists())
        finally:
            engine.stop()

    def test_stop_is_idempotent(self):
        engine = self._engine()
        engine.start()
        self.assertTrue(engine.stop())
        self.assertFalse(engine.stop())

    def test_api_serves_after_start_and_stops_cleanly(self):
        engine = self._engine()
        engine.start()
        port = engine.api.port
        try:
            import urllib.request
            with urllib.request.urlopen("http://127.0.0.1:%d/health" % port, timeout=5) as resp:
                self.assertEqual(resp.status, 200)
        finally:
            engine.stop()
        import urllib.error
        with self.assertRaises(Exception):
            urllib.request.urlopen("http://127.0.0.1:%d/health" % port, timeout=2)


if __name__ == "__main__":
    unittest.main()
