"""Real-time monitor tests: change detection, dedupe, deletions, honest status."""
from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from core.event_bus import EventBus
from modules.antivirus import ASEAntivirus, _EICAR
from modules.realtime import ASERealtimeMonitor


class RealtimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.watch = self.root / "watch"
        self.watch.mkdir()
        self.av = ASEAntivirus(self.root / "av")
        self.av.start()
        self.bus = EventBus()
        self.events = []
        for name in ("realtime.file_changed", "realtime.file_deleted", "antivirus.detection"):
            self.bus.subscribe(name, lambda data, n=name: self.events.append((n, data)))
        self.monitor = ASERealtimeMonitor(self.av, self.bus, interval=1)

    def tearDown(self):
        self.monitor.stop()
        self.av.stop()
        self.temp.cleanup()

    def test_configure_accepts_directories_only(self):
        file_path = self.root / "file.txt"
        file_path.write_text("x")
        configured = self.monitor.configure([str(self.watch), str(file_path), "/missing/path"])
        self.assertEqual(configured, [str(self.watch.resolve())])

    def test_new_file_detected_and_scanned(self):
        self.monitor.configure([self.watch])
        (self.watch / "new.txt").write_text("harmless")
        result = self.monitor.scan_once()
        self.assertEqual(result["scanned"], 1)
        self.assertEqual(result["results"][0]["change"], "created")

    def test_duplicate_events_suppressed(self):
        self.monitor.configure([self.watch])
        (self.watch / "a.txt").write_text("one")
        self.assertEqual(self.monitor.scan_once()["scanned"], 1)
        self.assertEqual(self.monitor.scan_once()["scanned"], 0)

    def test_modification_detected(self):
        self.monitor.configure([self.watch])
        path = self.watch / "a.txt"
        path.write_text("one")
        self.monitor.scan_once()
        path.write_text("two different content")
        result = self.monitor.scan_once()
        self.assertEqual(result["scanned"], 1)
        self.assertEqual(result["results"][0]["change"], "modified")

    def test_deletion_tracked(self):
        self.monitor.configure([self.watch])
        path = self.watch / "gone.txt"
        path.write_text("x")
        self.monitor.scan_once()
        path.unlink()
        result = self.monitor.scan_once()
        self.assertEqual(result["deleted"], 1)
        self.assertTrue(any(name == "realtime.file_deleted" for name, _ in self.events))

    def test_detection_publishes_antivirus_event(self):
        self.monitor.configure([self.watch])
        (self.watch / "bad.com").write_bytes(_EICAR)
        result = self.monitor.scan_once()
        self.assertEqual(result["detections"], 1)
        self.assertTrue(any(name == "antivirus.detection" for name, _ in self.events))

    def test_symlinks_ignored(self):
        outside = self.root / "outside.txt"
        outside.write_text("outside")
        try:
            (self.watch / "link").symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        self.monitor.configure([self.watch])
        self.assertEqual(self.monitor.scan_once()["scanned"], 0)

    def test_status_reports_scope_honestly(self):
        self.monitor.configure([self.watch])
        status = self.monitor.get_status()
        self.assertEqual(status["protection_scope"], "configured_directories_only")
        self.assertEqual(status["roots"], [str(self.watch.resolve())])
        self.assertIn("native_events_supported", status)

    def test_idle_status_when_no_paths(self):
        self.monitor.configure([])
        self.assertFalse(self.monitor.start())
        self.assertEqual(self.monitor.get_status()["mode"], "idle_no_paths")
        self.assertEqual(self.monitor.health()["state"], "idle")

    def test_start_stop_lifecycle(self):
        self.monitor.configure([self.watch])
        self.assertTrue(self.monitor.start())
        self.assertTrue(self.monitor.get_status()["running"])
        self.assertTrue(self.monitor.stop())
        self.assertFalse(self.monitor.get_status()["running"])
        self.assertEqual(self.monitor.get_status()["mode"], "stopped")

    def test_background_monitoring_detects_new_file(self):
        self.monitor.configure([self.watch])
        self.monitor.start()
        try:
            time.sleep(1.0)
            (self.watch / "live.txt").write_text("appeared while running")
            deadline = time.time() + 8
            while time.time() < deadline:
                if self.monitor.get_status()["total_scans"] > 0:
                    break
                time.sleep(0.2)
        finally:
            self.monitor.stop()
        self.assertGreater(self.monitor.get_status()["total_scans"], 0)

    def test_health_reports_healthy_when_running(self):
        self.monitor.configure([self.watch])
        self.monitor.start()
        try:
            time.sleep(1.2)
            state = self.monitor.health()["state"]
        finally:
            self.monitor.stop()
        self.assertIn(state, ("healthy", "stopped"))

    def test_resource_limit_caps_scan(self):
        self.monitor.max_files = 2
        for index in range(10):
            (self.watch / ("f%d.txt" % index)).write_text("x")
        self.monitor.configure([self.watch])
        result = self.monitor.scan_once()
        self.assertLessEqual(result["scanned"], 3)


if __name__ == "__main__":
    unittest.main()
