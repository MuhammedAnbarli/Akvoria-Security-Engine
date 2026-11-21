"""Detect module and monitor aggregation tests."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core.database import ASEDatabase
from core.event_bus import EventBus
from modules.detect import ASEDetect
from modules.monitor import ASEMonitor


class DetectTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = ASEDatabase(self.root / "db.sqlite")
        self.db.start()
        self.bus = EventBus()
        self.changes = []
        self.bus.subscribe("detect.file_changed", lambda data: self.changes.append(data))
        self.detect = ASEDetect(self.bus, self.db, {"max_file_size_mb": 1, "max_files": 50})
        self.detect.start()

    def tearDown(self):
        self.db.stop()
        self.temp.cleanup()

    def test_hash_is_sha256(self):
        path = self.root / "a.txt"
        path.write_text("abc", encoding="utf-8")
        digest = self.detect.calculate_hash(path)
        self.assertEqual(len(digest), 64)
        self.assertEqual(digest, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_baseline_then_change_detected(self):
        path = self.root / "a.txt"
        path.write_text("v1", encoding="utf-8")
        self.assertEqual(self.detect.monitor_file(path)["status"], "baseline_created")
        self.assertEqual(self.detect.monitor_file(path)["status"], "unchanged")
        path.write_text("v2 changed", encoding="utf-8")
        self.assertEqual(self.detect.monitor_file(path)["status"], "file_changed")
        self.assertEqual(len(self.changes), 1)

    def test_baseline_persisted_in_database(self):
        path = self.root / "a.txt"
        path.write_text("data", encoding="utf-8")
        self.detect.monitor_file(path)
        record = self.db.get_baseline(str(path.resolve()))
        self.assertIsNotNone(record)
        self.assertEqual(len(record["sha256"]), 64)

    def test_symlink_refused(self):
        target = self.root / "t.txt"
        target.write_text("x")
        link = self.root / "l.txt"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaises(ValueError):
            self.detect.monitor_file(link)

    def test_hash_size_limit(self):
        self.detect.max_file_size = 4
        path = self.root / "big.txt"
        path.write_text("far too long for the limit")
        with self.assertRaises(ValueError):
            self.detect.calculate_hash(path)

    def test_static_scan_double_extension(self):
        path = self.root / "invoice.pdf.exe"
        path.write_text("harmless")
        result = self.detect.scan_file(path)
        self.assertEqual(result["status"], "suspicious")
        self.assertFalse(result["modified"])

    def test_static_scan_matches_stored_indicator(self):
        path = self.root / "x.bin"
        path.write_text("payload")
        digest = self.detect.calculate_hash(path)
        self.db.add_indicator(digest, "sha256", "test")
        self.assertEqual(self.detect.scan_file(path)["status"], "malicious_indicator")

    def test_directory_scan_summary(self):
        work = self.root / "files"
        work.mkdir()
        for index in range(3):
            (work / ("f%d.txt" % index)).write_text("x")
        summary = self.detect.scan_directory(work)
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["baseline_created"], 3)

    def test_directory_scan_respects_max_files(self):
        self.detect.max_files = 2
        work = self.root / "many"
        work.mkdir()
        for index in range(6):
            (work / ("g%d.txt" % index)).write_text("x")
        summary = self.detect.scan_directory(work)
        self.assertLessEqual(summary["total"], 2)

    def test_missing_directory_raises(self):
        with self.assertRaises(FileNotFoundError):
            self.detect.scan_directory(self.root / "nope")


class MonitorTests(unittest.TestCase):
    def test_reports_stopped_engine(self):
        class Stub:
            running = False
            module_manager = None
            database = None
            scheduler = None
            antivirus = None
            realtime = None
            network = None
            process = None

        monitor = ASEMonitor(Stub())
        monitor.start()
        result = monitor.check()
        self.assertEqual(result["overall"], "stopped")
        self.assertFalse(result["engine_running"])

    def test_reports_unsupported_features(self):
        class Stub:
            running = True

            class _MM:
                @staticmethod
                def get_status():
                    return {"x": "running"}

            class _DB:
                ready = True
                schema_version = 3

            class _Sched:
                running = True

                @staticmethod
                def get_status():
                    return {"tasks": {}}

            class _AV:
                started = True

            class _RT:
                @staticmethod
                def health():
                    return {"state": "healthy"}

            class _Net:
                @staticmethod
                def is_supported():
                    return False

            class _Proc:
                @staticmethod
                def is_supported():
                    return True

            module_manager = _MM()
            database = _DB()
            scheduler = _Sched()
            antivirus = _AV()
            realtime = _RT()
            network = _Net()
            process = _Proc()

        monitor = ASEMonitor(Stub())
        result = monitor.check()
        self.assertEqual(result["overall"], "healthy_with_unsupported_features")
        self.assertEqual(result["checks"]["network"]["state"], "unsupported")


if __name__ == "__main__":
    unittest.main()
