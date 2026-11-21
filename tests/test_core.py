"""Core infrastructure tests: config, database migrations, event bus, modules, scheduler."""
from __future__ import annotations

import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from core.config import ASEConfig, DEFAULTS
from core.database import ASEDatabase, SCHEMA_VERSION
from core.event_bus import EventBus
from core.exceptions import ASEConfigError, ASEDatabaseError, ASEModuleError
from core.module_manager import ModuleManager
from core.scheduler import ASEScheduler


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "config" / "ase.json"

    def tearDown(self):
        self.temp.cleanup()

    def test_defaults_written_when_missing(self):
        config = ASEConfig(self.path)
        data = config.load()
        self.assertTrue(self.path.exists())
        self.assertEqual(data["api"]["host"], "127.0.0.1")
        self.assertEqual(data["realtime"]["watch_paths"], [])

    def test_partial_file_is_merged_with_defaults(self):
        self.path.parent.mkdir(parents=True)
        self.path.write_text(json.dumps({"api": {"port": 9000}}), "utf-8")
        data = ASEConfig(self.path).load()
        self.assertEqual(data["api"]["port"], 9000)
        self.assertEqual(data["api"]["host"], "127.0.0.1")
        self.assertIn("scan", data)

    def test_non_loopback_host_rejected(self):
        config = ASEConfig(self.path)
        config.load()
        for host in ("0.0.0.0", "192.168.1.5", "example.com"):
            with self.assertRaises(ASEConfigError):
                config.update("api", {"host": host})

    def test_invalid_port_rejected(self):
        config = ASEConfig(self.path)
        config.load()
        for port in (80, 0, 70000):
            with self.assertRaises(ASEConfigError):
                config.update("api", {"port": port})

    def test_symlink_following_rejected(self):
        config = ASEConfig(self.path)
        config.load()
        with self.assertRaises(ASEConfigError):
            config.update("realtime", {"follow_symlinks": True})

    def test_watch_paths_must_be_string_list(self):
        config = ASEConfig(self.path)
        config.load()
        with self.assertRaises(ASEConfigError):
            config.update("realtime", {"watch_paths": [1, 2, 3]})

    def test_failed_update_does_not_persist(self):
        config = ASEConfig(self.path)
        config.load()
        original_host = config.get("api")["host"]
        with self.assertRaises(ASEConfigError):
            config.update("api", {"host": "0.0.0.0"})
        self.assertEqual(config.get("api")["host"], original_host)
        reloaded = ASEConfig(self.path).load()
        self.assertEqual(reloaded["api"]["host"], original_host)

    def test_malformed_json_rejected(self):
        self.path.parent.mkdir(parents=True)
        self.path.write_text("{not json", "utf-8")
        with self.assertRaises(ASEConfigError):
            ASEConfig(self.path).load()

    def test_scan_size_cap_enforced(self):
        config = ASEConfig(self.path)
        config.load()
        with self.assertRaises(ASEConfigError):
            config.update("scan", {"max_file_size_mb": 99999})


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "ase.db"
        self.db = ASEDatabase(self.path)
        self.db.start()

    def tearDown(self):
        if self.db.ready:
            self.db.stop()
        self.temp.cleanup()

    def test_schema_version_is_current(self):
        self.assertEqual(self.db.schema_version, SCHEMA_VERSION)

    def test_expected_tables_exist(self):
        tables = {row[0] for row in self.db.connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        for name in ("security_events", "scheduler_history", "file_baselines",
                     "threat_indicators", "scans", "scan_results", "quarantine",
                     "alerts", "incidents"):
            self.assertIn(name, tables)

    def test_events_round_trip(self):
        self.db.save_event("test.event", {"a": 1})
        events = self.db.get_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "test.event")

    def test_search_events_filters_by_risk_level(self):
        self.db.save_event("x", {"risk_level": "high"})
        self.db.save_event("x", {"risk_level": "low"})
        result = self.db.search_events(risk_level="high")
        self.assertEqual(result["total"], 1)

    def test_indicator_upsert_updates_fields(self):
        self.db.add_indicator("8.8.8.8", "ip", "first", "one")
        self.db.add_indicator("8.8.8.8", "ip", "second", "two", confidence=90)
        record = self.db.get_indicator("8.8.8.8")
        self.assertEqual(record["source"], "second")
        self.assertEqual(record["confidence"], 90)
        self.assertEqual(len(self.db.get_indicators()), 1)

    def test_expired_indicator_hidden_by_default(self):
        self.db.add_indicator("1.1.1.1", "ip", expires_at="2000-01-01T00:00:00+00:00")
        self.assertEqual(self.db.get_indicators(), [])
        self.assertEqual(len(self.db.get_indicators(include_expired=True)), 1)

    def test_delete_indicator(self):
        self.db.add_indicator("9.9.9.9", "ip")
        self.assertTrue(self.db.delete_indicator("9.9.9.9"))
        self.assertIsNone(self.db.get_indicator("9.9.9.9"))

    def test_scan_persistence_and_statistics(self):
        scan_id = self.db.create_scan("quick", "/tmp")
        self.db.finish_scan(scan_id, "completed",
                            {"total": 1, "scanned": 1, "detections": 1, "errors": 0, "skipped": 0},
                            [{"file": "/tmp/x", "status": "malicious_indicator",
                              "sha256": "a" * 64, "risk_score": 90, "findings": []}])
        scan = self.db.get_scan(scan_id)
        self.assertEqual(scan["status"], "completed")
        self.assertEqual(len(self.db.get_scan_results(scan_id)), 1)
        stats = self.db.get_scan_statistics()
        self.assertEqual(stats["total_scans"], 1)
        self.assertEqual(stats["by_verdict"]["malicious_indicator"], 1)

    def test_alert_lifecycle_and_acknowledgement(self):
        alert_id = self.db.add_alert({"fingerprint": "f", "event_type": "e", "severity": "high",
                                      "risk_score": 80, "subject": "s", "reasons": ["r"]})
        alert = self.db.get_alert(alert_id)
        self.assertEqual(alert["reasons"], ["r"])
        self.assertEqual(alert["status"], "open")
        self.assertTrue(self.db.acknowledge_alert(alert_id))
        self.assertEqual(self.db.get_alert(alert_id)["status"], "acknowledged")
        self.assertFalse(self.db.acknowledge_alert(alert_id))

    def test_duplicate_alert_lookup(self):
        self.db.add_alert({"fingerprint": "same", "event_type": "e", "severity": "low"})
        found = self.db.find_recent_alert("same", "2000-01-01T00:00:00+00:00")
        self.assertIsNotNone(found)
        self.assertIsNone(self.db.find_recent_alert("other", "2000-01-01T00:00:00+00:00"))

    def test_backup_and_restore(self):
        self.db.save_event("before.backup", {})
        backup = Path(self.temp.name) / "backup.db"
        self.db.backup(backup)
        self.assertTrue(backup.exists())
        self.db.save_event("after.backup", {})
        self.assertEqual(self.db.count_events(), 2)
        self.db.restore_from(backup)
        self.assertEqual(self.db.count_events(), 1)

    def test_symlink_database_refused(self):
        target = Path(self.temp.name) / "real.db"
        target.touch()
        link = Path(self.temp.name) / "link.db"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        db = ASEDatabase(link)
        with self.assertRaises(ASEDatabaseError):
            db.start()

    def test_queries_require_started_database(self):
        fresh = ASEDatabase(Path(self.temp.name) / "other.db")
        with self.assertRaises(ASEDatabaseError):
            fresh.get_events()


class LegacyMigrationTests(unittest.TestCase):
    """A 1.3 database must upgrade in place without losing rows."""

    def test_legacy_schema_upgrades_preserving_data(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "legacy.db"
            connection = sqlite3.connect(path)
            connection.execute(
                "CREATE TABLE file_baselines(file_path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, "
                "updated_at TEXT NOT NULL)")
            connection.execute("INSERT INTO file_baselines VALUES('/keep','abc','2020')")
            connection.execute(
                "CREATE TABLE threat_indicators(indicator TEXT PRIMARY KEY, indicator_type TEXT NOT NULL, "
                "source TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL)")
            connection.execute(
                "INSERT INTO threat_indicators VALUES('1.2.3.4','ip','legacy','','2020')")
            connection.commit()
            connection.close()

            db = ASEDatabase(path)
            db.start()
            try:
                self.assertEqual(db.schema_version, SCHEMA_VERSION)
                self.assertEqual(db.get_baseline("/keep")["sha256"], "abc")
                self.assertIsNotNone(db.get_indicator("1.2.3.4"))
                columns = {row[1] for row in db.connection.execute(
                    "PRAGMA table_info(threat_indicators)")}
                self.assertTrue({"confidence", "expires_at", "updated_at"}.issubset(columns))
            finally:
                db.stop()

    def test_migration_is_idempotent(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "db.sqlite"
            first = ASEDatabase(path)
            first.start()
            first.save_event("x", {})
            first.stop()
            second = ASEDatabase(path)
            second.start()
            try:
                self.assertEqual(second.count_events(), 1)
                self.assertEqual(second.schema_version, SCHEMA_VERSION)
            finally:
                second.stop()


class EventBusTests(unittest.TestCase):
    def test_delivery(self):
        bus = EventBus()
        seen = []
        bus.subscribe("x", lambda data: seen.append(data))
        bus.publish("x", {"v": 1})
        self.assertEqual(seen, [{"v": 1}])

    def test_failure_isolation(self):
        bus = EventBus()
        seen = []
        bus.subscribe("x", lambda _: (_ for _ in ()).throw(RuntimeError("boom")))
        bus.subscribe("x", lambda data: seen.append(data))
        result = bus.publish("x", {"ok": True})
        self.assertEqual(seen, [{"ok": True}])
        self.assertEqual(len(result["errors"]), 1)

    def test_duplicate_subscription_ignored(self):
        bus = EventBus()
        handler = lambda data: None
        bus.subscribe("x", handler)
        bus.subscribe("x", handler)
        self.assertEqual(bus.subscriber_count("x"), 1)

    def test_unsubscribe(self):
        bus = EventBus()
        seen = []
        handler = lambda data: seen.append(data)
        bus.subscribe("x", handler)
        self.assertTrue(bus.unsubscribe("x", handler))
        bus.publish("x", {})
        self.assertEqual(seen, [])

    def test_non_callable_rejected(self):
        with self.assertRaises(TypeError):
            EventBus().subscribe("x", "not callable")


class _StubModule:
    def __init__(self, log, name, outcome=True):
        self.log = log
        self.name = name
        self.outcome = outcome

    def start(self):
        self.log.append("start:" + self.name)
        return self.outcome

    def stop(self):
        self.log.append("stop:" + self.name)


class ModuleManagerTests(unittest.TestCase):
    def test_registration_requires_lifecycle_methods(self):
        manager = ModuleManager()
        with self.assertRaises(ASEModuleError):
            manager.register("bad", object())

    def test_duplicate_registration_rejected(self):
        manager = ModuleManager()
        manager.register("a", _StubModule([], "a"))
        with self.assertRaises(ASEModuleError):
            manager.register("a", _StubModule([], "a"))

    def test_dependency_order(self):
        log = []
        manager = ModuleManager()
        manager.register("dependent", _StubModule(log, "dependent"), dependencies=("base",))
        manager.register("base", _StubModule(log, "base"))
        manager.start_all()
        self.assertEqual(log, ["start:base", "start:dependent"])

    def test_missing_dependency_blocks_start(self):
        manager = ModuleManager()
        manager.register("child", _StubModule([], "child"), dependencies=("ghost",))
        outcome = manager.start_all()
        self.assertIn("child", outcome["failed"])

    def test_idle_module_is_not_reported_running(self):
        manager = ModuleManager()
        manager.register("idle", _StubModule([], "idle", outcome=False))
        manager.start_all()
        self.assertEqual(manager.get_status()["idle"], "idle")

    def test_circular_dependency_detected(self):
        manager = ModuleManager()
        manager.register("a", _StubModule([], "a"), dependencies=("b",))
        manager.register("b", _StubModule([], "b"), dependencies=("a",))
        with self.assertRaises(ASEModuleError):
            manager._order()

    def test_stop_all_reverses_order(self):
        log = []
        manager = ModuleManager()
        manager.register("base", _StubModule(log, "base"))
        manager.register("leaf", _StubModule(log, "leaf"), dependencies=("base",))
        manager.start_all()
        log.clear()
        manager.stop_all()
        self.assertEqual(log, ["stop:leaf", "stop:base"])


class SchedulerTests(unittest.TestCase):
    def test_rejects_bad_interval(self):
        scheduler = ASEScheduler(EventBus())
        with self.assertRaises(ValueError):
            scheduler.register("t", lambda: None, 0)

    def test_duplicate_task_rejected(self):
        scheduler = ASEScheduler(EventBus())
        scheduler.register("t", lambda: None, 5)
        with self.assertRaises(ValueError):
            scheduler.register("t", lambda: None, 5)

    def test_task_runs(self):
        scheduler = ASEScheduler(EventBus(), tick_seconds=0.05)
        hits = []
        scheduler.register("t", lambda: hits.append(1), 1)
        scheduler.start()
        try:
            deadline = time.time() + 3
            while time.time() < deadline and not hits:
                time.sleep(0.05)
        finally:
            scheduler.stop()
        self.assertTrue(hits)

    def test_failure_recorded_and_backoff_applied(self):
        scheduler = ASEScheduler(EventBus(), tick_seconds=0.05)
        scheduler.register("boom", lambda: (_ for _ in ()).throw(RuntimeError("x")), 1)
        scheduler.start()
        try:
            deadline = time.time() + 3
            while time.time() < deadline and scheduler.get_status()["tasks"]["boom"]["failures"] == 0:
                time.sleep(0.05)
        finally:
            scheduler.stop()
        status = scheduler.get_status()["tasks"]["boom"]
        self.assertGreaterEqual(status["failures"], 1)
        self.assertIn("RuntimeError", status["last_error"])

    def test_enable_disable(self):
        scheduler = ASEScheduler(EventBus())
        scheduler.register("t", lambda: None, 5)
        self.assertTrue(scheduler.disable("t"))
        self.assertEqual(scheduler.get_status()["tasks"]["t"]["status"], "disabled")
        self.assertTrue(scheduler.enable("t"))
        self.assertTrue(scheduler.remove("t"))
        self.assertFalse(scheduler.remove("t"))

    def test_run_now(self):
        scheduler = ASEScheduler(EventBus())
        hits = []
        scheduler.register("t", lambda: hits.append(1), 3600)
        self.assertTrue(scheduler.run_now("t"))
        self.assertEqual(len(hits), 1)


if __name__ == "__main__":
    unittest.main()
