"""Engine composition root: builds, wires, starts and stops every subsystem."""
from __future__ import annotations

import json
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from core.api import ASEAPI
from core.config import ASEConfig
from core.database import ASEDatabase
from core.event_bus import EventBus
from core.logger import get_logger
from core.module_manager import ModuleManager
from core.scheduler import ASEScheduler

from modules.analysis import ASEAnalysis
from modules.antivirus import ASEAntivirus
from modules.detect import ASEDetect
from modules.intelligence import ASEIntelligence
from modules.monitor import ASEMonitor
from modules.network import ASENetwork
from modules.process import ASEProcessMonitor
from modules.realtime import ASERealtimeMonitor
from modules.response import ASEResponse
from modules.threat_feed import ASEThreatFeed


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


class ASEEngine:
    """Wires the subsystems together. No component starts until ``start()``."""

    def __init__(self, config_path="config/ase.json", log_dir=None):
        self.config = ASEConfig(config_path)
        self.settings = self.config.load()
        self.logger = get_logger(
            log_dir=log_dir or self.settings.get("storage", {}).get("logs_dir", "storage/logs"),
            level=self.settings.get("logging", {}).get("level", "INFO"),
            max_bytes=int(self.settings.get("logging", {}).get("max_bytes", 5 * 1024 * 1024)),
            backups=int(self.settings.get("logging", {}).get("backups", 3)),
        )
        self.event_bus = EventBus()
        self.module_manager = ModuleManager()
        self.running = False
        self.started_at = None

        storage = self.settings.get("storage", {})
        database_path = self.settings.get("database", {}).get("path", "storage/database/ase.db")
        self.database = ASEDatabase(database_path)

        antivirus_dir = storage.get("antivirus_dir", "storage/antivirus")
        self.antivirus = ASEAntivirus(
            base_dir=antivirus_dir,
            settings=self.settings.get("scan", {}),
            database=self.database,
            event_bus=self.event_bus,
        )
        self.threat_feed = ASEThreatFeed(
            self.antivirus, Path(antivirus_dir) / "feed_state.json")

        realtime_settings = self.settings.get("realtime", {})
        self.realtime = ASERealtimeMonitor(
            self.antivirus,
            self.event_bus,
            interval=realtime_settings.get("interval_seconds", 3),
            max_files=realtime_settings.get("max_files", 5000),
            prefer_native=realtime_settings.get("prefer_native", True),
            auto_scan=realtime_settings.get("auto_scan", True),
        )
        watch_paths = (realtime_settings.get("watch_paths")
                       or self.settings.get("monitoring", {}).get("watch_paths", []))
        self.realtime.configure(watch_paths)

        self.intelligence = ASEIntelligence(
            self.event_bus, self.database, self.settings.get("intelligence", {}))
        self.network = ASENetwork(
            self.event_bus, self.intelligence, self.settings.get("network", {}))
        self.process = ASEProcessMonitor(
            self.event_bus, self.settings.get("process", {}))
        self.response = ASEResponse(
            self.event_bus, self.database, self.settings.get("analysis", {}))
        self.analysis = ASEAnalysis(
            self.event_bus, self.database, self.response, self.settings.get("analysis", {}))
        self.detect = ASEDetect(
            self.event_bus, self.database, self.settings.get("scan", {}))
        self.monitor = ASEMonitor(self)

        self.scheduler = ASEScheduler(self.event_bus, self.database)
        self.api = ASEAPI(self)

        self._register_modules()
        self._register_scheduler_tasks()
        self._subscribe_persistence()

    # ------------------------------------------------------------- wiring
    def _register_modules(self):
        self.module_manager.register("monitor", self.monitor)
        self.module_manager.register("detect", self.detect)
        self.module_manager.register("intelligence", self.intelligence)
        self.module_manager.register("response", self.response)
        self.module_manager.register("analysis", self.analysis, dependencies=("response",))
        self.module_manager.register("network", self.network,
                                     dependencies=("intelligence",))
        self.module_manager.register("process", self.process)
        self.module_manager.register("file_monitor", self.realtime,
                                     dependencies=("detect",))

    def _register_scheduler_tasks(self):
        self.scheduler.register("monitor_health", self.monitor.check, 60)
        scan_settings = self.settings.get("scan", {})
        if scan_settings.get("scheduled_enabled"):
            interval = max(60, int(scan_settings.get("scheduled_interval_minutes", 1440)) * 60)
            self.scheduler.register("scheduled_scan", self._scheduled_scan, interval,
                                    run_immediately=True)
        self.scheduler.register("indicator_maintenance", self._indicator_maintenance, 3600)
        self.scheduler.register("realtime_health", self._realtime_health, 30)

    def _subscribe_persistence(self):
        self.event_bus.subscribe("analysis.completed", self._save_analysis_event)
        self.event_bus.subscribe("response.alert_created", self._save_response_event)

    def _save_analysis_event(self, data):
        if not self.database.ready:
            return
        try:
            self.database.save_event("analysis.completed",
                                     json.dumps(data, ensure_ascii=False, default=str), _utc_now())
        except Exception:
            self.logger.exception("Failed to persist analysis event")

    def _save_response_event(self, data):
        if not self.database.ready:
            return
        try:
            self.database.save_event("response.alert_created",
                                     json.dumps(data, ensure_ascii=False, default=str), _utc_now())
        except Exception:
            self.logger.exception("Failed to persist response event")

    def _scheduled_scan(self):
        roots = self.settings.get("scan", {}).get("scheduled_paths") or None
        self.antivirus.full_scan(roots=roots)

    def _indicator_maintenance(self):
        removed = self.intelligence.purge_expired()
        if removed:
            self.logger.info("Purged %d expired indicators", removed)

    def _realtime_health(self):
        state = self.realtime.health()
        if state["state"] in ("degraded", "stalled"):
            self.logger.warning("Realtime monitor state: %s (%s)", state["state"], state.get("last_error"))

    # ------------------------------------------------------------- policy
    def is_path_allowed(self, target):
        """Enforce the API scan allowlist. Empty allowlist permits the caller's own paths."""
        allowlist = self.settings.get("api", {}).get("allow_scan_paths") or []
        if not allowlist:
            return True
        try:
            resolved = Path(target).expanduser().resolve(strict=True)
        except (OSError, RuntimeError):
            return False
        for allowed in allowlist:
            try:
                base = Path(allowed).expanduser().resolve(strict=True)
            except (OSError, RuntimeError):
                continue
            if resolved == base or base in resolved.parents:
                return True
        return False

    def set_watch_paths(self, paths):
        configured = self.realtime.configure(paths)
        self.config.update("realtime", {"watch_paths": configured})
        if self.running:
            self.realtime.stop()
            self.realtime.start()
        return configured

    # ------------------------------------------------------------- lifecycle
    def start(self):
        if self.running:
            return False
        self.logger.info("AKVORIA Security Engine starting")

        self.database.start()
        self.antivirus.start()

        # Order matters: response must subscribe before analysis emits anything.
        outcome = self.module_manager.start_all()
        if outcome["failed"]:
            self.logger.warning("Modules failed to start: %s", outcome["failed"])

        self.realtime.start()
        self.scheduler.start()
        self.api.start()

        self.running = True
        self.started_at = _utc_now()
        self.event_bus.publish("engine.started", {"version": self.settings["engine"]["version"]})
        self.logger.info("AKVORIA Security Engine started")
        return True

    def stop(self):
        if not self.running:
            return False
        self.logger.info("AKVORIA Security Engine stopping")

        self.scheduler.stop()
        self.api.stop()
        self.realtime.stop()
        self.module_manager.stop_all()
        self.antivirus.stop()

        self.running = False
        self.event_bus.publish("engine.stopped", {})
        self.database.stop()
        self.logger.info("AKVORIA Security Engine stopped")
        return True

    # ------------------------------------------------------------- reporting
    def get_status(self):
        return {
            "engine": self.settings["engine"]["name"],
            "version": self.settings["engine"]["version"],
            "environment": self.settings["engine"].get("environment", "local"),
            "running": self.running,
            "started_at": self.started_at,
            "modules": self.module_manager.get_status(),
            "monitor": self.monitor.check(),
            "scheduler": self.scheduler.get_status(),
            "analysis": self.analysis.get_status(),
            "response": self.response.get_status(),
            "network": self.network.get_status(),
            "process": self.process.get_status(),
            "intelligence": self.intelligence.statistics(),
            "antivirus": self.antivirus.get_status(),
            "realtime": self.realtime.get_status(),
            "database": self.database.statistics() if self.database.ready else {"ready": False},
            "api": self.api.get_status(),
            "protection_scope": "configured_directories_only",
        }

    def health(self):
        return self.monitor.check()

    def public_config(self):
        """Config safe to expose over the API: no secrets, no key paths."""
        settings = json.loads(json.dumps(self.settings))
        settings.get("api", {}).pop("allow_scan_paths", None)
        return settings

    def diagnostics(self):
        """Aggregate diagnostics without leaking credentials."""
        db_stats = self.database.statistics() if self.database.ready else {"ready": False}
        return {
            "generated_at": _utc_now(),
            "engine": {"version": self.settings["engine"]["version"],
                       "running": self.running, "started_at": self.started_at},
            "platform": __import__("platform").platform(),
            "python": __import__("sys").version.split()[0],
            "database": db_stats,
            "modules": self.module_manager.get_details(),
            "scheduler": self.scheduler.get_status(),
            "event_bus": {"published": self.event_bus.published,
                          "recent_errors": self.event_bus.last_errors[-10:]},
            "realtime": self.realtime.health(),
            "antivirus": self.antivirus.get_status(),
            "network": self.network.get_status(),
            "process": self.process.get_status(),
            "api": {"running": self.api.server is not None,
                    "security": self.api.security.get_health()},
            "limitations": [
                "Monitoring covers configured directories only.",
                "Network and process views are passive read-only inventories.",
                "A no_known_indicators verdict is not proof a file is harmless.",
            ],
        }

    def backup_database(self):
        backup_dir = Path(self.settings.get("storage", {}).get("backup_dir", "storage/backups"))
        backup_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        destination = backup_dir / ("ase-%s.db" % stamp)
        self.database.backup(destination)
        return str(destination)

    def restore_database(self, backup_path):
        self.database.restore_from(backup_path)
        self.intelligence.reload()
        return True

    def export_report(self, destination, scan_id=None):
        """Write a structured JSON report of the current engine state."""
        target = Path(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        report = {
            "generated_at": _utc_now(),
            "engine": self.settings["engine"],
            "status": self.get_status(),
            "scan_statistics": self.database.get_scan_statistics() if self.database.ready else {},
        }
        if scan_id is not None and self.database.ready:
            scan = self.database.get_scan(scan_id)
            if scan is None:
                raise ValueError("Scan not found: %s" % scan_id)
            scan["results"] = self.database.get_scan_results(scan_id)
            report["scan"] = scan
        target.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), "utf-8")
        return {"path": str(target), "bytes": target.stat().st_size}
