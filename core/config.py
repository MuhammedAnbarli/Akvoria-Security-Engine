"""Configuration loading, deep merge and strict validation.

The config is a JSON object on disk. Unknown top-level sections are preserved
so a newer config file is never silently truncated by an older engine.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

from core.exceptions import ASEConfigError

DEFAULT_CONFIG_PATH = Path("config/ase.json")
LOOPBACK_HOSTS = ("127.0.0.1", "::1", "localhost")

DEFAULTS = {
    "engine": {
        "name": "AKVORIA SECURITY ENGINE",
        "version": "0.1.0 BETA",
        "environment": "local",
    },
    "logging": {"level": "INFO", "max_bytes": 5242880, "backups": 3},
    "api": {
        "host": "127.0.0.1",
        "port": 8765,
        "enabled": True,
        "rate_limit_requests": 120,
        "rate_limit_window_seconds": 60,
        "max_body_bytes": 65536,
        "allow_scan_paths": [],
    },
    "database": {"path": "storage/database/ase.db"},
    "storage": {
        "logs_dir": "storage/logs",
        "antivirus_dir": "storage/antivirus",
        "reports_dir": "storage/reports",
        "backup_dir": "storage/backups",
    },
    "monitoring": {"watch_paths": [], "follow_symlinks": False},
    "realtime": {
        "enabled": True,
        "watch_paths": [],
        "interval_seconds": 3,
        "max_files": 5000,
        "prefer_native": True,
        "auto_scan": True,
    },
    "scan": {
        "max_file_size_mb": 64,
        "max_files": 10000,
        "max_archive_members": 2000,
        "max_archive_member_size_mb": 32,
        "max_archive_total_size_mb": 128,
        "yara_rules_path": "",
        "quick_scan_paths": [],
        "scheduled_enabled": False,
        "scheduled_interval_minutes": 1440,
        "scheduled_paths": [],
    },
    "quarantine": {"require_authorization": True, "max_items": 5000},
    "intelligence": {
        "indicator_ttl_days": 0,
        "trusted_feed_keys": [],
        "max_indicators": 100000,
    },
    "network": {"enabled": True, "alert_suppression_seconds": 900},
    "process": {"enabled": True, "max_processes": 1000},
    "analysis": {"correlation_window_seconds": 300, "alert_dedupe_seconds": 300},
    "scheduler": {"enabled": True},
}

_INT_SECTIONS = {
    "api": ("port", "rate_limit_requests", "rate_limit_window_seconds", "max_body_bytes"),
    "realtime": ("interval_seconds", "max_files"),
    "scan": (
        "max_file_size_mb",
        "max_files",
        "max_archive_members",
        "max_archive_member_size_mb",
        "max_archive_total_size_mb",
        "scheduled_interval_minutes",
    ),
    "quarantine": ("max_items",),
    "intelligence": ("indicator_ttl_days", "max_indicators"),
    "network": ("alert_suppression_seconds",),
    "process": ("max_processes",),
    "analysis": ("correlation_window_seconds", "alert_dedupe_seconds"),
    "logging": ("max_bytes", "backups"),
}


_ZERO_ALLOWED = {"indicator_ttl_days"}


def _merge(base, incoming):
    """Recursively merge ``incoming`` over a copy of ``base``."""
    result = copy.deepcopy(base)
    for key, value in incoming.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result


class ASEConfig:
    """Load, validate, save and query the engine configuration."""

    def __init__(self, path=DEFAULT_CONFIG_PATH):
        self.path = Path(path)
        self.data = copy.deepcopy(DEFAULTS)

    def load(self):
        if self.path.exists():
            try:
                incoming = json.loads(self.path.read_text("utf-8"))
            except json.JSONDecodeError as exc:
                raise ASEConfigError("Configuration file is not valid JSON: %s" % exc) from exc
            if not isinstance(incoming, dict):
                raise ASEConfigError("Configuration root must be an object")
            self.data = _merge(DEFAULTS, incoming)
        else:
            self.data = copy.deepcopy(DEFAULTS)
            self.save()
        self.validate()
        return self.data

    def validate(self):
        """Raise :class:`ASEConfigError` on any invalid value."""
        if not isinstance(self.data, dict):
            raise ASEConfigError("Configuration root must be an object")

        api = self.data.get("api") or {}
        host = api.get("host", "127.0.0.1")
        if host not in LOOPBACK_HOSTS:
            raise ASEConfigError("API must bind to loopback only (127.0.0.1, ::1 or localhost)")
        try:
            port = int(api.get("port", 8765))
        except (TypeError, ValueError) as exc:
            raise ASEConfigError("api.port must be an integer") from exc
        if port not in range(1024, 65536):
            raise ASEConfigError("API port must be between 1024 and 65535")
        for key in _INT_SECTIONS["api"]:
            if int(api.get(key, DEFAULTS["api"][key])) < 1:
                raise ASEConfigError("api.%s must be positive" % key)

        for section in ("monitoring", "realtime", "scan"):
            cfg = self.data.get(section) or {}
            if cfg.get("follow_symlinks", False):
                raise ASEConfigError("Following symbolic links is not supported")
        for section, key in (
            ("monitoring", "watch_paths"),
            ("realtime", "watch_paths"),
            ("scan", "quick_scan_paths"),
            ("scan", "scheduled_paths"),
            ("api", "allow_scan_paths"),
            ("intelligence", "trusted_feed_keys"),
        ):
            value = (self.data.get(section) or {}).get(key, [])
            if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                raise ASEConfigError("%s.%s must be a list of strings" % (section, key))

        for section, keys in _INT_SECTIONS.items():
            cfg = self.data.get(section) or {}
            for key in keys:
                default = DEFAULTS.get(section, {}).get(key, 1)
                try:
                    value = int(cfg.get(key, default))
                except (TypeError, ValueError) as exc:
                    raise ASEConfigError("%s.%s must be an integer" % (section, key)) from exc
                minimum = 0 if key in _ZERO_ALLOWED else 1
                if value < minimum:
                    raise ASEConfigError("%s.%s must be >= %d" % (section, key, minimum))

        scan = self.data.get("scan") or {}
        if int(scan.get("max_file_size_mb", 64)) > 1024:
            raise ASEConfigError("scan.max_file_size_mb must not exceed 1024")
        realtime = self.data.get("realtime") or {}
        interval = int(realtime.get("interval_seconds", 3))
        if not 1 <= interval <= 3600:
            raise ASEConfigError("realtime.interval_seconds must be between 1 and 3600")
        level = str((self.data.get("logging") or {}).get("level", "INFO")).upper()
        if level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            raise ASEConfigError("logging.level must be a standard log level")
        return True

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.validate()
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(self.data, indent=4, ensure_ascii=False), "utf-8")
        tmp.replace(self.path)

    def get(self, key, default=None):
        return self.data.get(key, default)

    def section(self, name):
        return self.data.get(name) or {}

    def update(self, section, values):
        """Merge ``values`` into ``section``, validate and persist."""
        current = dict(self.data.get(section) or {})
        current.update(values)
        candidate = _merge(self.data, {section: current})
        previous = self.data
        self.data = candidate
        try:
            self.validate()
        except ASEConfigError:
            self.data = previous
            raise
        self.save()
        return self.data[section]
