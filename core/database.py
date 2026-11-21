"""SQLite persistence with versioned migrations and transactional writes.

The schema is described by an ordered list of migrations. ``user_version``
records the applied level so an existing database is upgraded in place and
never recreated, preserving user data.
"""
from __future__ import annotations

import json
import shutil
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock

from core.exceptions import ASEDatabaseError

SCHEMA_VERSION = 3

MIGRATIONS = {
    1: [
        """CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            details TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type)",
        "CREATE INDEX IF NOT EXISTS idx_security_events_created ON security_events(created_at)",
        """CREATE TABLE IF NOT EXISTS scheduler_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_name TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT NOT NULL,
            status TEXT NOT NULL,
            error TEXT
        )""",
        """CREATE TABLE IF NOT EXISTS file_baselines (
            file_path TEXT PRIMARY KEY,
            sha256 TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            size INTEGER NOT NULL DEFAULT 0,
            modified_ns INTEGER NOT NULL DEFAULT 0
        )""",
        """CREATE TABLE IF NOT EXISTS threat_indicators (
            indicator TEXT PRIMARY KEY,
            indicator_type TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT 'local',
            description TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        )""",
    ],
    2: [
        """CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT NOT NULL,
            target TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            total INTEGER NOT NULL DEFAULT 0,
            scanned INTEGER NOT NULL DEFAULT 0,
            detections INTEGER NOT NULL DEFAULT 0,
            errors INTEGER NOT NULL DEFAULT 0,
            skipped INTEGER NOT NULL DEFAULT 0,
            report TEXT NOT NULL DEFAULT '{}'
        )""",
        "CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at)",
        """CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            file_path TEXT NOT NULL,
            verdict TEXT NOT NULL,
            sha256 TEXT,
            risk_score INTEGER NOT NULL DEFAULT 0,
            findings TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )""",
        "CREATE INDEX IF NOT EXISTS idx_scan_results_scan ON scan_results(scan_id)",
        """CREATE TABLE IF NOT EXISTS quarantine (
            id TEXT PRIMARY KEY,
            original_path TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            size INTEGER NOT NULL DEFAULT 0,
            verdict TEXT NOT NULL DEFAULT '',
            findings TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL,
            restored_at TEXT,
            status TEXT NOT NULL DEFAULT 'quarantined'
        )""",
        """CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            risk_score INTEGER NOT NULL DEFAULT 0,
            subject TEXT NOT NULL DEFAULT '',
            reasons TEXT NOT NULL DEFAULT '[]',
            details TEXT NOT NULL DEFAULT '{}',
            incident_id TEXT,
            created_at TEXT NOT NULL,
            acknowledged_at TEXT,
            acknowledged_by TEXT,
            status TEXT NOT NULL DEFAULT 'open'
        )""",
        "CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_fingerprint ON alerts(fingerprint)",
        """CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            notes TEXT NOT NULL DEFAULT ''
        )""",
    ],
    3: [
        "ALTER TABLE threat_indicators ADD COLUMN confidence INTEGER NOT NULL DEFAULT 50",
        "ALTER TABLE threat_indicators ADD COLUMN expires_at TEXT",
        "ALTER TABLE threat_indicators ADD COLUMN updated_at TEXT",
    ],
}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


class ASEDatabase:
    """Thread-safe SQLite wrapper used by every module."""

    def __init__(self, path="storage/database/ase.db"):
        self.path = Path(path)
        self.connection = None
        self.lock = RLock()

    def start(self):
        with self.lock:
            if self.connection is not None:
                return
            if self.path.is_symlink():
                raise ASEDatabaseError("Database path must not be a symbolic link")
            self.path.parent.mkdir(parents=True, exist_ok=True)
            try:
                self.connection = sqlite3.connect(str(self.path), check_same_thread=False, timeout=15)
            except sqlite3.Error as exc:
                raise ASEDatabaseError("Database open failed: %s" % exc) from exc
            self.connection.row_factory = sqlite3.Row
            self.connection.execute("PRAGMA foreign_keys=ON")
            self.connection.execute("PRAGMA journal_mode=WAL")
            self.connection.execute("PRAGMA busy_timeout=5000")
            self._migrate()

    def stop(self):
        with self.lock:
            if self.connection is not None:
                try:
                    self.connection.commit()
                except sqlite3.Error:
                    pass
                self.connection.close()
                self.connection = None

    @property
    def ready(self):
        return self.connection is not None

    def _require(self):
        if self.connection is None:
            raise ASEDatabaseError("Database is not started")
        return self.connection

    @contextmanager
    def transaction(self):
        """Run a block atomically; roll back on any exception."""
        connection = self._require()
        with self.lock:
            try:
                yield connection
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def _migrate(self):
        connection = self.connection
        current = connection.execute("PRAGMA user_version").fetchone()[0]
        if current == 0:
            # A legacy database may already hold tables but no version stamp.
            tables = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            current = 1 if "security_events" in tables else 0
        for version in range(current + 1, SCHEMA_VERSION + 1):
            for statement in MIGRATIONS[version]:
                try:
                    connection.execute(statement)
                except sqlite3.OperationalError as exc:
                    # A column added by an older ad-hoc migration is not fatal.
                    if "duplicate column name" not in str(exc).lower():
                        raise ASEDatabaseError("Migration %d failed: %s" % (version, exc)) from exc
            connection.execute("PRAGMA user_version=%d" % version)
        self._ensure_columns(connection)
        connection.commit()

    @staticmethod
    def _ensure_columns(connection):
        """Repair legacy tables created before a column existed."""
        expected = {
            "file_baselines": {
                "size": "INTEGER NOT NULL DEFAULT 0",
                "modified_ns": "INTEGER NOT NULL DEFAULT 0",
            },
            "threat_indicators": {
                "source": "TEXT NOT NULL DEFAULT 'local'",
                "description": "TEXT NOT NULL DEFAULT ''",
                "confidence": "INTEGER NOT NULL DEFAULT 50",
                "expires_at": "TEXT",
                "updated_at": "TEXT",
            },
        }
        for table, columns in expected.items():
            present = {row[1] for row in connection.execute("PRAGMA table_info(%s)" % table)}
            if not present:
                continue
            for name, declaration in columns.items():
                if name not in present:
                    connection.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, name, declaration))

    @property
    def schema_version(self):
        return self._require().execute("PRAGMA user_version").fetchone()[0]

    # ---------------------------------------------------------------- events
    def save_event(self, event_type, details, created_at=None):
        created_at = created_at or utc_now()
        payload = details if isinstance(details, str) else json.dumps(details, ensure_ascii=False, default=str)
        with self.lock:
            self._require().execute(
                "INSERT INTO security_events(event_type, details, created_at) VALUES(?,?,?)",
                (event_type, payload, created_at),
            )
            self.connection.commit()
        return True

    def get_events(self, limit=100, offset=0):
        limit = max(1, min(int(limit), 1000))
        offset = max(0, int(offset))
        with self.lock:
            rows = self._require().execute(
                "SELECT id, event_type, details, created_at FROM security_events ORDER BY id DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_recent_events(self, limit=10):
        return self.get_events(limit=limit)

    def count_events(self):
        with self.lock:
            return self._require().execute("SELECT COUNT(*) FROM security_events").fetchone()[0]

    def search_events(self, event_type=None, risk_level=None, start_date=None, end_date=None, limit=10, offset=0):
        limit = int(limit)
        offset = int(offset)
        if not 1 <= limit <= 1000:
            raise ValueError("Limit must be between 1 and 1000")
        if offset < 0:
            raise ValueError("Offset cannot be negative")
        query = "SELECT id, event_type, details, created_at FROM security_events WHERE 1=1"
        params = []
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if start_date:
            query += " AND created_at >= ?"
            params.append(start_date)
        if end_date:
            query += " AND created_at <= ?"
            params.append(end_date)
        query += " ORDER BY id DESC"
        with self.lock:
            rows = [dict(row) for row in self._require().execute(query, params).fetchall()]
        if risk_level:
            wanted = risk_level.lower()
            rows = [r for r in rows if _details_level(r.get("details")) == wanted]
        return {"total": len(rows), "limit": limit, "offset": offset, "events": rows[offset:offset + limit]}

    # ---------------------------------------------------------------- scheduler
    def save_scheduler_run(self, task_name, started_at, finished_at, status, error=None):
        with self.lock:
            self._require().execute(
                "INSERT INTO scheduler_history(task_name, started_at, finished_at, status, error) VALUES(?,?,?,?,?)",
                (task_name, started_at, finished_at, status, error),
            )
            self.connection.commit()

    def get_scheduler_history(self, task_name=None, limit=20):
        limit = max(1, min(int(limit), 500))
        with self.lock:
            if task_name:
                rows = self._require().execute(
                    "SELECT id, task_name, started_at, finished_at, status, error FROM scheduler_history "
                    "WHERE task_name = ? ORDER BY id DESC LIMIT ?",
                    (task_name, limit),
                ).fetchall()
            else:
                rows = self._require().execute(
                    "SELECT id, task_name, started_at, finished_at, status, error FROM scheduler_history "
                    "ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [dict(row) for row in rows]

    # ---------------------------------------------------------------- baselines
    def get_baseline(self, file_path):
        with self.lock:
            row = self._require().execute(
                "SELECT sha256, size, modified_ns FROM file_baselines WHERE file_path = ?", (str(file_path),)
            ).fetchone()
        return dict(row) if row else None

    def set_baseline(self, file_path, sha256, size, modified_ns, updated_at=None):
        with self.lock:
            self._require().execute(
                "INSERT INTO file_baselines(file_path, sha256, updated_at, size, modified_ns) VALUES(?,?,?,?,?) "
                "ON CONFLICT(file_path) DO UPDATE SET sha256=excluded.sha256, updated_at=excluded.updated_at, "
                "size=excluded.size, modified_ns=excluded.modified_ns",
                (str(file_path), sha256, updated_at or utc_now(), int(size), int(modified_ns)),
            )
            self.connection.commit()

    # ---------------------------------------------------------------- indicators
    def add_indicator(self, indicator, indicator_type, source="local", description="", confidence=50, expires_at=None, created_at=None):
        if indicator_type not in ("ip", "domain", "sha256"):
            raise ValueError("Unsupported indicator type")
        if not isinstance(indicator, str) or not indicator.strip():
            raise ValueError("Indicator must be non-empty")
        key = indicator.strip().lower()
        confidence = max(0, min(int(confidence), 100))
        now = created_at or utc_now()
        with self.lock:
            self._require().execute(
                "INSERT INTO threat_indicators(indicator, indicator_type, source, description, created_at, "
                "confidence, expires_at, updated_at) VALUES(?,?,?,?,?,?,?,?) "
                "ON CONFLICT(indicator) DO UPDATE SET indicator_type=excluded.indicator_type, "
                "source=excluded.source, description=excluded.description, confidence=excluded.confidence, "
                "expires_at=excluded.expires_at, updated_at=excluded.updated_at",
                (key, indicator_type, str(source)[:128], str(description)[:500], now, confidence, expires_at, now),
            )
            self.connection.commit()
        return key

    def get_indicators(self, indicator_type=None, include_expired=False):
        query = ("SELECT indicator, indicator_type, source, description, created_at, confidence, expires_at, "
                 "updated_at FROM threat_indicators")
        params = []
        if indicator_type:
            query += " WHERE indicator_type = ?"
            params.append(indicator_type)
        query += " ORDER BY indicator"
        now = utc_now()
        with self.lock:
            rows = self._require().execute(query, params).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            if not include_expired and item.get("expires_at") and item["expires_at"] < now:
                continue
            out.append(item)
        return out

    def get_indicator(self, indicator):
        with self.lock:
            row = self._require().execute(
                "SELECT indicator, indicator_type, source, description, created_at, confidence, expires_at, "
                "updated_at FROM threat_indicators WHERE indicator = ?", (str(indicator).strip().lower(),)
            ).fetchone()
        return dict(row) if row else None

    def delete_indicator(self, indicator):
        with self.lock:
            cursor = self._require().execute(
                "DELETE FROM threat_indicators WHERE indicator = ?", (str(indicator).strip().lower(),))
            self.connection.commit()
        return cursor.rowcount > 0

    def purge_expired_indicators(self):
        now = utc_now()
        with self.lock:
            cursor = self._require().execute(
                "DELETE FROM threat_indicators WHERE expires_at IS NOT NULL AND expires_at < ?", (now,))
            self.connection.commit()
        return cursor.rowcount

    # ---------------------------------------------------------------- scans
    def create_scan(self, scan_type, target):
        with self.lock:
            cursor = self._require().execute(
                "INSERT INTO scans(scan_type, target, status, started_at) VALUES(?,?,?,?)",
                (scan_type, str(target)[:1024], "running", utc_now()),
            )
            self.connection.commit()
            return cursor.lastrowid

    def finish_scan(self, scan_id, status, summary, results=None):
        finished = utc_now()
        with self.transaction() as connection:
            connection.execute(
                "UPDATE scans SET status=?, finished_at=?, total=?, scanned=?, detections=?, errors=?, skipped=?, report=? "
                "WHERE id=?",
                (
                    status, finished,
                    int(summary.get("total", 0)), int(summary.get("scanned", 0)),
                    int(summary.get("detections", 0)), int(summary.get("errors", 0)),
                    int(summary.get("skipped", 0)),
                    json.dumps(summary, ensure_ascii=False, default=str)[:200000], scan_id,
                ),
            )
            for item in results or []:
                connection.execute(
                    "INSERT INTO scan_results(scan_id, file_path, verdict, sha256, risk_score, findings, created_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (
                        scan_id, str(item.get("file", ""))[:2048], str(item.get("status", "scan_error")),
                        item.get("sha256"), int(item.get("risk_score", 0)),
                        json.dumps(item.get("findings", []), ensure_ascii=False, default=str)[:20000], finished,
                    ),
                )

    def get_scan(self, scan_id):
        with self.lock:
            row = self._require().execute("SELECT * FROM scans WHERE id=?", (int(scan_id),)).fetchone()
        return dict(row) if row else None

    def get_scans(self, limit=20, offset=0, scan_type=None):
        limit = max(1, min(int(limit), 200))
        offset = max(0, int(offset))
        query = "SELECT * FROM scans"
        params = []
        if scan_type:
            query += " WHERE scan_type=?"
            params.append(scan_type)
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        with self.lock:
            rows = self._require().execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def get_scan_results(self, scan_id, limit=1000):
        with self.lock:
            rows = self._require().execute(
                "SELECT file_path, verdict, sha256, risk_score, findings FROM scan_results "
                "WHERE scan_id=? ORDER BY id LIMIT ?", (int(scan_id), int(limit))
            ).fetchall()
        return [dict(row) for row in rows]

    def get_scan_statistics(self):
        with self.lock:
            connection = self._require()
            total = connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            by_type = connection.execute("SELECT scan_type, COUNT(*) FROM scans GROUP BY scan_type").fetchall()
            by_verdict = connection.execute("SELECT verdict, COUNT(*) FROM scan_results GROUP BY verdict").fetchall()
            latest = connection.execute("SELECT MAX(finished_at) FROM scans").fetchone()[0]
        return {
            "total_scans": total,
            "by_type": {row[0]: row[1] for row in by_type},
            "by_verdict": {row[0]: row[1] for row in by_verdict},
            "last_scan_at": latest,
        }

    # ---------------------------------------------------------------- quarantine
    def add_quarantine(self, quarantine_id, original_path, stored_name, sha256, size, verdict, findings):
        with self.lock:
            self._require().execute(
                "INSERT INTO quarantine(id, original_path, stored_name, sha256, size, verdict, findings, "
                "created_at, status) VALUES(?,?,?,?,?,?,?,?,?)",
                (quarantine_id, str(original_path)[:2048], stored_name, sha256, int(size), verdict,
                 json.dumps(findings, ensure_ascii=False, default=str)[:20000], utc_now(), "quarantined"),
            )
            self.connection.commit()

    def get_quarantine(self, quarantine_id):
        with self.lock:
            row = self._require().execute(
                "SELECT * FROM quarantine WHERE id=?", (str(quarantine_id),)).fetchone()
        return dict(row) if row else None

    def get_quarantined(self, limit=100):
        with self.lock:
            rows = self._require().execute(
                "SELECT * FROM quarantine WHERE status='quarantined' ORDER BY created_at DESC LIMIT ?",
                (max(1, min(int(limit), 1000)),),
            ).fetchall()
        return [dict(row) for row in rows]

    def mark_restored(self, quarantine_id):
        with self.lock:
            self._require().execute(
                "UPDATE quarantine SET status='restored', restored_at=? WHERE id=?",
                (utc_now(), str(quarantine_id)))
            self.connection.commit()

    def count_quarantined(self):
        with self.lock:
            return self._require().execute(
                "SELECT COUNT(*) FROM quarantine WHERE status='quarantined'").fetchone()[0]

    # ---------------------------------------------------------------- alerts
    def add_alert(self, alert):
        with self.lock:
            cursor = self._require().execute(
                "INSERT INTO alerts(fingerprint, event_type, severity, risk_score, subject, reasons, details, "
                "incident_id, created_at, status) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    alert.get("fingerprint", ""),
                    alert.get("event_type", "unknown"),
                    alert.get("severity", "low"),
                    int(alert.get("risk_score", 0)),
                    str(alert.get("subject", ""))[:1024],
                    json.dumps(alert.get("reasons", []), ensure_ascii=False)[:8000],
                    json.dumps(alert.get("details", {}), ensure_ascii=False, default=str)[:20000],
                    alert.get("incident_id"),
                    alert.get("created_at") or utc_now(),
                    alert.get("status", "open"),
                ),
            )
            self.connection.commit()
            return cursor.lastrowid

    def get_alerts(self, limit=50, offset=0, status=None, severity=None):
        limit = max(1, min(int(limit), 500))
        offset = max(0, int(offset))
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []
        if status:
            query += " AND status=?"
            params.append(status)
        if severity:
            query += " AND severity=?"
            params.append(severity)
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        with self.lock:
            rows = self._require().execute(query, params).fetchall()
        return [_alert_row(row) for row in rows]

    def get_alert(self, alert_id):
        with self.lock:
            row = self._require().execute("SELECT * FROM alerts WHERE id=?", (int(alert_id),)).fetchone()
        return _alert_row(row) if row else None

    def find_recent_alert(self, fingerprint, since):
        with self.lock:
            row = self._require().execute(
                "SELECT * FROM alerts WHERE fingerprint=? AND created_at>=? ORDER BY id DESC LIMIT 1",
                (fingerprint, since),
            ).fetchone()
        return _alert_row(row) if row else None

    def acknowledge_alert(self, alert_id, actor="operator"):
        with self.lock:
            cursor = self._require().execute(
                "UPDATE alerts SET status='acknowledged', acknowledged_at=?, acknowledged_by=? "
                "WHERE id=? AND status='open'",
                (utc_now(), str(actor)[:128], int(alert_id)),
            )
            self.connection.commit()
        return cursor.rowcount > 0

    def count_alerts(self):
        with self.lock:
            return self._require().execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    # ---------------------------------------------------------------- incidents
    def upsert_incident(self, incident_id, title, severity):
        now = utc_now()
        with self.lock:
            self._require().execute(
                "INSERT INTO incidents(id, title, severity, created_at, updated_at) VALUES(?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET severity=excluded.severity, updated_at=excluded.updated_at",
                (incident_id, str(title)[:512], severity, now, now),
            )
            self.connection.commit()

    def get_incidents(self, limit=50):
        with self.lock:
            rows = self._require().execute(
                "SELECT * FROM incidents ORDER BY updated_at DESC LIMIT ?",
                (max(1, min(int(limit), 200)),),
            ).fetchall()
        return [dict(row) for row in rows]

    # ---------------------------------------------------------------- maintenance
    def backup(self, destination):
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with self.lock:
            connection = self._require()
            target = sqlite3.connect(str(destination))
            try:
                connection.backup(target)
            finally:
                target.close()
        return str(destination)

    def restore_from(self, source):
        """Replace the live database with a backup file, then re-open."""
        source = Path(source)
        if not source.is_file():
            raise ASEDatabaseError("Backup file not found")
        with self.lock:
            self.stop()
            shutil.copyfile(source, self.path)
            self.start()
        return True

    def statistics(self):
        with self.lock:
            connection = self._require()
            return {
                "path": str(self.path),
                "schema_version": connection.execute("PRAGMA user_version").fetchone()[0],
                "size_bytes": self.path.stat().st_size if self.path.exists() else 0,
                "events": connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0],
                "indicators": connection.execute("SELECT COUNT(*) FROM threat_indicators").fetchone()[0],
                "alerts": connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
                "quarantined": connection.execute(
                    "SELECT COUNT(*) FROM quarantine WHERE status='quarantined'").fetchone()[0],
                "scans": connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0],
            }


def _details_level(details):
    try:
        return str(json.loads(details).get("risk_level", "")).lower()
    except (json.JSONDecodeError, TypeError, AttributeError):
        return ""


def _alert_row(row):
    item = dict(row)
    try:
        item["reasons"] = json.loads(item["reasons"]) if item.get("reasons") else []
    except (json.JSONDecodeError, TypeError):
        item["reasons"] = []
    try:
        item["details"] = json.loads(item["details"]) if item.get("details") else {}
    except (json.JSONDecodeError, TypeError):
        item["details"] = {}
    details = item["details"] if isinstance(item["details"], dict) else {}
    # Fields that live inside the stored detail blob are surfaced for callers.
    item.setdefault("recommendation", details.get("recommendation"))
    item.setdefault("action", details.get("action"))
    item.setdefault("file", details.get("file"))
    item.setdefault("indicator", details.get("indicator"))
    item.setdefault("event", details.get("event", item.get("event_type")))
    return item
