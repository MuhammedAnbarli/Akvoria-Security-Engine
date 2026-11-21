"""Read-only process inventory. Never terminates or modifies a process."""
from __future__ import annotations

import os
import platform
import subprocess
import threading


class ASEProcessMonitor:
    def __init__(self, event_bus=None, settings=None):
        self.event_bus = event_bus
        self.settings = settings or {}
        self.max_processes = max(1, min(int(self.settings.get("max_processes", 1000)), 10000))
        self.running = False
        self._lock = threading.RLock()
        self._last = []
        self.last_error = None

    def start(self):
        with self._lock:
            self.running = True
        return True

    def stop(self):
        with self._lock:
            self.running = False
        return True

    @staticmethod
    def is_supported():
        from core.platform_info import PlatformInfo
        if os.name == "nt":
            try:
                import psutil  # noqa: F401
                return True
            except ImportError:
                return False
        return PlatformInfo.has_procfs()

    def _linux_processes(self, limit):
        rows = []
        try:
            entries = os.scandir("/proc")
        except OSError as exc:
            self.last_error = "procfs unreadable: %s" % str(exc)[:120]
            return rows
        with entries:
            for entry in entries:
                if not entry.name.isdigit():
                    continue
                try:
                    with open(os.path.join(entry.path, "comm"), "r",
                              encoding="utf-8", errors="replace") as handle:
                        name = handle.read().strip()
                    with open(os.path.join(entry.path, "stat"), "r",
                              encoding="utf-8", errors="replace") as handle:
                        stat_text = handle.read()
                    # comm may contain spaces; parse fields after the final ')'.
                    tail = stat_text[stat_text.rfind(")") + 2:].split()
                    row = {"pid": int(entry.name), "name": name[:256],
                           "state": tail[0] if tail else "?", "platform": "linux"}
                    metadata = self._linux_metadata(entry.path)
                    row.update(metadata)
                    rows.append(row)
                except (OSError, ValueError, IndexError):
                    continue
                if len(rows) >= limit:
                    break
        return rows

    @staticmethod
    def _linux_metadata(proc_path):
        """Collect safe, permission-tolerant executable metadata."""
        meta = {"exe": None, "exe_accessible": False, "cmdline_length": 0, "uid": None}
        try:
            meta["exe"] = os.readlink(os.path.join(proc_path, "exe"))[:1024]
            meta["exe_accessible"] = True
        except OSError:
            pass  # normal for other users' processes without privileges
        try:
            with open(os.path.join(proc_path, "cmdline"), "rb") as handle:
                meta["cmdline_length"] = len(handle.read(4096))
        except OSError:
            pass
        try:
            meta["uid"] = os.stat(proc_path).st_uid
        except OSError:
            pass
        return meta

    def _windows_processes(self, limit):
        rows = []
        try:
            result = subprocess.run(["tasklist", "/FO", "CSV", "/NH"],
                                    capture_output=True, text=True, timeout=10, check=False)
            import csv
            import io
            for row in csv.reader(io.StringIO(result.stdout)):
                if len(row) >= 2:
                    try:
                        pid = int(row[1].replace(",", ""))
                    except ValueError:
                        continue
                    rows.append({"pid": pid, "name": row[0][:256], "state": "unknown",
                                 "platform": "windows", "memory": row[4] if len(row) > 4 else None})
                if len(rows) >= limit:
                    break
        except (OSError, subprocess.SubprocessError) as exc:
            self.last_error = "tasklist failed: %s" % str(exc)[:120]
        return rows

    def get_processes(self, limit=None):
        try:
            limit = max(1, min(int(limit or self.max_processes), 10000))
        except (TypeError, ValueError):
            limit = min(self.max_processes, 100)
        self.last_error = None
        if not self.is_supported():
            rows = []
            self.last_error = "process inventory unsupported on this platform"
        elif os.name == "nt":
            rows = self._windows_processes(limit)
        else:
            rows = self._linux_processes(limit)
        with self._lock:
            self._last = rows
        return rows

    def get_status(self):
        with self._lock:
            return {
                "running": self.running,
                "platform": platform.system(),
                "supported": self.is_supported(),
                "last_count": len(self._last),
                "mode": "read_only_inventory",
                "last_error": self.last_error,
                "note": "Processes are never terminated or modified.",
            }
