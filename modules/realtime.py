"""Configured-directory monitoring: native events where available, polling otherwise.

This is *not* operating-system-wide protection. Only directories the operator
explicitly configures are watched, and the module always reports the exact
directories it is watching plus the mechanism it is using.
"""
from __future__ import annotations

import os
import platform
import select
import struct
import threading
import time
from pathlib import Path

from modules.antivirus import DETECTION_VERDICTS


def _inotify_available():
    return hasattr(select, "epoll") and Path("/proc/sys/fs/inotify/max_user_watches").exists()


class ASERealtimeMonitor:
    """Watch configured directories and scan files that change."""

    def __init__(self, antivirus, event_bus=None, interval=3, max_files=5000,
                 prefer_native=True, auto_scan=True):
        self.antivirus = antivirus
        self.event_bus = event_bus
        self.interval = max(1, min(int(interval), 3600))
        self.max_files = max(1, min(int(max_files), 20000))
        self.prefer_native = bool(prefer_native)
        self.auto_scan = bool(auto_scan)

        self.running = False
        self.roots = []
        self.mode = "stopped"
        self._thread = None
        self._stop = threading.Event()
        self._lock = threading.RLock()

        self._seen = {}
        self._hashes = {}
        self._deleted = []

        self.last_cycle = None
        self.last_results = []
        self.last_error = None
        self.total_cycles = 0
        self.total_events = 0
        self.total_scans = 0
        self.started_at = None
        self.error_count = 0

    # ------------------------------------------------------------- configure
    def configure(self, roots):
        """Replace the watch list. Invalid entries are rejected and reported."""
        clean, rejected = [], []
        for item in roots or []:
            try:
                path = Path(item).expanduser().resolve(strict=True)
            except (OSError, RuntimeError):
                rejected.append(str(item))
                continue
            if path.is_dir() and not path.is_symlink():
                if path not in clean:
                    clean.append(path)
            else:
                rejected.append(str(item))
        with self._lock:
            self.roots = clean
        self.last_error = None if not rejected else "rejected_paths: %s" % ", ".join(rejected[:10])
        return [str(path) for path in clean]

    def add_path(self, path):
        configured = [str(item) for item in self.roots] + [str(path)]
        return self.configure(configured)

    # ------------------------------------------------------------- scanning
    def scan_once(self):
        """One polling pass: detect new, modified and deleted files."""
        with self._lock:
            roots = list(self.roots)
        results = []
        deleted = []
        count = 0
        seen_now = {}

        for root in roots:
            for current, dirs, names in os.walk(root, followlinks=False):
                dirs[:] = [d for d in dirs if not (Path(current) / d).is_symlink()]
                for name in names:
                    path = Path(current) / name
                    if path.is_symlink() or not path.is_file():
                        continue
                    key = str(path)
                    try:
                        stat_result = path.stat()
                    except OSError:
                        continue
                    stamp = (stat_result.st_size, stat_result.st_mtime_ns)
                    seen_now[key] = stamp
                    if self._seen.get(key) == stamp:
                        continue
                    change = "modified" if key in self._seen else "created"
                    self._seen[key] = stamp
                    count += 1
                    if count > self.max_files:
                        break
                    if self.auto_scan:
                        try:
                            result = self.antivirus.scan_file(path)
                        except Exception as exc:
                            result = {"file": key, "status": "scan_error",
                                      "error": "%s: %s" % (type(exc).__name__, str(exc)[:160])}
                        result = dict(result)
                        result["change"] = change
                        results.append(result)
                        self.total_scans += 1
                        self._publish(result, change)
                if count > self.max_files:
                    break
            if count > self.max_files:
                break

        # Files previously seen but now absent count as deletions.
        for key in list(self._seen):
            if key not in seen_now:
                del self._seen[key]
                self._hashes.pop(key, None)
                deleted.append(key)
                if self.event_bus is not None:
                    try:
                        self.event_bus.publish("realtime.file_deleted", {"file": key,
                                                                         "timestamp": time.time()})
                    except Exception:
                        pass

        with self._lock:
            self.last_results = results
            self.last_cycle = time.time()
            self.total_cycles += 1
            self.total_events += len(results) + len(deleted)
            if deleted:
                self._deleted = (self._deleted + deleted)[-200:]
            self.last_error = None
        return {
            "scanned": len(results),
            "detections": sum(1 for item in results if item.get("status") in DETECTION_VERDICTS),
            "deleted": len(deleted),
            "results": results,
        }

    def _publish(self, result, change):
        if self.event_bus is None:
            return
        payload = dict(result)
        payload["change"] = change
        try:
            self.event_bus.publish("realtime.file_changed", payload)
            if result.get("status") in DETECTION_VERDICTS:
                self.event_bus.publish("antivirus.detection", payload)
        except Exception:
            pass

    # ------------------------------------------------------------- native watch
    def _run_native(self):
        """Watch with inotify, falling back to polling if setup fails."""
        import ctypes
        import ctypes.util

        libc_name = ctypes.util.find_library("c") or "libc.so.6"
        libc = ctypes.CDLL(libc_name, use_errno=True)
        fd = libc.inotify_init1(os.O_NONBLOCK)
        if fd < 0:
            raise OSError("inotify_init1 failed")

        mask = 0x00000002 | 0x00000004 | 0x00000008 | 0x00000040 | 0x00000080 | 0x00000100 | 0x00000200
        watch_map = {}
        for root in list(self.roots):
            wd = libc.inotify_add_watch(fd, str(root).encode("utf-8"), mask)
            if wd < 0:
                os.close(fd)
                raise OSError("inotify_add_watch failed for %s" % root)
            watch_map[wd] = root

        self.mode = "native_inotify"
        last_poll = 0.0
        try:
            while not self._stop.is_set():
                ready, _, _ = select.select([fd], [], [], 0.5)
                if ready:
                    try:
                        buffer = os.read(fd, 65536)
                    except BlockingIOError:
                        buffer = b""
                    for event in self._parse_inotify(buffer, watch_map):
                        self._handle_native_event(event)
                # A slow safety poll also catches changes in subdirectories.
                now = time.time()
                if now - last_poll >= max(self.interval * 5, 15):
                    last_poll = now
                    try:
                        self.scan_once()
                    except Exception as exc:
                        self.last_error = "%s: %s" % (type(exc).__name__, str(exc)[:240])
        finally:
            os.close(fd)

    @staticmethod
    def _parse_inotify(buffer, watch_map):
        events = []
        offset = 0
        length = len(buffer)
        while offset + 16 <= length:
            wd, mask, cookie, name_len = struct.unpack_from("iIII", buffer, offset)
            offset += 16
            name = buffer[offset:offset + name_len].split(b"\x00")[0].decode("utf-8", "replace")
            offset += name_len
            root = watch_map.get(wd)
            if root is None or not name:
                continue
            events.append({"root": root, "name": name, "mask": mask, "cookie": cookie})
        return events

    def _handle_native_event(self, event):
        mask = event["mask"]
        if mask & 0x00000100:  # IN_IGNORED
            return
        path = event["root"] / event["name"]
        try:
            if path.is_symlink():
                return
        except OSError:
            return
        if not path.is_file():
            return
        key = str(path)
        try:
            stat_result = path.stat()
        except OSError:
            if self.event_bus is not None:
                try:
                    self.event_bus.publish("realtime.file_deleted", {"file": key, "timestamp": time.time()})
                except Exception:
                    pass
            return
        stamp = (stat_result.st_size, stat_result.st_mtime_ns)
        if self._seen.get(key) == stamp:
            return  # duplicate event suppression
        self._seen[key] = stamp
        if not self.auto_scan:
            return
        try:
            result = dict(self.antivirus.scan_file(path))
        except Exception as exc:
            result = {"file": key, "status": "scan_error",
                      "error": "%s: %s" % (type(exc).__name__, str(exc)[:160])}
        result["change"] = "modified" if mask & 0x00000002 else "created"
        with self._lock:
            self.total_scans += 1
            self.total_events += 1
            self.last_results = (self.last_results + [result])[-200:]
        self._publish(result, result["change"])

    # ------------------------------------------------------------- polling
    def _run_polling(self):
        self.mode = "bounded_polling"
        while not self._stop.is_set():
            try:
                self.scan_once()
            except Exception as exc:
                with self._lock:
                    self.error_count += 1
                    self.last_error = "%s: %s" % (type(exc).__name__, str(exc)[:240])
            self._stop.wait(self.interval)

    def _run(self):
        if self.prefer_native and _inotify_available():
            try:
                self._run_native()
                return
            except Exception as exc:
                self.last_error = "native_watch_unavailable: %s" % str(exc)[:160]
        self._run_polling()

    # ------------------------------------------------------------- lifecycle
    def start(self):
        with self._lock:
            if self.running:
                return True
            if not self.roots:
                self.mode = "idle_no_paths"
                self.running = False
                return False
            self._stop.clear()
            self.running = True
            self.started_at = time.time()
            self._thread = threading.Thread(target=self._run, name="ase-realtime-monitor", daemon=True)
            self._thread.start()
        return True

    def stop(self):
        with self._lock:
            self._stop.set()
            thread = self._thread
            self.running = False
            self._thread = None
        if thread and thread.is_alive():
            thread.join(timeout=max(2, self.interval + 1))
        self.mode = "stopped"
        return True

    # ------------------------------------------------------------- health
    def health(self):
        with self._lock:
            now = time.time()
            stale = bool(self.last_cycle and now - self.last_cycle > max(self.interval * 5, 60))
            if not self.roots:
                state = "idle"
            elif not self.running:
                state = "stopped"
            elif self.last_error and self.error_count > 5:
                state = "degraded"
            elif stale and self.mode == "bounded_polling":
                state = "stalled"
            else:
                state = "healthy"
            return {
                "state": state,
                "running": self.running,
                "mode": self.mode,
                "watch_paths": [str(path) for path in self.roots],
                "interval_seconds": self.interval,
                "last_cycle": self.last_cycle,
                "seconds_since_cycle": round(now - self.last_cycle, 1) if self.last_cycle else None,
                "error_count": self.error_count,
                "last_error": self.last_error,
                "scope": "configured_directories_only",
            }

    def get_status(self):
        with self._lock:
            return {
                "running": self.running,
                "mode": self.mode,
                "interval_seconds": self.interval,
                "roots": [str(path) for path in self.roots],
                "watched_file_count": len(self._seen),
                "last_cycle": self.last_cycle,
                "last_scanned": len(self.last_results),
                "last_detections": sum(
                    1 for item in self.last_results if item.get("status") in DETECTION_VERDICTS),
                "total_cycles": self.total_cycles,
                "total_events": self.total_events,
                "total_scans": self.total_scans,
                "recent_deletions": list(self._deleted[-20:]),
                "last_error": self.last_error,
                "platform": platform.system(),
                "native_events_supported": _inotify_available(),
                "protection_scope": "configured_directories_only",
            }
