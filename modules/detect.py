"""File baseline tracking and static indicator checks (read-only).

This module stores hashes so a later change can be detected. It never writes to
the files it inspects.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


class ASEDetect:
    def __init__(self, event_bus, database, settings=None):
        self.event_bus = event_bus
        self.database = database
        self.settings = settings or {}
        self.max_file_size = int(self.settings.get("max_file_size_mb", 64)) * 1024 * 1024
        self.max_files = max(1, min(int(self.settings.get("max_files", 10000)), 20000))

    def start(self):
        # The schema is owned by ASEDatabase migrations; nothing to create here.
        return True

    def stop(self):
        return True

    def calculate_hash(self, file_path):
        path = Path(file_path)
        if path.is_symlink():
            raise ValueError("Symbolic links are not hashed")
        if not path.is_file():
            raise FileNotFoundError("File not found: %s" % file_path)
        if path.stat().st_size > self.max_file_size:
            raise ValueError("File exceeds configured hash size limit")
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def monitor_file(self, file_path):
        original = Path(file_path).expanduser()
        if original.is_symlink():
            raise ValueError("Symbolic links are not monitored")
        path = original.resolve(strict=True)
        stat_result = path.stat()
        current_hash = self.calculate_hash(path)

        record = self.database.get_baseline(str(path))
        timestamp = _now_iso()
        status = "unchanged" if record else "baseline_created"
        previous_hash = record["sha256"] if record else None

        if record is None:
            self.database.set_baseline(str(path), current_hash, stat_result.st_size,
                                       stat_result.st_mtime_ns, timestamp)
        elif record["sha256"] != current_hash:
            status = "file_changed"
            self.database.set_baseline(str(path), current_hash, stat_result.st_size,
                                       stat_result.st_mtime_ns, timestamp)

        if status == "file_changed" and self.event_bus is not None:
            try:
                self.event_bus.publish("detect.file_changed", {
                    "file": str(path), "old_hash": previous_hash, "new_hash": current_hash,
                    "timestamp": timestamp, "size": stat_result.st_size,
                })
            except Exception:
                pass
        return {"file": str(path), "status": status, "sha256": current_hash}

    def scan_file(self, file_path):
        """Bounded, read-only static checks for one regular file."""
        path = Path(file_path).expanduser()
        if path.is_symlink():
            raise ValueError("Symbolic links are not scanned")
        path = path.resolve(strict=True)
        if not path.is_file():
            raise FileNotFoundError(str(path))
        digest = self.calculate_hash(path)

        findings = []
        suffixes = [item.lower() for item in path.suffixes]
        executable_suffixes = {".exe", ".scr", ".bat", ".cmd", ".com", ".js", ".vbs", ".ps1", ".sh"}
        # A double extension is only a weak indicator; never treated as proof.
        if len(suffixes) >= 2 and suffixes[-1] in executable_suffixes and suffixes[-2] not in executable_suffixes:
            findings.append({
                "rule": "DOUBLE_EXTENSION", "severity": "low", "confidence": "low",
                "detail": "File has a document-like extension followed by an executable or script extension.",
            })

        indicator = None
        if getattr(self.database, "ready", False):
            try:
                indicator = self.database.get_indicator(digest)
            except Exception:
                indicator = None
        if indicator and indicator.get("indicator_type") == "sha256":
            findings.append({
                "rule": "LOCAL_SHA256_INDICATOR", "severity": "high", "confidence": "high",
                "detail": "File SHA-256 matched a locally stored threat indicator.",
            })

        if any(item["severity"] == "high" for item in findings):
            status = "malicious_indicator"
        elif findings:
            status = "suspicious"
        else:
            status = "no_known_indicators"
        result = {"file": str(path), "status": status, "sha256": digest,
                  "findings": findings, "modified": False}
        if findings and self.event_bus is not None:
            try:
                self.event_bus.publish("detect.static_finding", result)
            except Exception:
                pass
        return result

    def scan_directory(self, directory):
        root = Path(directory).expanduser()
        if root.is_symlink():
            raise ValueError("Symbolic-link directories are not scanned")
        root = root.resolve(strict=True)
        if not root.is_dir():
            raise NotADirectoryError(str(root))
        results = []
        for current, dirs, names in os_walk(root):
            dirs[:] = [d for d in dirs if not (Path(current) / d).is_symlink()]
            for name in names:
                candidate = Path(current) / name
                if candidate.is_symlink() or not candidate.is_file():
                    continue
                try:
                    results.append(self.monitor_file(candidate))
                except (OSError, ValueError) as exc:
                    results.append({"file": str(candidate), "status": "error", "error": str(exc)})
                if len(results) >= self.max_files:
                    break
            if len(results) >= self.max_files:
                break
        summary = {
            "directory": str(root),
            "total": len(results),
            "baseline_created": sum(item["status"] == "baseline_created" for item in results),
            "changed": sum(item["status"] == "file_changed" for item in results),
            "unchanged": sum(item["status"] == "unchanged" for item in results),
            "errors": sum(item["status"] == "error" for item in results),
            "results": results,
        }
        if self.event_bus is not None:
            try:
                self.event_bus.publish("detect.directory_scanned", summary)
            except Exception:
                pass
        return summary

    def get_status(self):
        return {"running": True, "mode": "read_only_baseline",
                "max_file_size_bytes": self.max_file_size, "max_files": self.max_files}


def os_walk(root):
    import os
    return os.walk(root, followlinks=False)
