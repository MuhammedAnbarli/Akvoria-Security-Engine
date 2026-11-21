"""AKVORIA local, read-only malware inspection with explicit quarantine.

Scanning never modifies a file. Quarantine moves a file only when the caller
explicitly asks for it and the file carries a detection.

Verdict vocabulary is deliberately narrow so a caller can never mistake an
inconclusive result for a clean bill of health:

``no_known_indicators``
    No configured rule matched. This is *not* proof the file is harmless.
``suspicious``
    One or more heuristics matched.
``malicious_indicator``
    A local signature or high-confidence rule matched.
``scan_incomplete``
    The scan started but could not finish (limit, cancellation, unreadable).
``scan_error``
    The scan could not run at all.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import stat
import threading
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from core.exceptions import ASEQuarantineError, ASEScanError

MAX_FILE_SIZE = 64 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 2000
MAX_ARCHIVE_MEMBER_SIZE = 32 * 1024 * 1024
MAX_ARCHIVE_TOTAL_SIZE = 128 * 1024 * 1024
MAX_SCAN_FILES = 10000
CHUNK = 1024 * 1024

VERDICTS = (
    "no_known_indicators",
    "suspicious",
    "malicious_indicator",
    "scan_incomplete",
    "scan_error",
)
DETECTION_VERDICTS = ("suspicious", "malicious_indicator")

SEVERITY_SCORE = {"low": 25, "medium": 55, "high": 90, "critical": 100}

# EICAR is an industry-standard harmless antivirus test string, not malware.
_EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

_SCRIPT_MARKERS = {
    "encoded_powershell": (b"-enc", b"-encodedcommand"),
    "download_and_execute": (b"downloadstring", b"invoke-expression"),
    "dynamic_code_execution": (b"eval(", b"exec("),
    "shell_launch": (b"subprocess.popen", b"os.system("),
}

_EXECUTABLE_SUFFIXES = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".ps1", ".hta", ".sh", ".jar",
}
_DOCUMENT_SUFFIXES = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt",
    ".jpg", ".jpeg", ".png", ".gif", ".rtf", ".odt",
}

# Files whose content is normally not meaningful to byte-pattern heuristics.
_TEXT_EXTENSIONS = {
    ".txt", ".py", ".js", ".json", ".xml", ".html", ".htm", ".css",
    ".md", ".sh", ".ps1", ".bat", ".cmd", ".vbs", ".php", ".yml", ".yaml",
    ".ini", ".cfg", ".conf", ".log", ".csv",
}

QUICK_SCAN_DIRECTORIES = (
    "~/Downloads",
    "~/Desktop",
    "~/Documents",
    "/tmp",
)


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


class ScanCancelled(Exception):
    """Raised internally when a caller cancels a running scan."""


class ScanCancellationToken:
    """Cooperative cancellation flag shared with a running scan."""

    def __init__(self):
        self._event = threading.Event()

    def cancel(self):
        self._event.set()

    @property
    def cancelled(self):
        return self._event.is_set()

    def raise_if_cancelled(self):
        if self._event.is_set():
            raise ScanCancelled()


class ASEAntivirus:
    def __init__(self, base_dir="storage/antivirus", settings=None, database=None, event_bus=None):
        self.settings = settings or {}
        self.database = database
        self.event_bus = event_bus

        configured = int(self.settings.get("max_file_size_mb", 64)) * 1024 * 1024
        self.max_file_size = min(MAX_FILE_SIZE, max(1, configured))
        self.max_files = max(1, min(int(self.settings.get("max_files", MAX_SCAN_FILES)), MAX_SCAN_FILES))
        self.max_archive_members = max(1, min(
            int(self.settings.get("max_archive_members", MAX_ARCHIVE_MEMBERS)), MAX_ARCHIVE_MEMBERS))
        self.max_archive_member_size = min(
            MAX_ARCHIVE_MEMBER_SIZE,
            max(1, int(self.settings.get("max_archive_member_size_mb", 32)) * 1024 * 1024),
        )
        self.max_archive_total_size = min(
            MAX_ARCHIVE_TOTAL_SIZE,
            max(1, int(self.settings.get("max_archive_total_size_mb", 128)) * 1024 * 1024),
        )
        self.yara_rules_path = str(self.settings.get("yara_rules_path") or "")

        self.base_dir = Path(base_dir)
        self.quarantine_dir = self.base_dir / "quarantine"
        self.metadata_path = self.base_dir / "quarantine.json"
        self.signatures_path = self.base_dir / "signatures.json"

        self.started = False
        self.scan_count = 0
        self.last_scan = None
        self._quarantine = {}
        self._lock = threading.RLock()
        self._yara_rules = None
        self._yara_error = None

    # ------------------------------------------------------------- lifecycle
    def start(self):
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        if self.metadata_path.exists():
            try:
                loaded = json.loads(self.metadata_path.read_text("utf-8"))
                self._quarantine = loaded if isinstance(loaded, dict) else {}
            except (OSError, json.JSONDecodeError):
                self._quarantine = {}
        if not self.signatures_path.exists():
            self.signatures_path.write_text(json.dumps({"sha256": []}, indent=2), "utf-8")
        self._load_yara()
        self.started = True
        return True

    def stop(self):
        self.started = False
        return True

    def _load_yara(self):
        """Load optional YARA rules; absence is reported, not treated as an error."""
        self._yara_rules = None
        self._yara_error = None
        if not self.yara_rules_path:
            return
        path = Path(self.yara_rules_path).expanduser()
        if not path.exists():
            self._yara_error = "rules_path_missing"
            return
        try:
            import yara  # type: ignore
        except ImportError:
            self._yara_error = "yara_not_installed"
            return
        try:
            if path.is_dir():
                sources = {item.stem: str(item) for item in sorted(path.glob("*.yar"))}
                sources.update({item.stem: str(item) for item in sorted(path.glob("*.yara"))})
                if not sources:
                    self._yara_error = "no_rule_files"
                    return
                self._yara_rules = yara.compile(filepaths=sources)
            else:
                self._yara_rules = yara.compile(filepath=str(path))
        except Exception as exc:
            self._yara_error = "compile_failed: %s" % str(exc)[:160]
            self._yara_rules = None

    def get_status(self):
        with self._lock:
            return {
                "running": self.started,
                "scans": self.scan_count,
                "quarantined_items": len(self._quarantine),
                "last_scan": self.last_scan,
                "limits": {
                    "max_file_size_bytes": self.max_file_size,
                    "max_files": self.max_files,
                    "max_archive_members": self.max_archive_members,
                    "max_archive_member_size_bytes": self.max_archive_member_size,
                    "max_archive_total_size_bytes": self.max_archive_total_size,
                },
                "yara": {
                    "enabled": bool(self.yara_rules_path),
                    "loaded": self._yara_rules is not None,
                    "error": self._yara_error,
                },
            }

    # ------------------------------------------------------------- hashing
    @staticmethod
    def _hash(path):
        digest = hashlib.sha256()
        with Path(path).open("rb") as handle:
            for block in iter(lambda: handle.read(CHUNK), b""):
                digest.update(block)
        return digest.hexdigest()

    def hash_file(self, file_path):
        """Return the SHA-256 of a regular file without scanning it."""
        path = Path(file_path).expanduser()
        if path.is_symlink():
            raise ASEScanError("Symbolic links are not hashed")
        if not path.is_file():
            raise ASEScanError("Only regular files can be hashed")
        return self._hash(path)

    def _known_hashes(self):
        try:
            data = json.loads(self.signatures_path.read_text("utf-8"))
        except (OSError, json.JSONDecodeError):
            return set()
        values = data.get("sha256", []) if isinstance(data, dict) else []
        return {str(item).lower() for item in values if isinstance(item, str) and len(item) == 64}

    def add_signature(self, sha256):
        digest = str(sha256).strip().lower()
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ASEScanError("Signature must be a hex SHA-256 digest")
        hashes = self._known_hashes()
        hashes.add(digest)
        payload = {"sha256": sorted(hashes)}
        self.signatures_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.signatures_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2), "utf-8")
        tmp.replace(self.signatures_path)
        return digest

    # ------------------------------------------------------------- heuristics
    def _inspect_bytes(self, data, filename=""):
        """Return heuristic findings for a byte buffer. Read-only."""
        findings = []
        lower = data.lower()
        if _EICAR in data:
            findings.append({
                "rule": "EICAR_TEST_FILE", "severity": "high", "confidence": "high",
                "detail": "Harmless EICAR antivirus test pattern matched.",
            })
        suffix = Path(filename).suffix.lower() if filename else ""
        if suffix in _TEXT_EXTENSIONS or not suffix:
            for rule, markers in _SCRIPT_MARKERS.items():
                matched = [marker.decode("ascii") for marker in markers if marker in lower]
                if matched:
                    findings.append({
                        "rule": rule.upper(), "severity": "low", "confidence": "low",
                        "detail": "Potentially risky scripting indicators: " + ", ".join(matched),
                    })
        return findings

    def _inspect_path(self, path):
        """Extension-based heuristics that do not read the file."""
        findings = []
        suffixes = [item.lower() for item in path.suffixes]
        if len(suffixes) >= 2 and suffixes[-1] in _EXECUTABLE_SUFFIXES and suffixes[-2] in _DOCUMENT_SUFFIXES:
            findings.append({
                "rule": "DOUBLE_EXTENSION", "severity": "medium", "confidence": "medium",
                "detail": "A document-like extension is followed by an executable extension (%s%s)."
                          % (suffixes[-2], suffixes[-1]),
            })
        if path.name.startswith(".") and suffixes and suffixes[-1] in _EXECUTABLE_SUFFIXES:
            findings.append({
                "rule": "HIDDEN_EXECUTABLE", "severity": "low", "confidence": "low",
                "detail": "Hidden file uses an executable extension.",
            })
        return findings

    def _yara_scan(self, path, data):
        if self._yara_rules is None:
            return []
        findings = []
        try:
            matches = self._yara_rules.match(data=data)
        except Exception as exc:
            findings.append({
                "rule": "YARA_ERROR", "severity": "low", "confidence": "low",
                "detail": "YARA evaluation failed: %s" % str(exc)[:120],
            })
            return findings
        for match in matches:
            namespace = getattr(match, "namespace", "") or ""
            findings.append({
                "rule": "YARA:%s" % match.rule, "severity": "high", "confidence": "medium",
                "detail": "YARA rule matched%s." % ((" in namespace " + namespace) if namespace else ""),
            })
        return findings

    @staticmethod
    def _score(findings):
        score = 0
        for item in findings:
            score = max(score, SEVERITY_SCORE.get(item.get("severity", "low"), 0))
        return score

    @staticmethod
    def _verdict_from(score, findings):
        if score >= 80:
            return "malicious_indicator"
        if findings:
            return "suspicious"
        return "no_known_indicators"

    @staticmethod
    def _explain(findings):
        if not findings:
            return ["No configured signature, heuristic or YARA rule matched.",
                    "This does not prove the file is harmless; unknown malware can pass every local rule."]
        return [item.get("detail", item.get("rule", "indicator")) for item in findings]

    # ------------------------------------------------------------- single file
    def scan_file(self, file_path, token=None):
        """Scan one regular file. Never modifies it."""
        original = Path(file_path).expanduser()
        if original.is_symlink():
            return self._error_result(str(original), "Symbolic links are not scanned")
        try:
            path = original.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            return self._error_result(str(original), "Path could not be resolved: %s" % str(exc)[:120])
        if not path.is_file():
            return self._error_result(str(path), "Only regular files can be scanned")

        if token is not None:
            token.raise_if_cancelled()

        try:
            size = path.stat().st_size
        except OSError as exc:
            return self._error_result(str(path), "File metadata unreadable: %s" % str(exc)[:120])

        if size > self.max_file_size:
            return {
                "file": str(path), "status": "scan_incomplete", "reason": "file_size_limit",
                "size": size, "sha256": None, "risk_score": 0, "findings": [],
                "explanations": ["File exceeds the configured %d byte inspection limit." % self.max_file_size],
                "scanned_at": _utc_now(),
            }

        try:
            digest = self._hash(path)
        except OSError as exc:
            return self._error_result(str(path), "File could not be read: %s" % str(exc)[:120])

        findings = []
        if digest in self._known_hashes():
            findings.append({
                "rule": "LOCAL_SHA256_SIGNATURE", "severity": "high", "confidence": "high",
                "detail": "SHA-256 matched a locally configured signature.",
            })

        findings.extend(self._inspect_path(path))

        try:
            with path.open("rb") as handle:
                data = handle.read(self.max_file_size + 1)
        except OSError as exc:
            return self._error_result(str(path), "File could not be read: %s" % str(exc)[:120])

        if token is not None:
            token.raise_if_cancelled()

        findings.extend(self._inspect_bytes(data, str(path)))
        findings.extend(self._yara_scan(path, data))

        if zipfile.is_zipfile(path):
            findings.extend(self._scan_archive(path, token))

        score = self._score(findings)
        verdict = self._verdict_from(score, findings)
        result = {
            "file": str(path),
            "status": verdict,
            "sha256": digest,
            "size": size,
            "risk_score": score,
            "findings": findings,
            "explanations": self._explain(findings),
            "scanned_at": _utc_now(),
        }
        with self._lock:
            self.scan_count += 1
            self.last_scan = result
        if verdict in DETECTION_VERDICTS and self.event_bus is not None:
            try:
                self.event_bus.publish("antivirus.detection", result)
            except Exception:
                pass
        return result

    @staticmethod
    def _error_result(path, message):
        return {
            "file": str(path), "status": "scan_error", "error": message,
            "sha256": None, "risk_score": 0, "findings": [],
            "explanations": [message], "scanned_at": _utc_now(),
        }

    def _scan_archive(self, path, token=None):
        """Inspect ZIP members under strict resource limits."""
        findings = []
        try:
            with zipfile.ZipFile(path) as archive:
                members = archive.infolist()
                if len(members) > self.max_archive_members:
                    findings.append({
                        "rule": "ARCHIVE_MEMBER_LIMIT", "severity": "medium", "confidence": "high",
                        "detail": "Archive exceeds the inspection member limit of %d." % self.max_archive_members,
                    })
                    return findings
                expanded = 0
                for member in members:
                    if member.is_dir():
                        continue
                    if member.file_size > self.max_archive_member_size:
                        findings.append({
                            "rule": "ARCHIVE_MEMBER_SIZE_LIMIT", "severity": "medium", "confidence": "high",
                            "detail": "Archive member exceeds the inspection size limit.",
                        })
                        continue
                    expanded += member.file_size
                    if expanded > self.max_archive_total_size:
                        findings.append({
                            "rule": "ARCHIVE_TOTAL_SIZE_LIMIT", "severity": "medium", "confidence": "high",
                            "detail": "Archive expanded size exceeds the inspection limit.",
                        })
                        break
                    if member.file_size and (
                            member.compress_size == 0
                            or member.file_size / max(member.compress_size, 1) > 200):
                        findings.append({
                            "rule": "ARCHIVE_COMPRESSION_RATIO", "severity": "medium", "confidence": "medium",
                            "detail": "Archive member has an unusually high compression ratio.",
                        })
                        continue
                    if token is not None:
                        token.raise_if_cancelled()
                    try:
                        with archive.open(member) as stream:
                            member_data = stream.read(self.max_archive_member_size + 1)
                    except (OSError, RuntimeError, zipfile.BadZipFile):
                        findings.append({
                            "rule": "ARCHIVE_MEMBER_READ_ERROR", "severity": "low", "confidence": "medium",
                            "detail": "An archive member could not be inspected.",
                        })
                        continue
                    if len(member_data) > self.max_archive_member_size:
                        continue
                    for finding in self._inspect_bytes(member_data, member.filename):
                        findings.append({**finding,
                                         "detail": "Archive member %s: %s"
                                                   % (member.filename[:160], finding["detail"])})
                    if self._yara_rules is not None:
                        for finding in self._yara_scan(member.filename, member_data):
                            findings.append({**finding,
                                             "detail": "Archive member %s: %s"
                                                       % (member.filename[:160], finding["detail"])})
        except (OSError, zipfile.BadZipFile):
            findings.append({
                "rule": "ARCHIVE_FORMAT_ERROR", "severity": "low", "confidence": "medium",
                "detail": "Archive structure could not be fully inspected.",
            })
        return findings

    # ------------------------------------------------------------- path scans
    def _collect_files(self, root, limit=None):
        """Yield regular, non-symlink files below ``root`` up to ``limit``."""
        limit = limit or self.max_files
        files = []
        for current, dirs, names in os.walk(root, followlinks=False):
            dirs[:] = sorted(d for d in dirs if not (Path(current) / d).is_symlink())
            for name in sorted(names):
                candidate = Path(current) / name
                if candidate.is_symlink() or not candidate.is_file():
                    continue
                files.append(candidate)
                if len(files) >= limit:
                    return files
        return files

    def scan_path(self, target, scan_type="custom", token=None, record=True):
        """Scan a file or directory tree and return a structured report."""
        original = Path(target).expanduser()
        if original.is_symlink():
            raise ASEScanError("Symbolic links are not scan targets")
        try:
            root = original.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ASEScanError("Scan target could not be resolved: %s" % str(exc)[:160]) from exc

        if root.is_file():
            files = [root]
        elif root.is_dir():
            files = self._collect_files(root)
        else:
            raise ASEScanError("Target must be a regular file or directory")

        scan_id = None
        if record and self.database is not None and getattr(self.database, "ready", False):
            try:
                scan_id = self.database.create_scan(scan_type, str(root))
            except Exception:
                scan_id = None

        started = time.monotonic()
        results = []
        cancelled = False
        for item in files:
            if token is not None and token.cancelled:
                cancelled = True
                break
            try:
                results.append(self.scan_file(item, token=token))
            except ScanCancelled:
                cancelled = True
                break
            except (OSError, ASEScanError) as exc:
                results.append(self._error_result(str(item), str(exc)[:200]))

        summary = self._summarize(results, root, scan_type, cancelled)
        summary["scan_id"] = scan_id
        summary["duration_seconds"] = round(time.monotonic() - started, 3)
        summary["limits"] = {"max_files": self.max_files, "files_considered": len(files)}

        if scan_id is not None:
            try:
                self.database.finish_scan(
                    scan_id, "cancelled" if cancelled else "completed", summary, results)
            except Exception:
                pass
        if self.event_bus is not None:
            try:
                self.event_bus.publish("antivirus.scan_completed", {
                    "scan_id": scan_id, "scan_type": scan_type, "target": str(root),
                    "detections": summary["detections"], "total": summary["total"],
                    "cancelled": cancelled,
                })
            except Exception:
                pass
        return summary

    def _summarize(self, results, root, scan_type, cancelled):
        counts = {verdict: 0 for verdict in VERDICTS}
        for item in results:
            status = item.get("status", "scan_error")
            counts[status] = counts.get(status, 0) + 1
        detections = [item for item in results if item.get("status") in DETECTION_VERDICTS]
        return {
            "target": str(root),
            "scan_type": scan_type,
            "status": "cancelled" if cancelled else "completed",
            "total": len(results),
            "scanned": sum(counts[v] for v in ("no_known_indicators", "suspicious", "malicious_indicator")),
            "detections": len(detections),
            "errors": counts.get("scan_error", 0),
            "skipped": counts.get("scan_incomplete", 0),
            "verdict_counts": counts,
            "detection_details": [
                {"file": item["file"], "status": item["status"],
                 "risk_score": item.get("risk_score", 0),
                 "reasons": item.get("explanations", [])}
                for item in detections[:200]
            ],
            "results": results,
        }

    # ------------------------------------------------------------- scan profiles
    def quick_scan(self, token=None):
        """Scan well-known user folders that exist on this host."""
        targets = []
        for candidate in QUICK_SCAN_DIRECTORIES:
            path = Path(candidate).expanduser()
            try:
                if path.is_dir() and not path.is_symlink():
                    targets.append(path)
            except OSError:
                continue
        return self._scan_many(targets, "quick", token)

    def full_scan(self, token=None, roots=None):
        """Scan explicit roots, or the user's home directory by default."""
        targets = [Path(item).expanduser() for item in (roots or [str(Path.home())])]
        return self._scan_many(targets, "full", token)

    def _scan_many(self, targets, scan_type, token=None):
        combined = []
        reports = []
        for target in targets:
            try:
                report = self.scan_path(target, scan_type=scan_type, token=token, record=False)
            except ASEScanError as exc:
                reports.append({"target": str(target), "status": "scan_error", "error": str(exc)[:200],
                                "results": [], "detections": 0, "total": 0})
                continue
            reports.append(report)
            combined.extend(report.get("results", []))
        summary = self._summarize(combined, ",".join(str(t) for t in targets), scan_type,
                                  any(r.get("status") == "cancelled" for r in reports))
        summary["targets"] = [str(item) for item in targets]
        summary["per_target"] = [
            {key: value for key, value in report.items() if key != "results"} for report in reports
        ]
        if not targets:
            summary["status"] = "completed"
            summary["note"] = "No existing default scan directories were found on this host."
        scan_id = None
        if self.database is not None and getattr(self.database, "ready", False):
            try:
                scan_id = self.database.create_scan(scan_type, summary["target"])
                self.database.finish_scan(scan_id, summary["status"], summary, combined)
            except Exception:
                scan_id = None
        summary["scan_id"] = scan_id
        if self.event_bus is not None:
            try:
                self.event_bus.publish("antivirus.scan_completed", {
                    "scan_id": scan_id, "scan_type": scan_type, "target": summary["target"],
                    "detections": summary["detections"], "total": summary["total"],
                    "cancelled": summary["status"] == "cancelled",
                })
            except Exception:
                pass
        return summary

    # ------------------------------------------------------------- quarantine
    def quarantine_file(self, file_path, authorized=False, reason="manual_request"):
        """Move a detected file into quarantine.

        Refused unless the caller passes ``authorized=True`` *and* the file
        carries a detection. Scanning itself never calls this method.
        """
        if not authorized:
            raise ASEQuarantineError(
                "Quarantine requires explicit authorization (authorized=True)")
        original = Path(file_path).expanduser()
        if original.is_symlink():
            raise ASEQuarantineError("Symbolic links cannot be quarantined")
        try:
            source = original.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ASEQuarantineError("File could not be resolved: %s" % str(exc)[:160]) from exc
        if not source.is_file():
            raise ASEQuarantineError("Only regular files can be quarantined")

        result = self.scan_file(source)
        if result["status"] not in DETECTION_VERDICTS:
            raise ASEQuarantineError(
                "File has no detected indicator (verdict: %s); quarantine refused." % result["status"])

        digest = result["sha256"]
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        quarantine_id, destination = self._allocate_quarantine_slot(digest)

        try:
            shutil.move(str(source), str(destination))
        except OSError as exc:
            raise ASEQuarantineError("Quarantine move failed: %s" % str(exc)[:160]) from exc

        try:
            os.chmod(destination, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

        # Verify the stored copy before trusting the metadata.
        stored_hash = self._hash(destination)
        if stored_hash != digest:
            try:
                shutil.move(str(destination), str(source))
            except OSError:
                pass
            raise ASEQuarantineError("Quarantine integrity verification failed; original restored")

        record = {
            "original_path": str(source),
            "stored_name": quarantine_id,
            "sha256": digest,
            "size": result.get("size", 0),
            "verdict": result["status"],
            "created_at": _utc_now(),
            "findings": result.get("findings", []),
            "reason": str(reason)[:200],
        }
        with self._lock:
            self._quarantine[quarantine_id] = record
            self._save_quarantine()
        if self.database is not None and getattr(self.database, "ready", False):
            try:
                self.database.add_quarantine(quarantine_id, str(source), quarantine_id,
                                             digest, result.get("size", 0),
                                             result["status"], result.get("findings", []))
            except Exception:
                pass
        if self.event_bus is not None:
            try:
                self.event_bus.publish("antivirus.quarantined", {
                    "quarantine_id": quarantine_id, "file": str(source), "sha256": digest,
                    "verdict": result["status"]})
            except Exception:
                pass
        return {
            "quarantine_id": quarantine_id,
            "original_path": str(source),
            "sha256": digest,
            "verdict": result["status"],
            "status": "quarantined",
        }

    def _allocate_quarantine_slot(self, digest):
        """Reserve a unique quarantine identifier, tolerating same-millisecond duplicates."""
        base = "%s-%d" % (digest[:16], int(time.time() * 1000))
        with self._lock:
            for attempt in range(1000):
                candidate = base if attempt == 0 else "%s-%d" % (base, attempt)
                destination = self.quarantine_dir / candidate
                if candidate in self._quarantine or destination.exists():
                    continue
                return candidate, destination
        raise ASEQuarantineError("Could not allocate a unique quarantine identifier")

    def restore_file(self, quarantine_id, target_path=None):
        """Restore a quarantined file after verifying its integrity."""
        item = self._quarantine.get(str(quarantine_id))
        if not item:
            raise ASEQuarantineError("Unknown quarantine ID")
        stored_name = str(item.get("stored_name", ""))
        if not stored_name or Path(stored_name).name != stored_name:
            raise ASEQuarantineError("Invalid quarantine metadata")
        stored = self.quarantine_dir / stored_name
        if stored.is_symlink() or not stored.is_file():
            raise ASEQuarantineError("Quarantined content is missing or unsafe")
        if self._hash(stored) != item.get("sha256"):
            raise ASEQuarantineError("Quarantine integrity check failed; file not restored")

        target = Path(target_path).expanduser() if target_path else Path(item["original_path"])
        if target.exists():
            raise ASEQuarantineError("Restore destination already exists; refusing to overwrite")
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ASEQuarantineError("Restore directory could not be created: %s" % str(exc)[:120]) from exc

        try:
            shutil.move(str(stored), str(target))
        except OSError as exc:
            raise ASEQuarantineError("Restore move failed: %s" % str(exc)[:160]) from exc

        if self._hash(target) != item.get("sha256"):
            # Roll back so the operator can retry rather than lose the file.
            try:
                shutil.move(str(target), str(stored))
            except OSError:
                pass
            raise ASEQuarantineError("Post-restore integrity check failed; file returned to quarantine")

        with self._lock:
            del self._quarantine[str(quarantine_id)]
            self._save_quarantine()
        if self.database is not None and getattr(self.database, "ready", False):
            try:
                self.database.mark_restored(str(quarantine_id))
            except Exception:
                pass
        if self.event_bus is not None:
            try:
                self.event_bus.publish("antivirus.restored", {
                    "quarantine_id": str(quarantine_id), "restored_to": str(target)})
            except Exception:
                pass
        return {"quarantine_id": str(quarantine_id), "restored_to": str(target), "status": "restored"}

    def list_quarantine(self):
        with self._lock:
            return [{"quarantine_id": key, **value} for key, value in sorted(self._quarantine.items())]

    def _save_quarantine(self):
        self.metadata_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.metadata_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._quarantine, indent=2), "utf-8")
        try:
            os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        tmp.replace(self.metadata_path)
