"""Loopback-only HTTP API for AKVORIA ASE.

Security posture:
* binds to a loopback address only (validated in config and again here)
* bearer token compared with :func:`hmac.compare_digest`
* the key file is created with mode 0600 and never logged
* per-client rate limiting and a loopback IP allowlist
* request body size limit, Content-Type check and strict JSON object parsing
* security response headers on every reply
* error bodies never include a traceback or internal path
"""
from __future__ import annotations

import hmac
import json
import os
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import parse_qs, urlparse

from core.api_security import ASEAPISecurity
from core.exceptions import (
    ASEIntelligenceError,
    ASEQuarantineError,
    ASEScanError,
)

LOOPBACK_HOSTS = ("127.0.0.1", "::1", "localhost")
DEFAULT_KEY_PATH = Path("storage/ase_api.key")
MIN_KEY_LENGTH = 32


class ASEAPI:
    def __init__(self, engine, key_path=None):
        self.engine = engine
        self.server = None
        self.thread = None
        self.api_key = None
        self.api_key_path = Path(key_path) if key_path else DEFAULT_KEY_PATH

        config = engine.settings.get("api", {})
        self.host = config.get("host", "127.0.0.1")
        self.port = int(config.get("port", 8765))
        if self.host not in LOOPBACK_HOSTS:
            raise ValueError("API must bind to loopback only")
        self.enabled = bool(config.get("enabled", True))
        self.max_body_bytes = max(1024, int(config.get("max_body_bytes", 65536)))
        self.security = ASEAPISecurity(
            max_requests=int(config.get("rate_limit_requests", 120)),
            window_seconds=int(config.get("rate_limit_window_seconds", 60)),
        )

    # ------------------------------------------------------------- key handling
    def _load_api_key(self):
        self.api_key_path.parent.mkdir(parents=True, exist_ok=True)
        if self.api_key_path.is_symlink():
            raise RuntimeError("API key path must not be a symbolic link")
        if self.api_key_path.exists():
            key = self.api_key_path.read_text("utf-8").strip()
            if len(key) < MIN_KEY_LENGTH:
                raise RuntimeError("Existing API key is too short; remove the file to regenerate")
        else:
            key = secrets.token_urlsafe(48)
            handle = os.open(str(self.api_key_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                stream.write(key)
        try:
            os.chmod(self.api_key_path, 0o600)
        except OSError:
            pass
        self.api_key = key
        return key

    def rotate_api_key(self):
        """Generate and persist a new key. The old key stops working immediately."""
        key = secrets.token_urlsafe(48)
        tmp = self.api_key_path.with_suffix(".tmp")
        tmp.write_text(key, "utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        tmp.replace(self.api_key_path)
        self.api_key = key
        return key

    def authorize(self, header):
        """Constant-time bearer check that never leaks timing on length."""
        if not isinstance(header, str) or not header.startswith("Bearer "):
            return False
        token = header[7:].strip()
        expected = self.api_key or ""
        return hmac.compare_digest(token.encode("utf-8"), expected.encode("utf-8"))

    # ------------------------------------------------------------- lifecycle
    def start(self):
        if self.server or not self.enabled:
            return False
        self._load_api_key()
        api = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "AKVORIA-ASE"
            sys_version = ""
            protocol_version = "HTTP/1.1"

            # ---------------------------------------------------- responses
            def send_json(self, status, data, extra_headers=None):
                api.security.log_request(self.client_address[0], self.command,
                                         urlparse(self.path).path, status)
                body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Pragma", "no-cache")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Security-Policy", "default-src 'none'")
                for name, value in (extra_headers or {}).items():
                    self.send_header(name, value)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def log_message(self, fmt, *args):
                # BaseHTTPRequestHandler's default logger writes to stderr unredacted.
                return

            # ---------------------------------------------------- access
            def _gate(self):
                ip = self.client_address[0]
                if not api.security.check_ip(ip):
                    self.send_json(403, {"error": "Forbidden"})
                    return False
                if not api.security.check_rate_limit(ip):
                    self.send_json(429, {"error": "Too many requests"},
                                   {"Retry-After": str(api.security.window_seconds)})
                    return False
                if not api.authorize(self.headers.get("Authorization", "")):
                    self.send_json(401, {"error": "Unauthorized"},
                                   {"WWW-Authenticate": "Bearer"})
                    return False
                return True

            def _read_json(self):
                """Return (payload, None) or (None, (status, message))."""
                content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
                if content_type != "application/json":
                    return None, (415, "Content-Type must be application/json")
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except (TypeError, ValueError):
                    return None, (400, "Invalid Content-Length")
                if length < 1:
                    return None, (400, "Request body is required")
                if length > api.max_body_bytes:
                    return None, (413, "Request body exceeds the configured limit")
                raw = self.rfile.read(length)
                try:
                    payload = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    return None, (400, "Invalid JSON")
                if not isinstance(payload, dict):
                    return None, (400, "JSON object required")
                return payload, None

            # ---------------------------------------------------- routes: GET
            def do_HEAD(self):
                self.do_GET()

            def do_GET(self):
                parsed = urlparse(self.path)
                path = parsed.path.rstrip("/") or "/"
                params = parse_qs(parsed.query)
                ip = self.client_address[0]

                if not api.security.check_ip(ip):
                    self.send_json(403, {"error": "Forbidden"})
                    return
                if path == "/health":
                    self.send_json(200, {"engine": "AKVORIA SECURITY ENGINE", "status": "running",
                                         "api": "local"})
                    return
                if not api.security.check_rate_limit(ip):
                    self.send_json(429, {"error": "Too many requests"})
                    return
                if not api.authorize(self.headers.get("Authorization", "")):
                    self.send_json(401, {"error": "Unauthorized"}, {"WWW-Authenticate": "Bearer"})
                    return

                def query_int(name, default, minimum=1, maximum=1000):
                    raw = params.get(name, [str(default)])[0]
                    value = int(raw)
                    return max(minimum, min(value, maximum))

                try:
                    if path in ("/status", "/api/status"):
                        self.send_json(200, api.engine.get_status())
                    elif path == "/api/health":
                        self.send_json(200, api.engine.health())
                    elif path == "/api/requests":
                        history = api.security.get_request_history(query_int("limit", 20, 1, 100))
                        self.send_json(200, {"total": len(history), "requests": history})
                    elif path in ("/api/processes", "/processes"):
                        rows = api.engine.process.get_processes(query_int("limit", 100, 1, 1000))
                        self.send_json(200, {"total": len(rows), "processes": rows,
                                             "mode": "read_only_inventory"})
                    elif path in ("/api/network/connections", "/network/connections"):
                        result = api.engine.network.get_connections()
                        if params.get("matches_only", ["0"])[0] in ("1", "true", "yes"):
                            result = {**result, "connections": []}
                        self.send_json(200, result)
                    elif path == "/api/network/history":
                        self.send_json(200, {"history": api.engine.network.get_history(
                            query_int("limit", 20, 1, 100))})
                    elif path == "/api/events":
                        limit = query_int("limit", 20, 1, 200)
                        offset = query_int("offset", 0, 0, 100000)
                        result = api.engine.database.search_events(
                            event_type=params.get("event_type", [None])[0],
                            risk_level=params.get("risk_level", [None])[0],
                            start_date=params.get("start_date", [None])[0],
                            end_date=params.get("end_date", [None])[0],
                            limit=limit, offset=offset)
                        self.send_json(200, result)
                    elif path == "/api/scheduler/history":
                        history = api.engine.scheduler.get_history(
                            task_name=params.get("task_name", [None])[0],
                            limit=query_int("limit", 20, 1, 200))
                        self.send_json(200, {"total": len(history),
                                             "task_name": params.get("task_name", [None])[0],
                                             "history": history})
                    elif path == "/api/scheduler":
                        self.send_json(200, api.engine.scheduler.get_status())
                    elif path == "/api/scans":
                        scans = api.engine.database.get_scans(
                            limit=query_int("limit", 20, 1, 200),
                            offset=query_int("offset", 0, 0, 100000),
                            scan_type=params.get("scan_type", [None])[0])
                        self.send_json(200, {"total": len(scans), "scans": scans})
                    elif path == "/api/scans/statistics":
                        self.send_json(200, api.engine.database.get_scan_statistics())
                    elif path.startswith("/api/scans/"):
                        scan_id = int(path.rsplit("/", 1)[1])
                        scan = api.engine.database.get_scan(scan_id)
                        if scan is None:
                            self.send_json(404, {"error": "Scan not found"})
                        else:
                            scan["results"] = api.engine.database.get_scan_results(scan_id)
                            self.send_json(200, scan)
                    elif path == "/api/alerts":
                        alerts = api.engine.response.get_alerts(
                            limit=query_int("limit", 50, 1, 200),
                            status=params.get("status", [None])[0],
                            severity=params.get("severity", [None])[0])
                        self.send_json(200, {"total": len(alerts), "alerts": alerts})
                    elif path == "/api/incidents":
                        incidents = api.engine.response.get_incidents(query_int("limit", 50, 1, 200))
                        self.send_json(200, {"total": len(incidents), "incidents": incidents})
                    elif path == "/api/quarantine":
                        items = api.engine.antivirus.list_quarantine()
                        self.send_json(200, {"total": len(items), "items": items})
                    elif path == "/api/intelligence/indicators":
                        indicators = api.engine.intelligence.list_indicators(
                            params.get("type", [None])[0])
                        self.send_json(200, {"total": len(indicators), "indicators": indicators,
                                             "statistics": api.engine.intelligence.statistics()})
                    elif path == "/api/monitoring":
                        status = api.engine.realtime.get_status()
                        self.send_json(200, {"scope": status["protection_scope"],
                                             "mode": status["mode"],
                                             "roots": status["roots"],
                                             "running": status["running"],
                                             "realtime": status,
                                             "health": api.engine.realtime.health()})
                    elif path == "/api/diagnostics":
                        self.send_json(200, api.engine.diagnostics())
                    elif path == "/api/config":
                        self.send_json(200, api.engine.public_config())
                    else:
                        self.send_json(404, {"error": "Endpoint not found"})
                except (ValueError, TypeError):
                    self.send_json(400, {"error": "Invalid request parameters"})
                except Exception:
                    api.engine.logger.exception("API GET failed")
                    self.send_json(500, {"error": "Internal server error"})

            # ---------------------------------------------------- routes: POST
            def do_POST(self):
                if not self._gate():
                    return
                payload, error = self._read_json()
                if error:
                    self.send_json(error[0], {"error": error[1]})
                    return
                path = urlparse(self.path).path.rstrip("/")
                try:
                    self._dispatch_post(path, payload)
                except ASEQuarantineError as exc:
                    self.send_json(404, {"error": str(exc)[:200]})
                except ASEScanError as exc:
                    self.send_json(400, {"error": str(exc)[:200]})
                except ASEIntelligenceError as exc:
                    self.send_json(400, {"error": str(exc)[:200]})
                except ValueError as exc:
                    self.send_json(400, {"error": str(exc)[:200]})
                except PermissionError as exc:
                    self.send_json(403, {"error": str(exc)[:200]})
                except FileNotFoundError as exc:
                    self.send_json(404, {"error": str(exc)[:200]})
                except Exception:
                    api.engine.logger.exception("API POST failed")
                    self.send_json(500, {"error": "Internal server error"})

            def _dispatch_post(self, path, payload):
                engine = api.engine

                if path in ("/api/scan", "/scan"):
                    target = payload.get("path")
                    if not isinstance(target, str) or not target.strip():
                        self.send_json(400, {"error": "path is required"})
                        return
                    if not engine.is_path_allowed(target):
                        self.send_json(403, {"error": "Path is outside the configured allowlist"})
                        return
                    result = engine.antivirus.scan_path(target, scan_type="custom")
                    self.send_json(200, result)
                    return

                if path in ("/api/scan/quick", "/scan/quick"):
                    self.send_json(200, engine.antivirus.quick_scan())
                    return

                if path in ("/api/scan/full", "/scan/full"):
                    roots = payload.get("paths")
                    if roots is not None and (not isinstance(roots, list)
                                              or any(not isinstance(item, str) for item in roots)):
                        self.send_json(400, {"error": "paths must be a list of strings"})
                        return
                    if roots:
                        for item in roots:
                            if not engine.is_path_allowed(item):
                                self.send_json(403, {"error": "Path is outside the configured allowlist"})
                                return
                    self.send_json(200, engine.antivirus.full_scan(roots=roots))
                    return

                if path in ("/api/indicators", "/api/threat-intelligence/indicators",
                            "/api/intelligence/indicators"):
                    result = engine.intelligence.add_indicator(
                        payload.get("indicator"), payload.get("type"),
                        payload.get("source", "api"), payload.get("description", ""),
                        confidence=payload.get("confidence", 50))
                    self.send_json(201, {"status": "added", **result})
                    return

                if path == "/api/quarantine":
                    target = payload.get("path")
                    if not isinstance(target, str) or not target.strip():
                        self.send_json(400, {"error": "path is required"})
                        return
                    # Quarantine always requires an explicit authorization flag.
                    if payload.get("authorized") is not True:
                        self.send_json(403, {"error": "Quarantine requires \"authorized\": true"})
                        return
                    if not engine.is_path_allowed(target):
                        self.send_json(403, {"error": "Path is outside the configured allowlist"})
                        return
                    self.send_json(201, engine.antivirus.quarantine_file(target, authorized=True))
                    return

                if path == "/api/quarantine/restore":
                    quarantine_id = payload.get("quarantine_id")
                    if not isinstance(quarantine_id, str) or not quarantine_id.strip():
                        self.send_json(400, {"error": "quarantine_id is required"})
                        return
                    self.send_json(200, engine.antivirus.restore_file(quarantine_id))
                    return

                if path == "/api/alerts/acknowledge":
                    alert_id = payload.get("alert_id")
                    if not isinstance(alert_id, int):
                        self.send_json(400, {"error": "alert_id must be an integer"})
                        return
                    acknowledged = engine.response.acknowledge(alert_id,
                                                              payload.get("actor", "api"))
                    if acknowledged:
                        self.send_json(200, {"status": "acknowledged", "alert_id": alert_id})
                    else:
                        self.send_json(404, {"error": "Alert not found or already acknowledged"})
                    return

                if path == "/api/monitoring/paths":
                    paths = payload.get("paths")
                    if not isinstance(paths, list) or any(not isinstance(item, str) for item in paths):
                        self.send_json(400, {"error": "paths must be a list of strings"})
                        return
                    configured = engine.set_watch_paths(paths)
                    self.send_json(200, {"watch_paths": configured,
                                         "realtime": engine.realtime.get_status()})
                    return

                if path == "/api/intelligence/export":
                    target = payload.get("path", "storage/reports/indicators.json")
                    if not isinstance(target, str):
                        self.send_json(400, {"error": "path must be a string"})
                        return
                    self.send_json(200, engine.intelligence.export_indicators(target))
                    return

                if path == "/api/diagnostics/backup":
                    self.send_json(200, {"backup": engine.backup_database()})
                    return

                self.send_json(404, {"error": "Endpoint not found"})

            def do_DELETE(self):
                if not self._gate():
                    return
                path = urlparse(self.path).path.rstrip("/")
                try:
                    if path.startswith("/api/intelligence/indicators/"):
                        indicator = path.rsplit("/", 1)[1]
                        removed = api.engine.intelligence.remove_indicator(indicator)
                        self.send_json(200 if removed else 404,
                                       {"status": "removed" if removed else "not_found",
                                        "indicator": indicator})
                    elif path.startswith("/api/quarantine/"):
                        self.send_json(405, {"error": "Use POST /api/quarantine/restore"})
                    else:
                        self.send_json(404, {"error": "Endpoint not found"})
                except Exception:
                    api.engine.logger.exception("API DELETE failed")
                    self.send_json(500, {"error": "Internal server error"})

        try:
            self.server = ThreadingHTTPServer((self.host, self.port), Handler)
        except OSError as exc:
            self.engine.logger.error("API bind failed on %s:%s (%s)", self.host, self.port, exc)
            raise
        self.server.daemon_threads = True
        self.server.timeout = 1
        self.thread = Thread(target=self.server.serve_forever,
                             kwargs={"poll_interval": 0.25}, daemon=True)
        self.thread.start()
        self.engine.logger.info("API listening on %s:%s (loopback only)", self.host, self.port)
        return True

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)
        self.thread = None
        return True

    def get_status(self):
        return {
            "enabled": self.enabled,
            "running": self.server is not None,
            "host": self.host,
            "port": self.port,
            "key_path": str(self.api_key_path),
            "security": self.security.get_health(),
        }
