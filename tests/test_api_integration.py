"""Live HTTP API integration tests against a real loopback server."""
from __future__ import annotations

import json
import socket
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from tests.helpers import IsolatedWorkspace

EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class ApiIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = IsolatedWorkspace(api_port=_free_port())
        cls.root = cls.workspace.__enter__()
        from core.engine import ASEEngine
        cls.engine = ASEEngine()
        cls.engine.start()
        cls.port = cls.engine.api.port
        cls.key = cls.engine.api.api_key
        work = Path(cls.root) / "work"
        work.mkdir()
        (work / "clean.txt").write_text("harmless content", encoding="utf-8")
        (work / "test.com").write_text(EICAR, encoding="utf-8")
        cls.work = work

    @classmethod
    def tearDownClass(cls):
        cls.engine.stop()
        cls.workspace.__exit__(None, None, None)

    def call(self, path, method="GET", payload=None, auth=True, raw=None,
             content_type="application/json"):
        data = None
        headers = {}
        if auth:
            headers["Authorization"] = "Bearer " + self.key
        if payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = content_type
        if raw is not None:
            data = raw
            headers["Content-Type"] = content_type
        request = urllib.request.Request(
            "http://127.0.0.1:%d%s" % (self.port, path),
            data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return response.status, json.loads(response.read() or b"{}"), dict(response.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}"), dict(exc.headers)

    # ---------------------------------------------------------- authentication
    def test_unauthenticated_rejected(self):
        status, _, headers = self.call("/api/alerts", auth=False)
        self.assertEqual(status, 401)
        self.assertIn("WWW-Authenticate", headers)

    def test_wrong_token_rejected(self):
        request = urllib.request.Request(
            "http://127.0.0.1:%d/api/alerts" % self.port,
            headers={"Authorization": "Bearer " + "z" * 64})
        try:
            urllib.request.urlopen(request, timeout=10)
            self.fail("expected 401")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 401)

    def test_public_health_needs_no_token(self):
        status, body, _ = self.call("/health", auth=False)
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "running")

    def test_security_headers_present(self):
        _, _, headers = self.call("/health", auth=False)
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(headers.get("Cache-Control"), "no-store")

    # ---------------------------------------------------------- request hardening
    def test_wrong_content_type_rejected(self):
        status, _, _ = self.call("/api/scan", "POST", auth=True,
                                 raw=b'{"path":"."}', content_type="text/plain")
        self.assertEqual(status, 415)

    def test_invalid_json_rejected(self):
        status, _, _ = self.call("/api/scan", "POST", raw=b"not json")
        self.assertEqual(status, 400)

    def test_non_object_json_rejected(self):
        status, _, _ = self.call("/api/scan", "POST", payload=["a", "b"])
        self.assertEqual(status, 400)

    def test_oversized_body_rejected(self):
        huge = b'{"path":"' + b"a" * 200000 + b'"}'
        status, _, _ = self.call("/api/scan", "POST", raw=huge)
        self.assertEqual(status, 413)

    def test_empty_body_rejected(self):
        status, _, _ = self.call("/api/scan", "POST", raw=b"")
        self.assertEqual(status, 400)

    # ---------------------------------------------------------- scanning
    def test_scan_directory(self):
        status, body, _ = self.call("/api/scan", "POST", {"path": str(self.work)})
        self.assertEqual(status, 200)
        self.assertEqual(body["detections"], 1)
        self.assertEqual(body["verdict_counts"]["malicious_indicator"], 1)

    def test_scan_missing_path_field(self):
        status, _, _ = self.call("/api/scan", "POST", {})
        self.assertEqual(status, 400)

    def test_scan_history_and_statistics(self):
        status, body, _ = self.call("/api/scans?limit=5")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(body["total"], 1)
        status, body, _ = self.call("/api/scans/statistics")
        self.assertEqual(status, 200)
        self.assertIn("total_scans", body)

    # ---------------------------------------------------------- quarantine
    def test_quarantine_requires_explicit_authorization(self):
        target = self.work / "test.com"
        status, _, _ = self.call("/api/quarantine", "POST", {"path": str(target)})
        self.assertEqual(status, 403)
        self.assertTrue(target.exists())

    def test_quarantine_and_restore(self):
        target = self.work / "test.com"
        status, body, _ = self.call("/api/quarantine", "POST",
                                    {"path": str(target), "authorized": True})
        self.assertEqual(status, 201)
        self.assertFalse(target.exists())
        qid = body["quarantine_id"]

        status, listing, _ = self.call("/api/quarantine")
        self.assertEqual(status, 200)
        self.assertEqual(listing["total"], 1)

        status, restored, _ = self.call("/api/quarantine/restore", "POST",
                                        {"quarantine_id": qid})
        self.assertEqual(status, 200)
        self.assertEqual(restored["status"], "restored")
        self.assertTrue(target.exists())

    def test_restore_unknown_id(self):
        status, _, _ = self.call("/api/quarantine/restore", "POST",
                                 {"quarantine_id": "nope"})
        self.assertEqual(status, 404)

    # ---------------------------------------------------------- intelligence
    def test_indicator_lifecycle(self):
        status, body, _ = self.call("/api/intelligence/indicators", "POST",
                                    {"indicator": "203.0.113.9", "type": "ip"})
        self.assertEqual(status, 201)
        status, listing, _ = self.call("/api/intelligence/indicators")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(listing["total"], 1)
        status, _, _ = self.call("/api/intelligence/indicators/203.0.113.9", "DELETE")
        self.assertEqual(status, 200)

    def test_invalid_indicator_rejected(self):
        status, _, _ = self.call("/api/intelligence/indicators", "POST",
                                 {"indicator": "not an ip", "type": "ip"})
        self.assertEqual(status, 400)

    # ---------------------------------------------------------- monitoring
    def test_monitoring_reports_honest_scope(self):
        status, body, _ = self.call("/api/monitoring")
        self.assertEqual(status, 200)
        self.assertEqual(body["health"]["scope"], "configured_directories_only")
        self.assertEqual(body["scope"], "configured_directories_only")
        self.assertEqual(body["roots"], [])
        self.assertEqual(body["mode"], "idle_no_paths")
        self.assertFalse(body["running"])

    def test_set_watch_paths(self):
        status, body, _ = self.call("/api/monitoring/paths", "POST",
                                    {"paths": [str(self.work)]})
        self.assertEqual(status, 200)
        self.assertEqual(body["watch_paths"], [str(self.work.resolve())])
        self.call("/api/monitoring/paths", "POST", {"paths": []})

    # ---------------------------------------------------------- read endpoints
    def test_status_and_health(self):
        status, body, _ = self.call("/api/status")
        self.assertEqual(status, 200)
        self.assertTrue(body["running"])
        status, body, _ = self.call("/api/health")
        self.assertEqual(status, 200)
        self.assertIn("overall", body)

    def test_process_inventory_is_read_only(self):
        status, body, _ = self.call("/api/processes?limit=5")
        self.assertEqual(status, 200)
        self.assertEqual(body["mode"], "read_only_inventory")

    def test_network_inventory(self):
        status, body, _ = self.call("/api/network/connections")
        self.assertEqual(status, 200)
        self.assertIn("connections", body)

    def test_diagnostics_has_limitations(self):
        status, body, _ = self.call("/api/diagnostics")
        self.assertEqual(status, 200)
        self.assertTrue(body["limitations"])

    def test_unknown_endpoint(self):
        status, _, _ = self.call("/api/does-not-exist")
        self.assertEqual(status, 404)

    def test_invalid_query_parameter(self):
        status, _, _ = self.call("/api/scans?limit=not-a-number")
        self.assertEqual(status, 400)

    def test_errors_never_leak_internals(self):
        status, body, _ = self.call("/api/scan", "POST", {"path": "/nope/missing/path"})
        text = json.dumps(body)
        self.assertNotIn("Traceback", text)
        self.assertNotIn("ase_api.key", text)
        self.assertNotIn(self.key, text)

    def test_config_endpoint_hides_scan_allowlist(self):
        status, body, _ = self.call("/api/config")
        self.assertEqual(status, 200)
        self.assertNotIn("allow_scan_paths", body.get("api", {}))


if __name__ == "__main__":
    unittest.main()
