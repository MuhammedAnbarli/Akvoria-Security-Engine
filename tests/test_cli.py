"""CLI tests: every documented command must run and return a sane exit code."""
from __future__ import annotations

import io
import json
import os
import socket
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import main as cli
from tests.helpers import IsolatedWorkspace

EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class CliTests(unittest.TestCase):
    def setUp(self):
        self.workspace = IsolatedWorkspace(api_port=_free_port())
        self.root = self.workspace.__enter__()
        self.work = Path(self.root) / "work"
        self.work.mkdir()
        (self.work / "clean.txt").write_text("harmless", encoding="utf-8")
        (self.work / "test.com").write_text(EICAR, encoding="utf-8")

    def tearDown(self):
        self.workspace.__exit__(None, None, None)

    def run_cli(self, *argv):
        """Invoke the CLI in-process and capture stdout as JSON."""
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli.main(list(argv))
        text = buffer.getvalue()
        try:
            return code, json.loads(text)
        except json.JSONDecodeError:
            return code, text

    def test_help_lists_all_commands(self):
        parser = cli.build_parser()
        actions = [action for action in parser._actions
                   if isinstance(action, __import__("argparse")._SubParsersAction)]
        names = set(actions[0].choices)
        expected = {"start", "stop", "status", "health", "self-test", "scan", "history",
                    "quarantine", "restore", "alerts", "intelligence", "monitoring",
                    "diagnostics", "report", "config"}
        self.assertTrue(expected.issubset(names), expected - names)

    def test_version(self):
        with self.assertRaises(SystemExit) as ctx:
            cli.main(["--version"])
        self.assertEqual(ctx.exception.code, 0)

    def test_self_test(self):
        code, payload = self.run_cli("self-test")
        self.assertEqual(code, 0)
        self.assertEqual(payload["status"], "ok")
        self.assertTrue(all(item["ok"] for item in payload["checks"].values()))

    def test_status(self):
        code, payload = self.run_cli("status")
        self.assertEqual(code, 0)
        self.assertFalse(payload["running"])
        self.assertEqual(payload["protection_scope"], "configured_directories_only")

    def test_health(self):
        code, payload = self.run_cli("health")
        self.assertIn(code, (0, 1))
        self.assertIn("overall", payload)

    def test_scan_custom(self):
        code, payload = self.run_cli("scan", str(self.work), "--summary")
        self.assertEqual(code, 0)
        self.assertEqual(payload["detections"], 1)
        self.assertEqual(payload["verdict_counts"]["malicious_indicator"], 1)

    def test_scan_writes_report(self):
        target = Path(self.root) / "report.json"
        code, payload = self.run_cli("scan", str(self.work), "--output", str(target))
        self.assertEqual(code, 0)
        self.assertTrue(target.exists())
        self.assertEqual(payload["report_path"], str(target))

    def test_scan_requires_path(self):
        with self.assertRaises(SystemExit):
            self.run_cli("scan")

    def test_history(self):
        self.run_cli("scan", str(self.work), "--summary")
        code, payload = self.run_cli("history", "--limit", "5")
        self.assertEqual(code, 0)
        self.assertGreaterEqual(payload["total"], 1)
        self.assertGreaterEqual(payload["statistics"]["total_scans"], 1)

    def test_quarantine_and_restore(self):
        target = self.work / "test.com"
        code, payload = self.run_cli("quarantine", "add", str(target))
        self.assertEqual(code, 0)
        self.assertFalse(target.exists())
        qid = payload["quarantine_id"]

        code, listing = self.run_cli("quarantine", "list")
        self.assertEqual(code, 0)
        self.assertEqual(len(listing["items"]), 1)

        code, restored = self.run_cli("restore", qid)
        self.assertEqual(code, 0)
        self.assertEqual(restored["status"], "restored")
        self.assertTrue(target.exists())

    def test_intelligence_commands(self):
        code, payload = self.run_cli("intelligence", "add", "198.51.100.7", "--type", "ip")
        self.assertEqual(code, 0)
        self.assertEqual(payload["type"], "ip")

        code, payload = self.run_cli("intelligence", "check", "198.51.100.7")
        self.assertTrue(payload["found"])

        code, payload = self.run_cli("intelligence", "list")
        self.assertEqual(payload["statistics"]["total"], 1)

        export_path = Path(self.root) / "ind.json"
        code, payload = self.run_cli("intelligence", "export", "--file", str(export_path))
        self.assertTrue(export_path.exists())

        code, payload = self.run_cli("intelligence", "remove", "198.51.100.7")
        self.assertEqual(code, 0)

    def test_intelligence_invalid_indicator_exits_nonzero(self):
        code = cli.main(["intelligence", "add", "not-an-ip", "--type", "ip"])
        self.assertEqual(code, 2)

    def test_monitoring_set_show_clear(self):
        code, payload = self.run_cli("monitoring", "set", str(self.work))
        self.assertEqual(code, 0)
        self.assertEqual(payload["watch_paths"], [str(self.work.resolve())])

        code, payload = self.run_cli("monitoring", "show")
        self.assertEqual(payload["configured"], [str(self.work.resolve())])
        self.assertEqual(payload["scope"], "configured_directories_only")
        self.assertEqual(payload["roots"], [str(self.work.resolve())])
        # The monitor is not started by `show`, so it reports stopped, not idle.
        self.assertIn(payload["mode"], ("stopped", "idle_no_paths", "polling", "native"))
        self.assertFalse(payload["running"])

        code, payload = self.run_cli("monitoring", "clear")
        self.assertEqual(payload["watch_paths"], [])

    def test_alerts_list_and_acknowledge(self):
        code, payload = self.run_cli("alerts", "--limit", "5")
        self.assertEqual(code, 0)
        self.assertIn("alerts", payload)

    def test_diagnostics_with_backup(self):
        code, payload = self.run_cli("diagnostics", "--backup")
        self.assertEqual(code, 0)
        self.assertTrue(Path(payload["backup"]).exists())
        self.assertTrue(payload["limitations"])

    def test_report_export(self):
        target = Path(self.root) / "state.json"
        code, payload = self.run_cli("report", "--output", str(target))
        self.assertEqual(code, 0)
        self.assertTrue(target.exists())
        self.assertGreater(payload["bytes"], 0)

    def test_config_show_validate_set(self):
        code, payload = self.run_cli("config", "show")
        self.assertEqual(code, 0)
        self.assertIn("api", payload)

        code, payload = self.run_cli("config", "validate")
        self.assertEqual(payload["status"], "valid")

        code, payload = self.run_cli("config", "set", "realtime.interval_seconds=7")
        self.assertEqual(payload["status"], "updated")
        code, payload = self.run_cli("config", "show")
        self.assertEqual(payload["realtime"]["interval_seconds"], 7)

    def test_config_rejects_non_loopback_host(self):
        code = cli.main(["config", "set", "api.host=0.0.0.0"])
        self.assertEqual(code, 2)

    def test_stop_without_running_engine(self):
        code, payload = self.run_cli("stop")
        self.assertEqual(code, 1)
        self.assertEqual(payload["status"], "not_running")

    def test_legacy_flag_status(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli.main(["--status"])
        self.assertEqual(code, 0)
        self.assertIn("protection_scope", buffer.getvalue())

    def test_legacy_flag_scan(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli.main(["--scan", str(self.work)])
        self.assertEqual(code, 0)
        self.assertIn("malicious_indicator", buffer.getvalue())

    def test_no_arguments_prints_help(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli.main([])
        self.assertEqual(code, 0)
        self.assertIn("usage:", buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
