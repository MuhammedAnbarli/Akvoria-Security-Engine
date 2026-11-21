"""Network and process monitor tests, including platform fallback behaviour."""
from __future__ import annotations

import unittest
from unittest import mock

from core.event_bus import EventBus
from modules.intelligence import ASEIntelligence
from modules.network import ASENetwork
from modules.process import ASEProcessMonitor

PROC_TCP_SAMPLE = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 08080808:0050 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1
"""


class ProcParsingTests(unittest.TestCase):
    def test_ipv4_decode(self):
        self.assertEqual(ASENetwork._decode_proc_address("0100007F", 4), "127.0.0.1")
        self.assertEqual(ASENetwork._decode_proc_address("08080808", 4), "8.8.8.8")

    def test_ipv6_decode(self):
        self.assertEqual(
            ASENetwork._decode_proc_address("00000000000000000000000001000000", 6), "::1")

    def test_unsupported_family(self):
        with self.assertRaises(ValueError):
            ASENetwork._decode_proc_address("00", 5)

    def test_parse_table(self):
        rows = ASENetwork._parse_proc_table(PROC_TCP_SAMPLE, "tcp", 4)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["local_port"], 8080)
        self.assertEqual(rows[0]["remote_address"], "8.8.8.8")
        self.assertEqual(rows[0]["remote_port"], 80)
        self.assertEqual(rows[0]["state_name"], "ESTABLISHED")
        self.assertEqual(rows[1]["state_name"], "LISTEN")

    def test_malformed_lines_skipped(self):
        rows = ASENetwork._parse_proc_table("header\n  bad line\n", "tcp", 4)
        self.assertEqual(rows, [])


class NetworkTests(unittest.TestCase):
    def setUp(self):
        self.bus = EventBus()
        self.matches = []
        self.bus.subscribe("network.indicator_match", lambda data: self.matches.append(data))
        self.intelligence = ASEIntelligence(self.bus)
        self.network = ASENetwork(self.bus, self.intelligence, {"alert_suppression_seconds": 900})

    def test_indicator_match_emits_event(self):
        self.intelligence.add_indicator("8.8.8.8", "ip")
        with mock.patch.object(ASENetwork, "is_supported", return_value=True):
            with mock.patch("modules.network._PROC_TABLES", (("/proc/net/tcp", "tcp", 4),)):
                with mock.patch("pathlib.Path.read_text", return_value=PROC_TCP_SAMPLE):
                    result = self.network.get_connections()
        self.assertEqual(result["total"], 2)
        self.assertEqual(len(result["indicator_matches"]), 1)
        self.assertEqual(result["indicator_matches"][0]["indicator"], "8.8.8.8")
        self.assertEqual(len(self.matches), 1)

    def test_duplicate_alert_suppressed(self):
        self.intelligence.add_indicator("8.8.8.8", "ip")
        with mock.patch.object(ASENetwork, "is_supported", return_value=True):
            with mock.patch("modules.network._PROC_TABLES", (("/proc/net/tcp", "tcp", 4),)):
                with mock.patch("pathlib.Path.read_text", return_value=PROC_TCP_SAMPLE):
                    self.network.get_connections()
                    second = self.network.get_connections()
        self.assertEqual(second["indicator_matches"], [])
        self.assertEqual(len(self.matches), 1)

    def test_unspecified_remote_ignored(self):
        self.intelligence.add_indicator("0.0.0.0", "ip")
        with mock.patch("modules.network._PROC_TABLES", (("/proc/net/tcp", "tcp", 4),)):
            with mock.patch("pathlib.Path.read_text", return_value=PROC_TCP_SAMPLE):
                result = self.network.get_connections()
        self.assertEqual(result["indicator_matches"], [])

    def test_status_reports_mode_and_support(self):
        status = self.network.get_status()
        self.assertEqual(status["mode"], "passive_read_only")
        self.assertIn("supported", status)

    def test_unsupported_result_shape(self):
        result = self.network.unsupported_result()
        self.assertFalse(result["supported"])
        self.assertEqual(result["connections"], [])

    def test_history_records(self):
        with mock.patch.object(ASENetwork, "is_supported", return_value=True):
            with mock.patch("modules.network._PROC_TABLES", (("/proc/net/tcp", "tcp", 4),)):
                with mock.patch("pathlib.Path.read_text", return_value=PROC_TCP_SAMPLE):
                    self.network.get_connections()
        self.assertEqual(len(self.network.get_history()), 1)


class ProcessTests(unittest.TestCase):
    def setUp(self):
        self.monitor = ASEProcessMonitor()
        self.monitor.start()

    def tearDown(self):
        self.monitor.stop()

    def test_read_only_inventory(self):
        rows = self.monitor.get_processes(10)
        self.assertIsInstance(rows, list)
        self.assertLessEqual(len(rows), 10)
        for row in rows:
            self.assertIn("pid", row)
            self.assertIn("name", row)

    def test_limit_is_bounded(self):
        self.assertLessEqual(len(self.monitor.get_processes(1)), 1)
        self.assertLessEqual(len(self.monitor.get_processes(100000)), 10000)

    def test_invalid_limit_falls_back(self):
        rows = self.monitor.get_processes("not a number")
        self.assertIsInstance(rows, list)

    def test_status_reports_read_only(self):
        status = self.monitor.get_status()
        self.assertEqual(status["mode"], "read_only_inventory")
        self.assertIn("never terminated", status["note"])

    def test_unsupported_platform_reports_cleanly(self):
        with mock.patch.object(ASEProcessMonitor, "is_supported", return_value=False):
            rows = self.monitor.get_processes(5)
            self.assertEqual(rows, [])
            self.assertIn("unsupported", (self.monitor.last_error or "").lower())

    def test_stop_sets_running_false(self):
        self.monitor.stop()
        self.assertFalse(self.monitor.get_status()["running"])


if __name__ == "__main__":
    unittest.main()
