"""Platform compatibility tests: Windows/Android fallbacks and capability reporting."""
from __future__ import annotations

import unittest
from unittest import mock

from core.platform_info import PlatformInfo
from modules.network import ASENetwork
from modules.process import ASEProcessMonitor


class PlatformInfoTests(unittest.TestCase):
    def test_reports_current_platform(self):
        info = PlatformInfo.current()
        self.assertIn(info["os"], ("Linux", "Windows", "Darwin", "Android"))
        self.assertIn("capabilities", info)

    def test_android_detection(self):
        with mock.patch("core.platform_info.PlatformInfo._is_android", return_value=True):
            info = PlatformInfo.current()
        self.assertTrue(info["android"])
        self.assertEqual(info["protection_scope"], "configured_directories_only")

    def test_windows_has_no_procfs(self):
        with mock.patch("os.name", "nt"):
            self.assertFalse(PlatformInfo.has_procfs())

    def test_limitations_are_explicit(self):
        info = PlatformInfo.current()
        self.assertTrue(info["limitations"])
        self.assertTrue(any("configured" in line.lower() for line in info["limitations"]))


class NetworkFallbackTests(unittest.TestCase):
    def test_unsupported_platform_returns_structured_result(self):
        with mock.patch("core.platform_info.PlatformInfo.has_procfs", return_value=False):
            network = ASENetwork(None, None, {})
            result = network.get_connections()
        self.assertFalse(result["supported"])
        self.assertEqual(result["connections"], [])
        self.assertTrue(result["detail"])

    def test_status_never_claims_support_when_absent(self):
        with mock.patch("core.platform_info.PlatformInfo.has_procfs", return_value=False):
            network = ASENetwork(None, None, {})
            status = network.get_status()
        self.assertFalse(status["supported"])


class ProcessFallbackTests(unittest.TestCase):
    def test_unsupported_platform_returns_empty_list(self):
        with mock.patch("core.platform_info.PlatformInfo.has_procfs", return_value=False):
            with mock.patch("os.name", "java"):
                monitor = ASEProcessMonitor()
                monitor.start()
                self.assertEqual(monitor.get_processes(10), [])
                self.assertFalse(monitor.is_supported())

    def test_windows_psutil_path_degrades_without_psutil(self):
        with mock.patch("os.name", "nt"):
            monitor = ASEProcessMonitor()
            monitor.start()
            try:
                rows = monitor.get_processes(5)
                self.assertIsInstance(rows, list)
            finally:
                monitor.stop()

    def test_permission_errors_are_not_fatal(self):
        monitor = ASEProcessMonitor()
        monitor.start()
        try:
            with mock.patch("builtins.open", side_effect=PermissionError("denied")):
                self.assertEqual(monitor.get_processes(5), [])
                self.assertTrue(monitor.last_error is None or isinstance(monitor.last_error, str))
        finally:
            monitor.stop()


if __name__ == "__main__":
    unittest.main()
