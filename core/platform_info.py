"""Platform capability reporting.

The engine runs unprivileged on Linux, Android/Termux and Windows. Where a
capability is unavailable the caller must report it as unsupported rather than
silently degrade.
"""
from __future__ import annotations

import os
import platform
import sys
from pathlib import Path


class PlatformInfo:
    @staticmethod
    def _is_android():
        if "ANDROID_ROOT" in os.environ or "ANDROID_DATA" in os.environ:
            return True
        try:
            return "android" in Path("/proc/version").read_text("utf-8").lower()
        except OSError:
            return False

    @staticmethod
    def has_procfs():
        """procfs is the passive source for connection and process inventory."""
        return os.name != "nt" and Path("/proc/net/tcp").exists()

    @staticmethod
    def has_inotify():
        if os.name == "nt":
            return False
        try:
            import ctypes
            library = ctypes.CDLL(None, use_errno=True)
            return hasattr(library, "inotify_init1")
        except (OSError, AttributeError, ImportError):
            return False

    @staticmethod
    def optional_packages():
        available = {}
        for module in ("yara", "cryptography", "psutil", "watchdog"):
            try:
                __import__(module)
                available[module] = True
            except ImportError:
                available[module] = False
        return available

    @classmethod
    def current(cls):
        os_name = platform.system() or os.name
        android = cls._is_android()
        procfs = cls.has_procfs()
        packages = cls.optional_packages()
        return {
            "os": "Android" if android else os_name,
            "android": android,
            "release": platform.release(),
            "python": sys.version.split()[0],
            "capabilities": {
                "procfs_inventory": procfs,
                "native_filesystem_events": cls.has_inotify() and not android,
                "polling_fallback": True,
                "yara_scanning": packages["yara"],
                "signed_feed_verification": packages["cryptography"],
            },
            "protection_scope": "configured_directories_only",
            "limitations": [
                "Monitoring covers configured directories only.",
                "System-wide or kernel-level protection is not implemented.",
                "Android does not expose system-wide filesystem monitoring to "
                "an unprivileged app.",
                "Network and process inventories are passive and read-only.",
            ],
        }
