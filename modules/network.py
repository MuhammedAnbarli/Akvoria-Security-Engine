"""Passive network inventory: read-only connection listing and indicator matching.

No scanning, no blocking, no credential collection. On hosts without procfs the
module reports that the platform is unsupported instead of guessing.
"""
from __future__ import annotations

import ipaddress
import platform
import socket
import time
from pathlib import Path

_PROC_TABLES = (
    ("/proc/net/tcp", "tcp", 4),
    ("/proc/net/tcp6", "tcp", 6),
    ("/proc/net/udp", "udp", 4),
    ("/proc/net/udp6", "udp", 6),
)

_TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}


class ASENetwork:
    def __init__(self, event_bus, intelligence=None, settings=None):
        self.event_bus = event_bus
        self.intelligence = intelligence
        self.settings = settings or {}
        self.suppression_seconds = max(0, int(self.settings.get("alert_suppression_seconds", 900)))
        self.last_result = None
        self.history = []
        self._alerted = {}
        self._lock = __import__("threading").RLock()

    @staticmethod
    def _decode_proc_address(value, family):
        raw = bytes.fromhex(value)
        if family == 4:
            return socket.inet_ntop(socket.AF_INET, raw[::-1])
        if family == 6:
            # Linux procfs stores IPv6 words in native little-endian order.
            raw = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
            return socket.inet_ntop(socket.AF_INET6, raw)
        raise ValueError("Unsupported address family")

    @classmethod
    def _parse_proc_table(cls, text, protocol, family, state_filter=None):
        rows = []
        for line in text.splitlines()[1:]:
            fields = line.split()
            if len(fields) < 4:
                continue
            try:
                local_addr, local_port = fields[1].split(":")
                remote_addr, remote_port = fields[2].split(":")
                state = fields[3]
                if state_filter is not None and state not in state_filter:
                    continue
                decoded_local = cls._decode_proc_address(local_addr, family)
                decoded_remote = cls._decode_proc_address(remote_addr, family)
                rows.append({
                    "protocol": protocol,
                    "family": family,
                    "local_address": decoded_local,
                    "local_ip": decoded_local,
                    "local_port": int(local_port, 16),
                    "remote_address": decoded_remote,
                    "remote_ip": decoded_remote,
                    "remote_port": int(remote_port, 16),
                    "state": state,
                    "state_name": _TCP_STATES.get(state, state),
                })
            except (ValueError, IndexError):
                continue
        return rows

    @staticmethod
    def is_supported():
        from core.platform_info import PlatformInfo
        return PlatformInfo.has_procfs()

    def get_connections(self):
        if not self.is_supported():
            return self.unsupported_result()
        rows = []
        for filename, protocol, family in _PROC_TABLES:
            try:
                rows.extend(self._parse_proc_table(Path(filename).read_text("utf-8"), protocol, family))
            except OSError:
                continue

        matches = []
        for row in rows:
            remote = row["remote_address"]
            if self.intelligence is None or remote in ("0.0.0.0", "::"):
                continue
            try:
                if ipaddress.ip_address(remote).is_unspecified:
                    continue
            except ValueError:
                continue
            result = self.intelligence.check_indicator(remote)
            if not result.get("found"):
                continue
            identity = (row["protocol"], row["local_port"], remote, row["remote_port"])
            now = time.time()
            with self._lock:
                previous = self._alerted.get(identity)
                if previous is not None and now - previous < self.suppression_seconds:
                    continue
                self._alerted[identity] = now
            alert = {**row, "indicator": remote, "indicator_type": result.get("type"),
                     "source": result.get("source"), "confidence": result.get("confidence")}
            matches.append(alert)
            if self.event_bus is not None:
                try:
                    self.event_bus.publish("network.indicator_match", alert)
                except Exception:
                    pass

        payload = {
            "total": len(rows),
            "connections": rows,
            "indicator_matches": matches,
            "supported": True,
            "mode": "read_only_procfs_inventory",
            "platform": platform.system(),
            "captured_at": time.time(),
        }
        with self._lock:
            self.last_result = payload
            self.history = (self.history + [{
                "captured_at": payload["captured_at"],
                "total": len(rows),
                "matches": len(matches),
            }])[-100:]
        return payload

    def unsupported_result(self):
        return {
            "total": 0,
            "connections": [],
            "indicator_matches": [],
            "supported": False,
            "mode": "unsupported_platform",
            "platform": platform.system(),
            "detail": "Passive connection inventory requires Linux procfs.",
        }

    def get_history(self, limit=20):
        with self._lock:
            return list(self.history)[-max(1, int(limit)):]

    def check_connection(self):
        try:
            hostname = socket.gethostname()
            addresses = socket.getaddrinfo(hostname, None)
            result = {"status": "available", "hostname": hostname, "address_count": len(addresses)}
        except OSError as error:
            result = {"status": "unavailable", "error": str(error)}
        self.last_result = result
        if self.event_bus is not None:
            try:
                self.event_bus.publish("network.checked", result)
            except Exception:
                pass
        return result

    def start(self):
        return True

    def stop(self):
        return True

    def get_status(self):
        return {
            "running": True,
            "supported": self.is_supported(),
            "platform": platform.system(),
            "mode": "passive_read_only",
            "suppression_seconds": self.suppression_seconds,
            "history_entries": len(self.history),
        }
