"""API access control: loopback allowlist, rate limiting, request accounting."""
from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
from threading import RLock
from time import time

DEFAULT_ALLOWED_IPS = ("127.0.0.1", "::1", "::ffff:127.0.0.1")


class ASEAPISecurity:
    """Per-client sliding-window rate limiting plus an audit trail."""

    def __init__(self, max_requests=120, window_seconds=60, allowed_ips=None, history_size=500):
        self.max_requests = max(1, int(max_requests))
        self.window_seconds = max(1, int(window_seconds))
        self.allowed_ips = set(allowed_ips or DEFAULT_ALLOWED_IPS)
        self.requests = defaultdict(deque)
        self.request_history = deque(maxlen=max(1, int(history_size)))
        self.total_requests = 0
        self.blocked_requests = 0
        self.rejected_clients = 0
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.lock = RLock()

    def check_ip(self, ip):
        allowed = ip in self.allowed_ips
        if not allowed:
            with self.lock:
                self.rejected_clients += 1
        return allowed

    def check_rate_limit(self, ip):
        now = time()
        with self.lock:
            history = self.requests[ip]
            while history and now - history[0] >= self.window_seconds:
                history.popleft()
            if len(history) >= self.max_requests:
                self.blocked_requests += 1
                return False
            history.append(now)
            return True

    def log_request(self, ip, method, path, status):
        """Record a request. The path is truncated and never includes a body."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ip": ip,
            "method": str(method)[:10],
            "path": str(path)[:200],
            "status": int(status),
        }
        with self.lock:
            self.total_requests += 1
            self.request_history.append(entry)
        return entry

    def get_health(self):
        with self.lock:
            return {
                "status": "healthy",
                "started_at": self.started_at,
                "total_requests": self.total_requests,
                "blocked_requests": self.blocked_requests,
                "rejected_clients": self.rejected_clients,
                "tracked_clients": len(self.requests),
                "max_requests_per_window": self.max_requests,
                "window_seconds": self.window_seconds,
            }

    def get_request_history(self, limit=20):
        limit = int(limit)
        if not 1 <= limit <= 100:
            raise ValueError("Limit must be between 1 and 100")
        with self.lock:
            return list(self.request_history)[-limit:][::-1]
