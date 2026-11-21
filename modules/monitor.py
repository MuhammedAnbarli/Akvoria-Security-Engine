"""Engine health aggregation for operators and the API."""
from __future__ import annotations

from datetime import datetime, timezone


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


class ASEMonitor:
    def __init__(self, engine):
        self.engine = engine
        self.last_check = None

    def start(self):
        self.last_check = datetime.now(timezone.utc)
        return True

    def stop(self):
        return True

    @staticmethod
    def _probe(predicate, failure_state, **extra):
        try:
            healthy = bool(predicate())
        except Exception:
            return {"state": "failed", **extra}
        return {"state": "healthy" if healthy else failure_state, **extra}

    @staticmethod
    def _safe_health(component):
        try:
            return component.health()
        except Exception:
            return {"state": "unknown"}

    @staticmethod
    def _capability(component):
        try:
            supported = bool(component.is_supported())
        except Exception:
            return {"state": "unknown", "supported": False}
        return {"state": "healthy" if supported else "unsupported", "supported": supported}

    @staticmethod
    def _probe(predicate, failure_state, **extra):
        try:
            healthy = bool(predicate())
        except Exception:
            return {"state": "failed", **extra}
        return {"state": "healthy" if healthy else failure_state, **extra}

    @staticmethod
    def _safe_health(component):
        try:
            return component.health()
        except Exception:
            return {"state": "unknown"}

    @staticmethod
    def _capability(component):
        try:
            supported = bool(component.is_supported())
        except Exception:
            return {"state": "unknown", "supported": False}
        return {"state": "healthy" if supported else "unsupported", "supported": supported}

    def check(self):
        """Return an honest snapshot of every subsystem's state."""
        self.last_check = datetime.now(timezone.utc)
        engine = self.engine

        # Every probe is guarded: a health check must report, never raise.
        modules = dict(engine.module_manager.get_status()) if engine.module_manager else {}
        checks = {
            "engine": {
                "state": "healthy" if engine.running else "stopped",
                "running": bool(engine.running),
            },
            "database": self._probe(
                lambda: bool(engine.database.ready), "stopped",
                schema_version=getattr(engine.database, "schema_version", None)
                if getattr(engine.database, "ready", False) else None),
            "scheduler": self._probe(
                lambda: bool(engine.scheduler.running), "stopped",
                tasks=len(engine.scheduler.get_status().get("tasks", {}))
                if getattr(engine.scheduler, "running", False) else 0),
            "antivirus": self._probe(lambda: bool(engine.antivirus.started), "stopped"),
            "realtime": self._safe_health(engine.realtime),
            "network": self._capability(engine.network),
            "process": self._capability(engine.process),
        }

        states = [entry["state"] for entry in checks.values()]
        if not engine.running:
            overall = "stopped"
        elif any(state in ("degraded", "stalled", "failed") for state in states):
            overall = "degraded"
        elif any(state == "unsupported" for state in states):
            overall = "healthy_with_unsupported_features"
        else:
            overall = "healthy"

        return {
            "engine_running": engine.running,
            "overall": overall,
            "modules": modules,
            "checks": checks,
            "last_check": self.last_check.isoformat(),
        }
