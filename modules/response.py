"""Alert creation, duplicate suppression, persistence and manual review.

The response engine recommends actions; it never performs a destructive step.
Quarantine only happens when an operator explicitly authorizes it.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from modules.analysis import fingerprint


def _now():
    return datetime.now(timezone.utc)


_RECOMMENDATIONS = {
    "file_changed": "Review the changed file. If it is unexpected, scan it and consider quarantine.",
    "realtime_file_change": "Review the changed file. If it is unexpected, scan it and consider quarantine.",
    "network_indicator_match": "Review the remote endpoint and the owning process before blocking anything.",
    "antivirus_detection": "Review the detection. Quarantine is available with explicit authorization.",
    "default": "Manual review required.",
}


class ASEResponse:
    def __init__(self, event_bus, database=None, settings=None):
        self.event_bus = event_bus
        self.database = database
        self.settings = settings or {}
        self.dedupe_seconds = max(0, int(self.settings.get("alert_dedupe_seconds", 300)))
        self.alerts = []
        self.suppressed = 0
        self.subscribed = False

    def start(self):
        if not self.subscribed:
            self.event_bus.subscribe("analysis.completed", self.handle_analysis)
            self.subscribed = True
        return True

    def stop(self):
        if self.subscribed:
            self.event_bus.unsubscribe("analysis.completed", self.handle_analysis)
            self.subscribed = False
        return True

    def _recent_duplicate(self, alert_fingerprint):
        if self.dedupe_seconds <= 0:
            return None
        since = (_now() - timedelta(seconds=self.dedupe_seconds)).isoformat()
        if self.database is not None and getattr(self.database, "ready", False):
            try:
                return self.database.find_recent_alert(alert_fingerprint, since)
            except Exception:
                return None
        for existing in reversed(self.alerts):
            if existing.get("fingerprint") == alert_fingerprint and existing.get("created_at", "") >= since:
                return existing
        return None

    def handle_analysis(self, data):
        if not isinstance(data, dict):
            return None
        event_type = data.get("event_type") or data.get("event", "unknown")
        severity = data.get("risk_level", "low")
        subject = data.get("file") or data.get("indicator") or data.get("remote_address") or "unknown"

        alert = {
            "event_type": event_type,
            "event": data.get("event", event_type),
            "subject": subject,
            "file": data.get("file"),
            "indicator": data.get("indicator"),
            "risk_score": int(data.get("risk_score", 0)),
            "severity": severity,
            "risk_level": severity,
            "reasons": list(data.get("reasons", []) or []),
            "recommendation": data.get("recommendation")
            or _RECOMMENDATIONS.get(event_type, _RECOMMENDATIONS["default"]),
            "details": {key: value for key, value in data.items() if key != "reasons"},
            "created_at": _now().isoformat(),
            "status": "open",
            "action": "manual_review_required" if data.get("requires_review") else "record_only",
            "incident_id": self._incident_for(subject, event_type),
        }
        # Derived fields are mirrored into the stored blob so they survive a reload.
        alert["details"].update({
            "action": alert["action"],
            "recommendation": alert["recommendation"],
            "event": alert["event"],
        })
        alert["fingerprint"] = fingerprint(alert)

        if not alert["reasons"]:
            alert["reasons"] = ["Event recorded without a specific risk factor."]

        duplicate = self._recent_duplicate(alert["fingerprint"])
        if duplicate is not None:
            self.suppressed += 1
            return {"suppressed": True, "duplicate_of": duplicate.get("id"),
                    "fingerprint": alert["fingerprint"]}

        if self.database is not None and getattr(self.database, "ready", False):
            try:
                alert["id"] = self.database.add_alert(alert)
                if alert.get("incident_id"):
                    self.database.upsert_incident(alert["incident_id"],
                                                  "Incident for %s" % subject, severity)
            except Exception:
                alert["id"] = None
        else:
            alert["id"] = len(self.alerts) + 1

        self.alerts.append(alert)
        if len(self.alerts) > 5000:
            del self.alerts[:1000]

        if self.event_bus is not None:
            try:
                self.event_bus.publish("response.alert_created", alert)
            except Exception:
                pass
        return alert

    @staticmethod
    def _incident_for(subject, event_type):
        """Group related alerts into a stable incident identifier."""
        if not subject or subject == "unknown":
            return None
        return uuid.uuid5(uuid.NAMESPACE_URL, "%s|%s" % (event_type, subject)).hex[:16]

    # ------------------------------------------------------------- queries
    def get_alerts(self, limit=None, status=None, severity=None):
        if self.database is not None and getattr(self.database, "ready", False):
            try:
                return self.database.get_alerts(limit=limit or 50, status=status, severity=severity)
            except Exception:
                pass
        alerts = list(self.alerts)
        if status:
            alerts = [item for item in alerts if item.get("status") == status]
        if severity:
            alerts = [item for item in alerts if item.get("severity") == severity]
        return alerts[-(limit or 50):][::-1]

    def acknowledge(self, alert_id, actor="operator"):
        if self.database is not None and getattr(self.database, "ready", False):
            try:
                acknowledged = self.database.acknowledge_alert(alert_id, actor)
            except Exception:
                acknowledged = False
            if acknowledged and self.event_bus is not None:
                try:
                    self.event_bus.publish("response.alert_acknowledged",
                                           {"id": alert_id, "actor": actor})
                except Exception:
                    pass
            return acknowledged
        for alert in self.alerts:
            if alert.get("id") == alert_id and alert.get("status") == "open":
                alert["status"] = "acknowledged"
                alert["acknowledged_at"] = _now().isoformat()
                alert["acknowledged_by"] = actor
                return True
        return False

    def get_incidents(self, limit=50):
        if self.database is not None and getattr(self.database, "ready", False):
            try:
                return self.database.get_incidents(limit=limit)
            except Exception:
                return []
        grouped = {}
        for alert in self.alerts:
            incident = alert.get("incident_id")
            if not incident:
                continue
            entry = grouped.setdefault(incident, {
                "id": incident, "severity": alert["severity"], "alerts": 0,
                "title": "Incident for %s" % alert.get("subject"),
            })
            entry["alerts"] += 1
        return list(grouped.values())[:limit]

    def get_status(self):
        return {
            "running": self.subscribed,
            "alerts_recorded": len(self.alerts),
            "suppressed_duplicates": self.suppressed,
            "dedupe_seconds": self.dedupe_seconds,
            "mode": "recommendation_only",
        }
