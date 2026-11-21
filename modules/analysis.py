"""Central event normalization, correlation and explainable risk scoring.

Every alert this engine emits carries a ``reasons`` list so an operator can see
why it fired. Nothing here performs a destructive action.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

# Weights are additive and capped, so the score stays explainable.
_BASE_SCORE = {"file_changed": 20, "network_indicator_match": 60, "antivirus_detection": 70}
_SEVERITY_BANDS = ((80, "critical"), (60, "high"), (35, "medium"), (0, "low"))


def _now():
    return datetime.now(timezone.utc)


def severity_for(score):
    for threshold, name in _SEVERITY_BANDS:
        if score >= threshold:
            return name
    return "low"


class ASEAnalysis:
    def __init__(self, event_bus, database=None, response=None, settings=None):
        self.event_bus = event_bus
        self.database = database
        self.response = response
        self.settings = settings or {}
        self.window = timedelta(seconds=int(self.settings.get("correlation_window_seconds", 300)))
        self.results = []
        self.events = []
        self.subscribed = False

    def start(self):
        if not self.subscribed:
            self.event_bus.subscribe("detect.file_changed", self.analyze_file_change)
            self.event_bus.subscribe("realtime.file_changed", self.analyze_realtime_change)
            self.event_bus.subscribe("network.indicator_match", self.analyze_network_indicator)
            self.event_bus.subscribe("antivirus.detection", self.analyze_antivirus_detection)
            self.subscribed = True
        return True

    def stop(self):
        if self.subscribed:
            self.event_bus.unsubscribe("detect.file_changed", self.analyze_file_change)
            self.event_bus.unsubscribe("realtime.file_changed", self.analyze_realtime_change)
            self.event_bus.unsubscribe("network.indicator_match", self.analyze_network_indicator)
            self.event_bus.unsubscribe("antivirus.detection", self.analyze_antivirus_detection)
            self.subscribed = False
        return True

    # ------------------------------------------------------------- scoring
    def calculate_risk(self, event):
        event_type = event.get("event_type") or event.get("event") or "file_changed"
        score = _BASE_SCORE.get(event_type, 15)
        reasons = []

        if event_type == "file_changed":
            reasons.append("A monitored file changed.")
        elif event_type == "network_indicator_match":
            reasons.append("An observed remote address matched a locally configured threat indicator.")
        elif event_type == "antivirus_detection":
            reasons.append("The local antivirus engine returned a detection verdict.")

        if event.get("suspicious_location"):
            score += 20
            reasons.append("File is in a flagged location.")
        if event.get("repeated_changes"):
            score += 15
            reasons.append("The same file changed repeatedly within the correlation window.")
        if event.get("status") == "malicious_indicator":
            score += 25
            reasons.append("A local signature or high-confidence rule matched.")
        elif event.get("status") == "suspicious":
            score += 10
            reasons.append("One or more heuristics matched; this alone does not prove malicious intent.")
        confidence = event.get("confidence")
        if isinstance(confidence, int) and confidence >= 80:
            score += 10
            reasons.append("The matching indicator has high confidence.")
        if event.get("change") == "created":
            reasons.append("The file was newly created in a monitored directory.")

        score = max(0, min(score, 100))
        if not reasons:
            reasons.append("Event recorded without additional risk factors.")
        return score, severity_for(score), reasons

    def correlate_events(self, event):
        now = _now()
        cutoff = now - self.window
        self.events = [item for item in self.events if item["timestamp"] >= cutoff]
        subject = event.get("file") or event.get("indicator") or event.get("remote_address") or "unknown"
        related = [item for item in self.events if item["subject"] == subject]
        self.events.append({"subject": subject, "timestamp": now,
                            "event_type": event.get("event_type") or event.get("event")})
        count = len(related) + 1
        kinds = {item["event_type"] for item in related} | {event.get("event_type") or event.get("event")}
        return {
            "subject": subject,
            "related_event_count": count,
            "repeated_changes": count >= 3,
            "cross_module_correlation": len(kinds) > 1,
            "correlation_window_seconds": int(self.window.total_seconds()),
        }

    # ------------------------------------------------------------- handlers
    def _complete(self, result):
        self.results.append(result)
        if len(self.results) > 5000:
            del self.results[:1000]
        if self.response is not None:
            self.response.handle_analysis(result)
        if self.event_bus is not None:
            try:
                self.event_bus.publish("analysis.completed", result)
            except Exception:
                pass
        return result

    @staticmethod
    def _correlation_block(correlation):
        return {key: correlation[key] for key in
                ("related_event_count", "repeated_changes",
                 "cross_module_correlation", "correlation_window_seconds")}

    def analyze_file_change(self, data):
        if not isinstance(data, dict):
            return None
        enriched = {"event_type": "file_changed", **data}
        correlation = self.correlate_events(enriched)
        enriched.update(correlation)
        score, level, reasons = self.calculate_risk(enriched)
        result = {
            "event": "file_changed",
            "event_type": "file_changed",
            "file": data.get("file", "unknown"),
            "risk_score": score,
            "risk_level": level,
            "reasons": reasons,
            "correlation": self._correlation_block(correlation),
            "recommendation": "review_file_change",
            "timestamp": _now().isoformat(),
            "requires_review": score >= 35,
        }
        return self._complete(result)

    def analyze_realtime_change(self, data):
        if not isinstance(data, dict):
            return None
        enriched = {"event_type": "file_changed", **data}
        correlation = self.correlate_events(enriched)
        enriched.update(correlation)
        score, level, reasons = self.calculate_risk(enriched)
        result = {
            "event": "realtime_file_change",
            "event_type": "file_changed",
            "file": data.get("file", "unknown"),
            "change": data.get("change"),
            "scan_verdict": data.get("status"),
            "risk_score": score,
            "risk_level": level,
            "reasons": reasons,
            "correlation": self._correlation_block(correlation),
            "recommendation": "review_file_change",
            "timestamp": _now().isoformat(),
            "requires_review": score >= 35,
        }
        return self._complete(result)

    def analyze_network_indicator(self, data):
        if not isinstance(data, dict):
            return None
        enriched = {"event_type": "network_indicator_match", **data}
        correlation = self.correlate_events(enriched)
        enriched.update(correlation)
        score, level, reasons = self.calculate_risk(enriched)
        result = {
            "event": "network_indicator_match",
            "event_type": "network_indicator_match",
            "file": None,
            "indicator": data.get("indicator") or data.get("remote_address"),
            "remote_address": data.get("remote_address"),
            "remote_port": data.get("remote_port"),
            "protocol": data.get("protocol"),
            "risk_score": score,
            "risk_level": level,
            "reasons": reasons,
            "correlation": self._correlation_block(correlation),
            "recommendation": "review_remote_endpoint",
            "timestamp": _now().isoformat(),
            "requires_review": True,
        }
        return self._complete(result)

    def analyze_antivirus_detection(self, data):
        if not isinstance(data, dict):
            return None
        enriched = {"event_type": "antivirus_detection", **data}
        correlation = self.correlate_events(enriched)
        enriched.update(correlation)
        score, level, reasons = self.calculate_risk(enriched)
        result = {
            "event": "antivirus_detection",
            "event_type": "antivirus_detection",
            "file": data.get("file", "unknown"),
            "status": data.get("status"),
            "sha256": data.get("sha256"),
            "risk_score": score,
            "risk_level": level,
            "reasons": reasons + list(data.get("explanations", []) or []),
            "correlation": self._correlation_block(correlation),
            "recommendation": "review_and_consider_quarantine",
            "timestamp": _now().isoformat(),
            "requires_review": True,
        }
        return self._complete(result)

    def get_results(self, limit=None):
        if limit:
            return list(self.results)[-int(limit):]
        return list(self.results)

    def get_status(self):
        return {
            "running": self.subscribed,
            "results_recorded": len(self.results),
            "correlation_window_seconds": int(self.window.total_seconds()),
        }


def fingerprint(alert):
    """Stable identity for duplicate suppression."""
    material = "|".join([
        str(alert.get("event_type", "")),
        str(alert.get("subject", "")),
        str(alert.get("severity", "")),
    ])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]
