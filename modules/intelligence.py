"""Threat intelligence store with strict validation and normalization.

Unsigned external data is never trusted automatically: the only bulk import
path is :mod:`modules.threat_feed`, which verifies an Ed25519 signature.
"""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core.exceptions import ASEIntelligenceError

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TYPES = ("ip", "domain", "sha256")


def _utc_now():
    return datetime.now(timezone.utc)


class ASEIntelligence:
    def __init__(self, event_bus, database=None, settings=None):
        self.event_bus = event_bus
        self.database = database
        self.settings = settings or {}
        self.ttl_days = int(self.settings.get("indicator_ttl_days", 0) or 0)
        self.max_indicators = max(1, int(self.settings.get("max_indicators", 100000)))
        self.indicators = {}
        self._index = set()

    # ------------------------------------------------------------- lifecycle
    def start(self):
        self.reload()
        return True

    def stop(self):
        return True

    def reload(self):
        """Load indicators from the database into the in-memory index."""
        if self.database is None or not getattr(self.database, "ready", False):
            return 0
        rows = self.database.get_indicators()
        self.indicators = {}
        for row in rows:
            self.indicators[row["indicator"]] = {
                "type": row["indicator_type"],
                "source": row["source"],
                "confidence": row.get("confidence", 50),
                "expires_at": row.get("expires_at"),
            }
        self._index = set(self.indicators)
        return len(self.indicators)

    # ------------------------------------------------------------- validation
    @staticmethod
    def normalize(indicator, indicator_type):
        """Return the canonical form of an indicator or raise."""
        if indicator_type not in _TYPES:
            raise ASEIntelligenceError("Unsupported indicator type: %s" % indicator_type)
        if not isinstance(indicator, str):
            raise ASEIntelligenceError("Indicator must be a string")
        value = indicator.strip().lower()
        if not value or len(value) > 512:
            raise ASEIntelligenceError("Indicator must be 1-512 characters")

        if indicator_type == "ip":
            try:
                return str(ipaddress.ip_address(value))
            except ValueError as exc:
                raise ASEIntelligenceError("Invalid IP address: %s" % value) from exc
        if indicator_type == "domain":
            value = value.rstrip(".")
            if not _DOMAIN_RE.match(value):
                raise ASEIntelligenceError("Invalid domain name: %s" % value)
            return value
        value = value.replace(":", "")
        if not _SHA256_RE.match(value):
            raise ASEIntelligenceError("Invalid SHA-256 digest: %s" % indicator[:80])
        return value

    def classify(self, indicator):
        """Best-effort type inference used by import paths."""
        value = str(indicator).strip().lower()
        try:
            ipaddress.ip_address(value)
            return "ip"
        except ValueError:
            pass
        if _SHA256_RE.match(value.replace(":", "")):
            return "sha256"
        if _DOMAIN_RE.match(value.rstrip(".")):
            return "domain"
        raise ASEIntelligenceError("Indicator does not match any supported type")

    # ------------------------------------------------------------- mutation
    def add_indicator(self, indicator, indicator_type=None, source="local", description="",
                      confidence=50, ttl_days=None):
        if indicator_type is None:
            indicator_type = self.classify(indicator)
        key = self.normalize(indicator, indicator_type)
        confidence = max(0, min(int(confidence), 100))
        if len(self.indicators) >= self.max_indicators and key not in self.indicators:
            raise ASEIntelligenceError("Indicator store is at its configured capacity")

        ttl = self.ttl_days if ttl_days is None else int(ttl_days)
        expires_at = None
        if ttl > 0:
            expires_at = (_utc_now() + timedelta(days=ttl)).isoformat()

        record = {"type": indicator_type, "source": str(source)[:128],
                  "confidence": confidence, "expires_at": expires_at}
        self.indicators[key] = record
        self._index.add(key)
        if self.database is not None and getattr(self.database, "ready", False):
            self.database.add_indicator(key, indicator_type, source, description,
                                        confidence=confidence, expires_at=expires_at)
        if self.event_bus is not None:
            try:
                self.event_bus.publish("intelligence.indicator_added",
                                       {"indicator": key, "type": indicator_type, "source": source})
            except Exception:
                pass
        return {"indicator": key, "type": indicator_type, "source": record["source"],
                "confidence": confidence, "expires_at": expires_at}

    def remove_indicator(self, indicator):
        key = str(indicator).strip().lower()
        existed = key in self.indicators
        self.indicators.pop(key, None)
        self._index.discard(key)
        if self.database is not None and getattr(self.database, "ready", False):
            self.database.delete_indicator(key)
        return existed

    def check_indicator(self, indicator):
        key = str(indicator).strip().lower()
        record = self.indicators.get(key)
        result = {"found": bool(record), "indicator": key}
        if record:
            expires_at = record.get("expires_at")
            if expires_at and expires_at < _utc_now().isoformat():
                self.indicators.pop(key, None)
                self._index.discard(key)
                result = {"found": False, "indicator": key, "expired": True}
            else:
                result.update({"type": record["type"], "source": record["source"],
                               "confidence": record.get("confidence", 50)})
        if self.event_bus is not None:
            try:
                self.event_bus.publish("intelligence.checked", result)
            except Exception:
                pass
        return result

    # ------------------------------------------------------------- bulk I/O
    def list_indicators(self, indicator_type=None):
        rows = []
        for key, record in sorted(self.indicators.items()):
            if indicator_type and record["type"] != indicator_type:
                continue
            rows.append({"indicator": key, **record})
        return rows

    def export_indicators(self, path):
        """Write a plain JSON export for the operator to inspect."""
        payload = {"exported_at": _utc_now().isoformat(),
                   "count": len(self.indicators),
                   "indicators": self.list_indicators()}
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, indent=2), "utf-8")
        return {"path": str(target), "count": payload["count"]}

    def import_indicators(self, path, source="local_import", require_signed=False):
        """Import plain JSON indicators. Refused when a signature is required."""
        if require_signed:
            raise ASEIntelligenceError(
                "Unsigned indicator import is disabled; use the signed feed importer")
        data = json.loads(Path(path).read_text("utf-8"))
        items = data.get("indicators", data) if isinstance(data, dict) else data
        if not isinstance(items, list):
            raise ASEIntelligenceError("Import file must contain an indicator list")
        added, rejected = 0, []
        for item in items[:self.max_indicators]:
            try:
                if isinstance(item, dict):
                    self.add_indicator(item.get("indicator"), item.get("type"),
                                       item.get("source", source),
                                       item.get("description", ""),
                                       item.get("confidence", 50))
                else:
                    self.add_indicator(item, None, source)
                added += 1
            except ASEIntelligenceError as exc:
                rejected.append(str(exc)[:120])
        return {"added": added, "rejected": len(rejected), "errors": rejected[:20]}

    def purge_expired(self):
        if self.database is not None and getattr(self.database, "ready", False):
            removed = self.database.purge_expired_indicators()
            self.reload()
            return removed
        now = _utc_now().isoformat()
        stale = [key for key, record in self.indicators.items()
                 if record.get("expires_at") and record["expires_at"] < now]
        for key in stale:
            self.indicators.pop(key, None)
            self._index.discard(key)
        return len(stale)

    def statistics(self):
        by_type = {}
        for record in self.indicators.values():
            by_type[record["type"]] = by_type.get(record["type"], 0) + 1
        sources = {}
        for record in self.indicators.values():
            sources[record["source"]] = sources.get(record["source"], 0) + 1
        return {"total": len(self.indicators), "by_type": by_type, "by_source": sources}
