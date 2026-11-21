"""Thread-safe publish/subscribe bus with failure isolation.

A failing subscriber never prevents the remaining subscribers from receiving
the event; failures are recorded for diagnostics instead.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from threading import RLock

logger = logging.getLogger("ASE.EventBus")


class EventBus:
    def __init__(self, history_size=200):
        self._subscribers = defaultdict(list)
        self._lock = RLock()
        self._history = []
        self._history_size = max(1, int(history_size))
        self.last_errors = []
        self.published = 0

    def subscribe(self, event_type, callback):
        if not callable(callback):
            raise TypeError("Subscriber must be callable")
        with self._lock:
            if callback not in self._subscribers[event_type]:
                self._subscribers[event_type].append(callback)
        return callback

    def unsubscribe(self, event_type, callback):
        with self._lock:
            if callback in self._subscribers.get(event_type, ()):
                self._subscribers[event_type].remove(callback)
                return True
        return False

    def publish(self, event_type, data=None):
        with self._lock:
            callbacks = list(self._subscribers.get(event_type, ()))
            self.published += 1
            self._history.append({"event_type": event_type, "data": data})
            if len(self._history) > self._history_size:
                del self._history[: len(self._history) - self._history_size]
        delivered = 0
        errors = []
        for callback in callbacks:
            try:
                callback(data)
                delivered += 1
            except Exception as exc:
                errors.append({"event_type": event_type, "error": "%s: %s" % (type(exc).__name__, str(exc)[:300])})
                logger.exception("Event subscriber failed for %s", event_type)
        if errors:
            self.last_errors = (self.last_errors + errors)[-100:]
        return {"delivered": delivered, "errors": errors}

    def subscriber_count(self, event_type):
        with self._lock:
            return len(self._subscribers.get(event_type, ()))

    def get_history(self, limit=20):
        with self._lock:
            return list(self._history)[-max(1, int(limit)):]
