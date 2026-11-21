"""Interval scheduler with error backoff, overlap protection and history."""
from __future__ import annotations

import threading
import time
from datetime import datetime, timezone


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


class ASEScheduler:
    def __init__(self, event_bus, database=None, tick_seconds=1.0):
        self.event_bus = event_bus
        self.database = database
        self.tasks = {}
        self.running = False
        self.thread = None
        self.lock = threading.RLock()
        self.tick_seconds = max(0.05, float(tick_seconds))
        self._stop = threading.Event()

    def register(self, name, callback, interval, run_immediately=False):
        if not callable(callback):
            raise ValueError("Callback must be callable")
        interval = float(interval)
        if interval < 1:
            raise ValueError("Interval must be at least 1 second")
        with self.lock:
            if name in self.tasks:
                raise ValueError("Task already exists: %s" % name)
            self.tasks[name] = {
                "callback": callback,
                "interval": interval,
                "last_run": None,
                "runs": 0,
                "failures": 0,
                "backoff_until": 0.0,
                "status": "scheduled" if self.running else "registered",
                "enabled": True,
                "last_error": None,
                "last_duration_ms": None,
                "run_immediately": bool(run_immediately),
                "history": [],
            }
        return True

    def remove(self, name):
        with self.lock:
            return self.tasks.pop(name, None) is not None

    def enable(self, name):
        with self.lock:
            task = self.tasks.get(name)
            if task is None:
                return False
            task["enabled"] = True
            task["backoff_until"] = 0.0
            task["status"] = "scheduled" if self.running else "registered"
            return True

    def disable(self, name):
        with self.lock:
            task = self.tasks.get(name)
            if task is None:
                return False
            task["enabled"] = False
            task["status"] = "disabled"
            return True

    def run_now(self, name):
        """Execute a task immediately, outside the schedule."""
        with self.lock:
            task = self.tasks.get(name)
            if task is None:
                return False
            if task["status"] == "running_task":
                return False
            task["status"] = "running_task"
        try:
            self._execute(name, task, time.monotonic())
        finally:
            with self.lock:
                if self.tasks.get(name) is task:
                    task["status"] = "scheduled" if (task["enabled"] and self.running) else (
                        "registered" if task["enabled"] else "disabled")
        return True

    def start(self):
        with self.lock:
            if self.running:
                return
            self.running = True
            self._stop.clear()
            for task in self.tasks.values():
                if task["enabled"]:
                    task["status"] = "scheduled"
                    if task["run_immediately"]:
                        task["last_run"] = None
            self.thread = threading.Thread(target=self._run, name="ase-scheduler", daemon=True)
            self.thread.start()

    def _run(self):
        while not self._stop.is_set():
            now = time.monotonic()
            with self.lock:
                tasks = list(self.tasks.items())
            for name, task in tasks:
                if self._stop.is_set():
                    break
                with self.lock:
                    if self.tasks.get(name) is not task:
                        continue
                    if not task["enabled"] or task["status"] == "running_task":
                        continue
                    due = task["last_run"] is None or now - task["last_run"] >= task["interval"]
                    if due and now >= task["backoff_until"]:
                        task["status"] = "running_task"
                    else:
                        continue
                try:
                    self._execute(name, task, now)
                finally:
                    with self.lock:
                        if self.tasks.get(name) is task:
                            task["status"] = "scheduled" if task["enabled"] else "disabled"
            self._stop.wait(self.tick_seconds)

    def _execute(self, name, task, now):
        started_at = _now_iso()
        began = time.monotonic()
        error = None
        try:
            task["callback"]()
        except Exception as exc:
            error = "%s: %s" % (type(exc).__name__, str(exc)[:300])
        duration_ms = round((time.monotonic() - began) * 1000, 2)
        finished_at = _now_iso()
        with self.lock:
            if self.tasks.get(name) is not task:
                return
            task["last_run"] = now
            task["runs"] += 1
            task["last_error"] = error
            task["last_duration_ms"] = duration_ms
            if error is None:
                task["failures"] = 0
                task["backoff_until"] = 0.0
            else:
                task["failures"] += 1
                # Exponential backoff capped at ten intervals.
                delay = min(task["interval"] * (2 ** min(task["failures"], 4)), task["interval"] * 10)
                task["backoff_until"] = time.monotonic() + delay
            record = {"started_at": started_at, "finished_at": finished_at,
                      "status": "failed" if error else "completed", "error": error}
            task["history"].append(record)
            task["history"] = task["history"][-20:]

        if self.database is not None and getattr(self.database, "ready", False):
            try:
                self.database.save_scheduler_run(name, started_at, finished_at,
                                                 "failed" if error else "completed", error)
            except Exception:
                pass

        event_name = "scheduler.task_completed" if error is None else "scheduler.task_failed"
        try:
            self.event_bus.publish(event_name, {
                "task": name, "timestamp": finished_at, "error": error, "duration_ms": duration_ms})
        except Exception:
            pass

    def get_history(self, task_name=None, limit=20):
        if self.database is not None and getattr(self.database, "ready", False):
            try:
                return self.database.get_scheduler_history(task_name, limit)
            except Exception:
                pass
        with self.lock:
            if task_name:
                task = self.tasks.get(task_name)
                return list(reversed(task["history"][-limit:])) if task else []
            history = []
            for name, task in self.tasks.items():
                for record in task["history"]:
                    history.append({"task_name": name, **record})
            return history[-limit:]

    def get_status(self):
        with self.lock:
            return {
                "running": self.running,
                "tasks": {
                    name: {
                        "interval": task["interval"],
                        "runs": task["runs"],
                        "failures": task["failures"],
                        "status": task["status"],
                        "enabled": task["enabled"],
                        "last_error": task["last_error"],
                        "last_duration_ms": task["last_duration_ms"],
                    }
                    for name, task in self.tasks.items()
                },
            }

    def stop(self):
        with self.lock:
            if not self.running:
                return
            self.running = False
            self._stop.set()
            thread = self.thread
        if thread and thread.is_alive():
            thread.join(timeout=5)
        with self.lock:
            self.thread = None
            for task in self.tasks.values():
                task["status"] = "registered" if task["enabled"] else "disabled"
