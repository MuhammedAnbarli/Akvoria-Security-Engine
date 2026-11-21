"""Module registry with declared dependencies and ordered lifecycle."""
from __future__ import annotations

from threading import RLock

from core.exceptions import ASEModuleError


class ModuleManager:
    def __init__(self):
        self.modules = {}
        self._lock = RLock()

    def register(self, name, module, dependencies=None):
        with self._lock:
            if name in self.modules:
                raise ASEModuleError("Module already registered: %s" % name)
            if not callable(getattr(module, "start", None)):
                raise ASEModuleError("Module must implement start(): %s" % name)
            if not callable(getattr(module, "stop", None)):
                raise ASEModuleError("Module must implement stop(): %s" % name)
            self.modules[name] = {
                "instance": module,
                "status": "registered",
                "dependencies": tuple(dependencies or ()),
                "last_error": None,
            }

    def _order(self):
        """Topologically order modules so dependencies start first."""
        ordered, visiting, visited = [], set(), set()

        def visit(name):
            if name in visited:
                return
            if name in visiting:
                raise ASEModuleError("Circular module dependency at %s" % name)
            entry = self.modules.get(name)
            if entry is None:
                raise ASEModuleError("Module not found: %s" % name)
            visiting.add(name)
            for dependency in entry["dependencies"]:
                visit(dependency)
            visiting.discard(name)
            visited.add(name)
            ordered.append(name)

        for name in list(self.modules):
            visit(name)
        return ordered

    def start_all(self):
        """Start every module, isolating failures so one bad module cannot abort the rest."""
        started, failures = [], {}
        try:
            order = self._order()
        except ASEModuleError as exc:
            failures["_ordering"] = str(exc)
            order = list(self.modules)
        for name in order:
            try:
                self.start(name)
                if self.modules[name]["status"] == "running":
                    started.append(name)
            except ASEModuleError as exc:
                failures[name] = str(exc)
        return {"started": started, "failed": failures}

    def stop_all(self):
        """Stop every running module, ignoring dependency-ordering problems."""
        stopped = []
        try:
            order = self._order()
        except ASEModuleError:
            order = list(self.modules)
        for name in reversed(order):
            try:
                if self.modules[name]["status"] == "running":
                    self.stop(name)
                    stopped.append(name)
            except ASEModuleError:
                continue
        return stopped

    def start(self, name):
        with self._lock:
            if name not in self.modules:
                raise ASEModuleError("Module not found: %s" % name)
            entry = self.modules[name]
            if entry["status"] == "running":
                return
            for dependency in entry["dependencies"]:
                dependency_entry = self.modules.get(dependency)
                if dependency_entry is None or dependency_entry["status"] != "running":
                    raise ASEModuleError(
                        "Dependency not running for %s: %s" % (name, dependency))
            instance = entry["instance"]
        try:
            outcome = instance.start()
        except Exception as error:
            with self._lock:
                entry["status"] = "failed"
                entry["last_error"] = str(error)
            raise ASEModuleError("Module start failed: %s" % name) from error
        with self._lock:
            # A module returning False explicitly reports it is idle, not running.
            entry["status"] = "idle" if outcome is False else "running"
            entry["last_error"] = None

    def stop(self, name):
        with self._lock:
            if name not in self.modules:
                raise ASEModuleError("Module not found: %s" % name)
            entry = self.modules[name]
            if entry["status"] != "running":
                return
            instance = entry["instance"]
        try:
            instance.stop()
        except Exception as error:
            with self._lock:
                entry["status"] = "failed"
                entry["last_error"] = str(error)
            raise ASEModuleError("Module stop failed: %s" % name) from error
        with self._lock:
            entry["status"] = "registered"

    def get(self, name):
        entry = self.modules.get(name)
        return entry["instance"] if entry else None

    def get_status(self):
        with self._lock:
            return {name: entry["status"] for name, entry in self.modules.items()}

    def get_details(self):
        with self._lock:
            return {
                name: {
                    "status": entry["status"],
                    "dependencies": list(entry["dependencies"]),
                    "last_error": entry["last_error"],
                }
                for name, entry in self.modules.items()
            }
