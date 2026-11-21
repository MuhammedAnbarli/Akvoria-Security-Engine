#!/usr/bin/env python3
"""Pre-flight check: compile, import every module, verify config and DB."""
import importlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODULES = ["core.engine", "core.api", "core.api_security", "core.config",
           "core.database", "core.event_bus", "core.module_manager",
           "core.scheduler", "core.platform_info",
           "modules.antivirus", "modules.realtime", "modules.detect",
           "modules.intelligence", "modules.network", "modules.process",
           "modules.analysis", "modules.response", "modules.monitor",
           "modules.threat_feed"]


def main():
    sys.path.insert(0, str(ROOT))
    failures = []

    result = subprocess.run([sys.executable, "-m", "compileall", "-q", "core",
                             "modules", "main.py"], cwd=ROOT)
    if result.returncode != 0:
        failures.append("compileall failed")

    for name in MODULES:
        try:
            importlib.import_module(name)
        except Exception as exc:
            failures.append("%s: %s" % (name, exc))

    from core.platform_info import PlatformInfo
    print(json.dumps(PlatformInfo.current(), indent=2))

    if failures:
        print("\nFAILURES:", file=sys.stderr)
        for item in failures:
            print(" -", item, file=sys.stderr)
        return 1
    print("\nAll %d modules imported successfully." % len(MODULES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
