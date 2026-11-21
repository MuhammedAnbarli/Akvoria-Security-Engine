#!/usr/bin/env python3
"""Watch one directory for a short period and print every detected change."""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.event_bus import EventBus
from modules.antivirus import ASEAntivirus
from modules.realtime import ASERealtimeMonitor


def main(directory, seconds=15):
    av = ASEAntivirus("storage/antivirus")
    av.start()
    bus = EventBus()
    bus.subscribe("realtime.file_changed", lambda d: print("CHANGED", d.get("file")))
    bus.subscribe("realtime.file_deleted", lambda d: print("DELETED", d.get("file")))
    bus.subscribe("antivirus.detection", lambda d: print("DETECTION", d.get("file")))

    monitor = ASERealtimeMonitor(av, bus, interval=1)
    roots = monitor.configure([directory])
    if not roots:
        print("Not a readable directory: %s" % directory)
        return 2

    monitor.start()
    print("Watching %s (mode=%s) for %d seconds..."
          % (roots, monitor.get_status()["mode"], seconds))
    try:
        time.sleep(seconds)
    finally:
        monitor.stop()
        av.stop()
    status = monitor.get_status()
    print("Cycles: %d, events: %d, scans: %d"
          % (status["total_cycles"], status["total_events"], status["total_scans"]))
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: monitor_directory.py <directory> [seconds]")
        sys.exit(2)
    sys.exit(main(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 15))
