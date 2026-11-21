#!/usr/bin/env python3
"""Scan a directory and write a structured JSON report."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.antivirus import ASEAntivirus


def main(target):
    av = ASEAntivirus("storage/antivirus")
    av.start()
    try:
        report = av.scan_path(target)
    finally:
        av.stop()

    print("Verdict counts:")
    for verdict, count in report["verdict_counts"].items():
        print("  %-22s %d" % (verdict, count))

    for detection in report["detection_details"]:
        print("\n%s" % detection["file"])
        print("  status     : %s" % detection["status"])
        print("  risk score : %d" % detection["risk_score"])
        for reason in detection["reasons"]:
            print("  reason     : %s" % reason)

    out = Path("storage/reports/scan-report.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), "utf-8")
    print("\nReport written to %s" % out)
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: scan_and_report.py <directory>")
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
