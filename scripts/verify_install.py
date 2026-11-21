#!/usr/bin/env python3
"""AKVORIA ASE user acceptance test.

Run this after extracting the archive to confirm the build works on your
machine. It creates a temporary directory, exercises the documented workflow,
and removes everything it created.

    python3 verify_install.py

Exit code 0 means every check passed.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
def _engine_root():
    """The script sits at the archive root in the user kit and in scripts/ here."""
    here = Path(__file__).resolve().parent
    for candidate in (here, here.parent):
        if (candidate / "main.py").exists():
            return candidate
    raise SystemExit("main.py not found next to this script.")


ROOT = _engine_root()
MAIN = ROOT / "main.py"

results = []


def check(name, condition, detail=""):
    results.append((name, bool(condition), detail))
    print("  [%s] %s%s" % ("PASS" if condition else "FAIL", name,
                           (" — " + detail) if detail and not condition else ""))
    return bool(condition)


def run(argv):
    process = subprocess.run([sys.executable] + argv, cwd=str(ROOT),
                             capture_output=True, text=True, timeout=300)
    return process


def main():
    print("AKVORIA SECURITY ENGINE — user acceptance test\n")

    python_ok = sys.version_info >= (3, 10)
    check("Python 3.10 or newer", python_ok, sys.version.split()[0])
    if not python_ok:
        return 1

    work = Path(tempfile.mkdtemp(prefix="ase-uat-"))
    try:
        (work / "config").mkdir()
        (work / "config" / "ase.json").write_text(
            json.dumps({"api": {"port": 18999}}), "utf-8")

        sample = work / "sample.com"
        sample.write_text(EICAR, encoding="utf-8")
        (work / "notes.txt").write_text("ordinary document", encoding="utf-8")

        print("\n1. version and self-test")
        version = run([str(MAIN), "--version"])
        check("--version exits 0", version.returncode == 0, version.stderr[:120])
        check("--version reports 0.1.0 BETA", "0.1.0 BETA" in version.stdout + version.stderr,
              version.stdout[:120])

        selftest = run([str(MAIN), "--config",
                        str(work / "config" / "ase.json"), "self-test"])
        check("self-test exits 0", selftest.returncode == 0, selftest.stderr[:200])
        try:
            payload = json.loads(selftest.stdout)
            check("self-test reports ok", payload.get("status") == "ok")
        except json.JSONDecodeError:
            check("self-test emits JSON", False, selftest.stdout[:120])

        print("\n2. scanning")
        scan = run([str(MAIN), "--config",
                    str(work / "config" / "ase.json"), "scan", str(work),
                    "--summary"])
        check("scan exits 0", scan.returncode == 0, scan.stderr[:200])
        try:
            report = json.loads(scan.stdout)
            check("scan detected the EICAR sample", report.get("detections") == 1,
                  str(report.get("detections")))
            counts = report.get("verdict_counts", {})
            check("verdict vocabulary is the documented five",
                  set(counts) == {"no_known_indicators", "suspicious",
                                  "malicious_indicator", "scan_incomplete",
                                  "scan_error"}, str(sorted(counts)))
            check("no 'clean' verdict is reported", "clean" not in counts)
            check("scan left the sample in place", sample.exists())
        except json.JSONDecodeError:
            check("scan emits JSON", False, scan.stdout[:120])

        print("\n3. quarantine and restore")
        quarantine = run([str(MAIN), "--config",
                          str(work / "config" / "ase.json"),
                          "quarantine", "add", str(sample)])
        check("quarantine exits 0", quarantine.returncode == 0,
              quarantine.stderr[:200])
        check("sample removed from its original location", not sample.exists())
        qid = None
        try:
            qid = json.loads(quarantine.stdout).get("quarantine_id")
        except json.JSONDecodeError:
            pass
        check("quarantine id returned", bool(qid))

        if qid:
            restore = run([str(MAIN), "--config",
                           str(work / "config" / "ase.json"),
                           "restore", qid])
            check("restore exits 0", restore.returncode == 0, restore.stderr[:200])
            check("sample restored byte-for-byte", sample.exists() and
                  sample.read_text("utf-8") == EICAR)

        print("\n4. history and threat intelligence")
        history = run([str(MAIN), "--config",
                       str(work / "config" / "ase.json"), "history",
                       "--limit", "5"])
        check("history exits 0", history.returncode == 0, history.stderr[:200])
        try:
            check("history has at least one scan",
                  json.loads(history.stdout).get("total", 0) >= 1)
        except json.JSONDecodeError:
            check("history emits JSON", False, history.stdout[:120])

        add = run([str(MAIN), "--config",
                   str(work / "config" / "ase.json"), "intelligence", "add",
                   "198.51.100.9", "--type", "ip"])
        check("valid IP indicator accepted", add.returncode == 0, add.stderr[:200])

        bad = run([str(MAIN), "--config",
                   str(work / "config" / "ase.json"), "intelligence", "add",
                   "999.1.1.1", "--type", "ip"])
        check("invalid IP indicator rejected", bad.returncode == 2,
              "exit %d" % bad.returncode)
        check("rejection names the invalid value",
              "999.1.1.1" in bad.stdout + bad.stderr)

        print("\n5. monitoring reports its real scope")
        monitor = run([str(MAIN), "--config",
                       str(work / "config" / "ase.json"), "monitoring",
                       "show"])
        check("monitoring exits 0", monitor.returncode == 0, monitor.stderr[:200])
        try:
            status = json.loads(monitor.stdout)
            check("scope is configured_directories_only",
                  status.get("scope") == "configured_directories_only",
                  str(status.get("scope")))
        except json.JSONDecodeError:
            check("monitoring emits JSON", False, monitor.stdout[:120])

        print("\n6. configuration safety")
        reject = run([str(MAIN), "--config",
                      str(work / "config" / "ase.json"), "config", "set",
                      "api.host=0.0.0.0"])
        check("non-loopback API host rejected", reject.returncode == 2,
              "exit %d" % reject.returncode)
        check("rejection explains the loopback rule",
              "loopback" in (reject.stdout + reject.stderr).lower())
        on_disk = (work / "config" / "ase.json").read_text("utf-8")
        check("rejected change was not written to disk", "0.0.0.0" not in on_disk)
        check("config file is still valid JSON",
              isinstance(json.loads(on_disk), dict))

        print("\n7. diagnostics and report")
        diag = run([str(MAIN), "--config",
                    str(work / "config" / "ase.json"), "diagnostics"])
        check("diagnostics exits 0", diag.returncode == 0, diag.stderr[:200])
        check("diagnostics states its limitations", "limitations" in diag.stdout)
        check("diagnostics leaks no api_key",
              "api_key" not in diag.stdout.lower())

        report_path = work / "report.json"
        report = run([str(MAIN), "--config",
                      str(work / "config" / "ase.json"), "report",
                      "--output", str(report_path)])
        check("report export exits 0", report.returncode == 0, report.stderr[:200])
        check("report file written", report_path.exists())
    finally:
        shutil.rmtree(work, ignore_errors=True)

    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print("\n" + "=" * 58)
    print("%d / %d checks passed" % (passed, total))
    if passed != total:
        print("\nFailures:")
        for name, ok, detail in results:
            if not ok:
                print("  - %s %s" % (name, detail))
        return 1
    print("Installation verified. AKVORIA ASE is working on this machine.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
