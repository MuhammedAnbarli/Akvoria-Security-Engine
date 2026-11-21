"""AKVORIA Security Engine command-line interface.

Run ``python main.py --help`` for the command list. Every command is also
available as a subcommand so scripts can rely on stable names.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from pathlib import Path

from core.config import ASEConfig
from core.engine import ASEEngine
from core.exceptions import ASEError

VERSION = "0.1.0 BETA"


def _print(payload):
    print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))


def _engine(config_path="config/ase.json"):
    return ASEEngine(config_path=config_path)


def _pid_file():
    return Path("storage/ase.pid")


def _write_pid(pid):
    path = _pid_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(pid), "utf-8")


def _read_pid():
    path = _pid_file()
    if not path.exists():
        return None
    try:
        return int(path.read_text("utf-8").strip())
    except (OSError, ValueError):
        return None


def _clear_pid():
    path = _pid_file()
    if path.exists():
        try:
            path.unlink()
        except OSError:
            pass


def _process_alive(pid):
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


# ---------------------------------------------------------------- commands
def cmd_status(args):
    engine = _engine(args.config)
    engine.database.start()
    try:
        _print(engine.get_status())
        return 0
    finally:
        engine.database.stop()


def cmd_health(args):
    engine = _engine(args.config)
    engine.database.start()
    try:
        result = engine.health()
        _print(result)
        return 0 if result["overall"] in (
            "healthy", "healthy_with_unsupported_features", "stopped") else 1
    finally:
        engine.database.stop()


def cmd_self_test(args):
    """Exercise each subsystem without touching the network or user files."""
    checks = {}
    engine = _engine(args.config)
    try:
        engine.database.start()
        checks["database"] = {"ok": engine.database.ready,
                              "schema_version": engine.database.schema_version}
        engine.antivirus.start()
        checks["antivirus"] = {"ok": engine.antivirus.started,
                               "limits": engine.antivirus.get_status()["limits"]}
        engine.intelligence.start()
        checks["intelligence"] = {"ok": True, "indicators": len(engine.intelligence.indicators)}
        checks["network"] = {"ok": True, "supported": engine.network.is_supported()}
        checks["process"] = {"ok": True, "supported": engine.process.is_supported()}
        checks["realtime"] = {"ok": True, **engine.realtime.health()}
        checks["config"] = {"ok": True, "version": engine.settings["engine"]["version"]}
        bus_result = engine.event_bus.publish("self_test", {"ok": True})
        checks["event_bus"] = {"ok": bus_result["errors"] == []}
        ok = all(item.get("ok") for item in checks.values())
        _print({"status": "ok" if ok else "degraded", "checks": checks})
        return 0 if ok else 1
    finally:
        engine.antivirus.stop()
        if engine.database.ready:
            engine.database.stop()


def cmd_scan(args):
    engine = _engine(args.config)
    engine.database.start()
    engine.antivirus.start()
    try:
        if args.quick:
            result = engine.antivirus.quick_scan()
        elif args.full:
            result = engine.antivirus.full_scan(roots=args.path or None)
        else:
            if not args.path:
                raise SystemExit("A path is required for a custom scan (or use --quick/--full)")
            result = engine.antivirus.scan_path(args.path[0], scan_type="custom")
        if args.output:
            target = Path(args.output)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(result, indent=2, ensure_ascii=False, default=str), "utf-8")
            summary = {key: value for key, value in result.items() if key != "results"}
            summary["report_path"] = str(target)
            _print(summary)
        elif args.summary:
            _print({key: value for key, value in result.items() if key != "results"})
        else:
            _print(result)
        return 0
    finally:
        engine.antivirus.stop()
        engine.database.stop()


def cmd_history(args):
    engine = _engine(args.config)
    engine.database.start()
    try:
        scans = engine.database.get_scans(limit=args.limit)
        statistics = engine.database.get_scan_statistics()
        _print({"total": len(scans), "statistics": statistics, "scans": scans})
        return 0
    finally:
        engine.database.stop()


def cmd_quarantine(args):
    engine = _engine(args.config)
    engine.database.start()
    engine.antivirus.start()
    try:
        if args.action == "list":
            _print({"items": engine.antivirus.list_quarantine()})
        elif args.action == "add":
            if not args.path:
                raise SystemExit("A path is required to quarantine a file")
            _print(engine.antivirus.quarantine_file(args.path[0], authorized=True,
                                                    reason="cli_request"))
        return 0
    finally:
        engine.antivirus.stop()
        engine.database.stop()


def cmd_restore(args):
    engine = _engine(args.config)
    engine.database.start()
    engine.antivirus.start()
    try:
        _print(engine.antivirus.restore_file(args.quarantine_id))
        return 0
    finally:
        engine.antivirus.stop()
        engine.database.stop()


def cmd_alerts(args):
    engine = _engine(args.config)
    engine.database.start()
    try:
        if args.acknowledge is not None:
            acknowledged = engine.response.acknowledge(args.acknowledge, actor="cli")
            _print({"alert_id": args.acknowledge,
                    "status": "acknowledged" if acknowledged else "not_found"})
            return 0 if acknowledged else 1
        alerts = engine.response.get_alerts(limit=args.limit, status=args.status,
                                            severity=args.severity)
        _print({"total": len(alerts), "alerts": alerts,
                "incidents": engine.response.get_incidents(limit=20)})
        return 0
    finally:
        engine.database.stop()


def cmd_intelligence(args):
    engine = _engine(args.config)
    engine.database.start()
    try:
        engine.intelligence.start()
        if args.action == "list":
            _print({"statistics": engine.intelligence.statistics(),
                    "indicators": engine.intelligence.list_indicators(args.type)})
        elif args.action == "add":
            if not args.indicator:
                raise SystemExit("An indicator value is required")
            _print(engine.intelligence.add_indicator(
                args.indicator, args.type, args.source, args.description or "",
                confidence=args.confidence))
        elif args.action == "remove":
            if not args.indicator:
                raise SystemExit("An indicator value is required")
            removed = engine.intelligence.remove_indicator(args.indicator)
            _print({"indicator": args.indicator, "removed": removed})
            return 0 if removed else 1
        elif args.action == "export":
            _print(engine.intelligence.export_indicators(
                args.file or "storage/reports/indicators.json"))
        elif args.action == "import":
            if not args.file:
                raise SystemExit("--file is required for import")
            _print(engine.intelligence.import_indicators(args.file))
        elif args.action == "feed":
            if not args.file or not args.public_key:
                raise SystemExit("--file and --public-key are required for signed feed import")
            _print(engine.threat_feed.import_signed(args.file, args.public_key))
        elif args.action == "check":
            if not args.indicator:
                raise SystemExit("An indicator value is required")
            _print(engine.intelligence.check_indicator(args.indicator))
        return 0
    finally:
        engine.database.stop()


def cmd_monitoring(args):
    engine = _engine(args.config)
    if args.action == "show":
        status = engine.realtime.get_status()
        _print({"scope": status["protection_scope"],
                "mode": status["mode"],
                "roots": status["roots"],
                "running": status["running"],
                "configured": engine.settings.get("realtime", {}).get("watch_paths", []),
                "realtime": status,
                "health": engine.realtime.health()})
        return 0
    if args.action == "set":
        if not args.paths:
            raise SystemExit("At least one path is required")
        configured = engine.set_watch_paths(args.paths)
        _print({"watch_paths": configured})
        return 0
    if args.action == "clear":
        configured = engine.set_watch_paths([])
        _print({"watch_paths": configured, "status": "cleared"})
        return 0
    return 0


def cmd_diagnostics(args):
    engine = _engine(args.config)
    engine.database.start()
    try:
        diagnostics = engine.diagnostics()
        if args.backup:
            diagnostics["backup"] = engine.backup_database()
        _print(diagnostics)
        return 0
    finally:
        engine.database.stop()


def cmd_report(args):
    engine = _engine(args.config)
    engine.database.start()
    try:
        _print(engine.export_report(args.output, scan_id=args.scan_id))
        return 0
    finally:
        engine.database.stop()


def cmd_start(args):
    """Run the engine in the foreground until interrupted."""
    engine = _engine(args.config)
    engine.start()
    _write_pid(os.getpid())
    try:
        status = engine.get_status()
        print("\nAKVORIA SECURITY ENGINE %s is running." % status["version"])
        roots = status["realtime"]["roots"]
        print("Monitoring scope: configured directories only (%s)."
              % (", ".join(roots) if roots else "none configured"))
        print("API: http://%s:%s (loopback only)" % (engine.api.host, engine.api.port))
        print("Press CTRL+C to stop.\n")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutdown requested.")
    finally:
        engine.stop()
        _clear_pid()
    return 0


def cmd_stop(args):
    pid = _read_pid()
    if not _process_alive(pid):
        _clear_pid()
        _print({"status": "not_running",
                "detail": "No engine PID file found, or the recorded process is gone."})
        return 1
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as exc:
        _print({"status": "error", "detail": str(exc)[:200]})
        return 1
    for _ in range(50):
        if not _process_alive(pid):
            break
        time.sleep(0.1)
    _clear_pid()
    _print({"status": "stopped", "pid": pid})
    return 0


def cmd_config(args):
    config = ASEConfig(args.config)
    config.load()
    if args.action == "show":
        _print(config.data)
        return 0
    if args.action == "validate":
        config.validate()
        _print({"status": "valid"})
        return 0
    if args.action == "set":
        if not args.pairs:
            raise SystemExit("Provide KEY=VALUE pairs")
        for pair in args.pairs:
            if "=" not in pair:
                raise SystemExit("Expected KEY=VALUE, got: %s" % pair)
            key, value = pair.split("=", 1)
            section, _, field = key.partition(".")
            if not field:
                raise SystemExit("Key must be section.field, got: %s" % key)
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                parsed = value
            config.update(section, {field: parsed})
        _print({"status": "updated"})
        return 0
    return 0


# ---------------------------------------------------------------- parser
def build_parser():
    parser = argparse.ArgumentParser(
        prog="ase",
        description="AKVORIA Security Engine - local defensive security engine.",
        epilog="Every command has a --help page, for example: ase scan --help",
    )
    parser.add_argument("--version", action="version", version="AKVORIA ASE %s" % VERSION)
    parser.add_argument("--config", default="config/ase.json", help="Configuration file path")
    subparsers = parser.add_subparsers(dest="command")

    sub = subparsers.add_parser("start", help="Run the engine in the foreground")
    sub.set_defaults(func=cmd_start)

    sub = subparsers.add_parser("stop", help="Stop a background engine recorded in storage/ase.pid")
    sub.set_defaults(func=cmd_stop)

    sub = subparsers.add_parser("status", help="Print engine status as JSON")
    sub.set_defaults(func=cmd_status)

    sub = subparsers.add_parser("health", help="Run health checks for every subsystem")
    sub.set_defaults(func=cmd_health)

    sub = subparsers.add_parser("self-test", help="Exercise local components without scanning user files")
    sub.set_defaults(func=cmd_self_test)

    sub = subparsers.add_parser("scan", help="Scan a file or directory")
    sub.add_argument("path", nargs="*", help="File or directory to scan")
    sub.add_argument("--quick", action="store_true", help="Scan well-known user folders")
    sub.add_argument("--full", action="store_true", help="Scan the home directory or given paths")
    sub.add_argument("--output", help="Write the full JSON report to this path")
    sub.add_argument("--summary", action="store_true", help="Print summary counts only")
    sub.set_defaults(func=cmd_scan)

    sub = subparsers.add_parser("history", help="Show scan history and statistics")
    sub.add_argument("--limit", type=int, default=20)
    sub.set_defaults(func=cmd_history)

    sub = subparsers.add_parser("quarantine", help="List or add quarantined files")
    sub.add_argument("action", choices=["list", "add"])
    sub.add_argument("path", nargs="*", help="File to quarantine (required for 'add')")
    sub.set_defaults(func=cmd_quarantine)

    sub = subparsers.add_parser("restore", help="Restore a quarantined file by ID")
    sub.add_argument("quarantine_id")
    sub.set_defaults(func=cmd_restore)

    sub = subparsers.add_parser("alerts", help="List, filter or acknowledge alerts")
    sub.add_argument("--limit", type=int, default=50)
    sub.add_argument("--status", choices=["open", "acknowledged"])
    sub.add_argument("--severity", choices=["low", "medium", "high", "critical"])
    sub.add_argument("--acknowledge", type=int, help="Alert ID to acknowledge")
    sub.set_defaults(func=cmd_alerts)

    sub = subparsers.add_parser("intelligence", help="Manage threat intelligence indicators")
    sub.add_argument("action", choices=["list", "add", "remove", "export", "import", "feed", "check"])
    sub.add_argument("indicator", nargs="?", help="Indicator value for add/remove/check")
    sub.add_argument("--type", choices=["ip", "domain", "sha256"])
    sub.add_argument("--source", default="cli")
    sub.add_argument("--description")
    sub.add_argument("--confidence", type=int, default=50)
    sub.add_argument("--file", help="Import/export/feed file path")
    sub.add_argument("--public-key", help="Ed25519 publisher public key (hex) for signed feeds")
    sub.set_defaults(func=cmd_intelligence)

    sub = subparsers.add_parser("monitoring", help="Inspect or change monitored directories")
    sub.add_argument("action", choices=["show", "set", "clear"])
    sub.add_argument("paths", nargs="*")
    sub.set_defaults(func=cmd_monitoring)

    sub = subparsers.add_parser("diagnostics", help="Print a diagnostics bundle")
    sub.add_argument("--backup", action="store_true", help="Also write a database backup")
    sub.set_defaults(func=cmd_diagnostics)

    sub = subparsers.add_parser("report", help="Export a structured JSON report")
    sub.add_argument("--output", default="storage/reports/ase-report.json")
    sub.add_argument("--scan-id", type=int)
    sub.set_defaults(func=cmd_report)

    sub = subparsers.add_parser("config", help="Show, validate or update configuration")
    sub.add_argument("action", choices=["show", "validate", "set"])
    sub.add_argument("pairs", nargs="*", help="section.field=value pairs for 'set'")
    sub.set_defaults(func=cmd_config)

    return parser


LEGACY_FLAGS = ("--status", "--self-test", "--scan", "--quarantine", "--restore", "--watch")


def main(argv=None):
    raw = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    # 1.3 style flag invocations are detected before argparse rejects them.
    if any(item in LEGACY_FLAGS or item.split("=")[0] in LEGACY_FLAGS for item in raw):
        return _legacy_main(parser, raw)
    args = parser.parse_args(raw)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    try:
        return args.func(args) or 0
    except ASEError as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


def _legacy_main(parser, argv=None):
    """Support the 1.3 style flags: --status, --scan PATH, --watch PATH, ..."""
    legacy = argparse.ArgumentParser(add_help=False)
    legacy.add_argument("--status", action="store_true")
    legacy.add_argument("--self-test", dest="self_test", action="store_true")
    legacy.add_argument("--scan")
    legacy.add_argument("--quarantine")
    legacy.add_argument("--restore")
    legacy.add_argument("--watch")
    known, _ = legacy.parse_known_args(argv)

    config = "config/ase.json"
    if known.status:
        return cmd_status(argparse.Namespace(config=config))
    if known.self_test:
        return cmd_self_test(argparse.Namespace(config=config))
    if known.scan:
        return cmd_scan(argparse.Namespace(config=config, path=[known.scan], quick=False,
                                           full=False, output=None, summary=False))
    if known.quarantine:
        return cmd_quarantine(argparse.Namespace(config=config, action="add",
                                                 path=[known.quarantine]))
    if known.restore:
        return cmd_restore(argparse.Namespace(config=config, quarantine_id=known.restore))
    if known.watch:
        engine = _engine(config)
        configured = engine.set_watch_paths([known.watch])
        if not configured:
            raise SystemExit("Watch path must be an existing accessible directory.")
        return cmd_start(argparse.Namespace(config=config))

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
