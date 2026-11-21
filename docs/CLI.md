# CLI Reference

All commands print JSON so output can be piped into `jq` or a script.

```
python3 main.py [--config PATH] <command> [options]
python3 main.py --version
```

## Engine control

### `start`

Runs the engine in the foreground until `CTRL+C`. Writes `storage/ase.pid` so
`stop` can find it.

```bash
python3 main.py start
```

```
AKVORIA SECURITY ENGINE 0.1.0 BETA is running.
Monitoring scope: configured directories only (/home/user/Downloads).
API: http://127.0.0.1:8765 (loopback only)
Press CTRL+C to stop.
```

### `stop`

Signals the PID recorded in `storage/ase.pid`. Exits `1` when no engine is
running.

```bash
python3 main.py stop
```

### `status`

Full status: modules, monitor, scheduler, analysis, response, network, process,
intelligence, antivirus, realtime, database, API. Includes
`protection_scope: "configured_directories_only"`.

```bash
python3 main.py status
```

### `health`

Per-subsystem health with an overall verdict: `healthy`,
`healthy_with_unsupported_features`, `degraded` or `stopped`. Exit code `1`
when the overall state is degraded.

```bash
python3 main.py health
```

### `self-test`

Exercises each local component without scanning user files or touching the
network: database, antivirus, intelligence, network, process, realtime, config
and event bus.

```bash
python3 main.py self-test
```

## Scanning

### `scan PATH...`

```bash
python3 main.py scan ~/Downloads                  # custom scan
python3 main.py scan ~/Downloads --summary        # counts only
python3 main.py scan ~/Downloads --output r.json  # full report to a file
python3 main.py scan --quick                      # well-known user folders
python3 main.py scan --full                       # home directory
python3 main.py scan --full --path /srv /var      # explicit roots
```

Summary output:

```json
{
  "target": "/home/user/Downloads",
  "scan_type": "custom",
  "status": "completed",
  "total": 2,
  "scanned": 2,
  "detections": 1,
  "errors": 0,
  "skipped": 0,
  "verdict_counts": {
    "no_known_indicators": 1,
    "suspicious": 0,
    "malicious_indicator": 1,
    "scan_incomplete": 0,
    "scan_error": 0
  },
  "detection_details": [
    {"file": ".../test.com", "status": "malicious_indicator",
     "risk_score": 90, "reasons": ["Harmless EICAR antivirus test pattern matched."]}
  ],
  "scan_id": 1,
  "duration_seconds": 0.001
}
```

### `history`

```bash
python3 main.py history --limit 20
```

Returns `statistics` (totals, counts by type and by verdict, last scan time) and
the matching scan rows.

## Quarantine

### `quarantine list`

```bash
python3 main.py quarantine list
```

### `quarantine add PATH`

Moves a file **only** if it carries a detection. The CLI passes
`authorized=True` because the operator invoked the command explicitly.

```bash
python3 main.py quarantine add ~/Downloads/suspect.exe
```

```json
{
  "quarantine_id": "275a021bbfb6489e-1795184494048",
  "original_path": "/home/user/Downloads/suspect.exe",
  "sha256": "275a021bbfb6489e...",
  "verdict": "malicious_indicator",
  "status": "quarantined"
}
```

### `restore ID`

Verifies SHA-256 against the stored metadata before writing anything back.
Refuses when the original path is occupied.

```bash
python3 main.py restore 275a021bbfb6489e-1795184494048
```

## Alerts

```bash
python3 main.py alerts --limit 20
python3 main.py alerts --severity critical
python3 main.py alerts --status open
python3 main.py alerts --acknowledge 4
```

Every alert carries `reasons`, `recommendation`, `severity`, `risk_score`,
`status` and an `incident_id` for grouping.

## Threat intelligence

```bash
python3 main.py intelligence list
python3 main.py intelligence add 198.51.100.7 --type ip --confidence 90
python3 main.py intelligence add example.com --type domain --description "campaign"
python3 main.py intelligence check 198.51.100.7
python3 main.py intelligence remove 198.51.100.7
python3 main.py intelligence export --file indicators.json
python3 main.py intelligence import --file indicators.json
```

Signed feed import requires the publisher's Ed25519 public key in hex:

```bash
python3 main.py intelligence feed --file feed.json --public-key <64-hex-chars>
```

Unsigned, tampered, replayed or rolled-back feeds are refused.

## Monitoring

```bash
python3 main.py monitoring show
python3 main.py monitoring set ~/Downloads ~/Desktop
python3 main.py monitoring clear
```

`show` reports the scope, the resolved roots and the active mode:

```json
{
  "scope": "configured_directories_only",
  "mode": "polling",
  "roots": ["/home/user/Downloads"],
  "running": true,
  "configured": ["/home/user/Downloads"]
}
```

`mode` is `native`, `polling`, `idle_no_paths` (running with no directories) or
`stopped` (the engine is not running). `set` persists the resolved paths to
`config/ase.json` and restarts monitoring when the engine is running.

## Diagnostics and reporting

```bash
python3 main.py diagnostics
python3 main.py diagnostics --backup
python3 main.py report --output storage/reports/ase-report.json
python3 main.py report --scan-id 3 --output scan-3.json
```

## Configuration

```bash
python3 main.py config show
python3 main.py config validate
python3 main.py config set realtime.interval_seconds=5
python3 main.py config set api.rate_limit_requests=60
```

Values are parsed as JSON when possible, so `true`, `5` and `"text"` all work.
An invalid change exits `2` and leaves the previous file untouched.

## Legacy 1.3 flags

These still work and map onto the subcommands:

```bash
python3 main.py --status
python3 main.py --self-test
python3 main.py --scan ~/Downloads
python3 main.py --quarantine ~/Downloads/suspect.exe
python3 main.py --restore <id>
python3 main.py --watch ~/Downloads
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Command completed but the state is not healthy (or nothing to stop) |
| 2 | Invalid input, invalid indicator, or rejected configuration |
| 130 | Interrupted with `CTRL+C` |
