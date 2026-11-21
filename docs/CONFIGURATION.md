# Configuration Reference

`config/ase.json` is created with safe defaults on first run. Nested sections
are merged with the defaults, so a partial file is valid and unknown keys are
preserved.

Updates are validated, written to a temporary file, then atomically replaced. A
rejected update leaves the previous file untouched.

```bash
python3 main.py config show
python3 main.py config validate
python3 main.py config set realtime.interval_seconds=5
```

## `engine`

| Key | Type | Default | Notes |
|---|---|---|---|
| `name` | string | `"AKVORIA SECURITY ENGINE"` | Display name |
| `version` | string | `"0.1.0 BETA"` | Reported by `status` and `--version` |
| `environment` | string | `"local"` | `local` for this release |

## `logging`

| Key | Type | Default | Notes |
|---|---|---|---|
| `level` | string | `"INFO"` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `max_bytes` | int | `5242880` | Rotate after this size |
| `backups` | int | `3` | Rotated files retained |

Logs go to `storage/logs/ase.log`. The logger never writes secrets, tokens or
API keys.

## `database`

| Key | Type | Default | Notes |
|---|---|---|---|
| `path` | string | `"storage/database/ase.db"` | SQLite file. A symlink is refused. |

## `storage`

| Key | Type | Default |
|---|---|---|
| `antivirus_dir` | string | `"storage/antivirus"` |
| `logs_dir` | string | `"storage/logs"` |
| `backup_dir` | string | `"storage/backups"` |

## `scan`

| Key | Type | Default | Notes |
|---|---|---|---|
| `max_file_size_mb` | int | `64` | Capped at 64. Larger files yield `scan_incomplete`. |
| `max_files` | int | `10000` | Capped at 10000 files per scan |
| `max_archive_members` | int | `2000` | Capped at 2000 |
| `max_archive_member_size_mb` | int | `32` | Capped at 32 |
| `max_archive_total_size_mb` | int | `128` | Capped at 128 |
| `scheduled_enabled` | bool | `false` | Enable the scheduled scan task |
| `scheduled_interval_minutes` | int | `1440` | Minimum 1 minute |
| `scheduled_paths` | list | `[]` | Empty means the home directory |

Limits cannot be raised above the hard caps by configuration — that is
deliberate, so a misconfiguration cannot turn a scan into a resource exhaustion
vector.

## `realtime`

| Key | Type | Default | Notes |
|---|---|---|---|
| `watch_paths` | list of strings | `[]` | Empty means the monitor reports `idle` |
| `interval_seconds` | int | `3` | Polling interval; native events also use it as a settle window |
| `max_files` | int | `5000` | Cap per directory tree |
| `prefer_native` | bool | `true` | Use inotify when available |
| `auto_scan` | bool | `true` | Scan files that change |

`follow_symlinks` is not configurable: symlinks are always refused.

Only directories that exist and are readable are accepted. Files and missing
paths are dropped from the list, and the resolved list is what gets reported.

## `monitoring`

Legacy alias for `realtime.watch_paths`. Used only when `realtime.watch_paths`
is empty.

## `api`

| Key | Type | Default | Notes |
|---|---|---|---|
| `host` | string | `"127.0.0.1"` | Must be `127.0.0.1`, `::1` or `localhost` |
| `port` | int | `8765` | Must be ≥ 1024 and ≤ 65535 |
| `enabled` | bool | `true` | Set `false` to run without the HTTP API |
| `max_body_bytes` | int | `65536` | Request body limit |
| `rate_limit_requests` | int | `120` | Requests per client per window |
| `rate_limit_window_seconds` | int | `60` | Rate-limit window |
| `allow_scan_paths` | list of strings | `[]` | Empty allows any readable path |

A non-loopback `host` raises `ASEConfigError` and is never written to disk.

## `intelligence`

| Key | Type | Default | Notes |
|---|---|---|---|
| `max_indicators` | int | `10000` | Capacity cap |
| `indicator_ttl_days` | int | `30` | `0` disables automatic expiry |

## `network`

| Key | Type | Default | Notes |
|---|---|---|---|
| `alert_suppression_seconds` | int | `900` | Duplicate alert window |
| `max_connections` | int | `2000` | Inventory cap |
| `history_size` | int | `100` | Connection history depth |

## `process`

| Key | Type | Default | Notes |
|---|---|---|---|
| `max_processes` | int | `500` | Inventory cap |
| `include_executable_path` | bool | `true` | Include `exe` when readable |

## `analysis`

| Key | Type | Default | Notes |
|---|---|---|---|
| `alert_dedupe_seconds` | int | `300` | Duplicate alert window; `0` disables |
| `history_size` | int | `500` | In-memory analysis results |

## Validation rules

Rejected with `ASEConfigError`:

- `api.host` not loopback
- `api.port` below 1024 or above 65535
- negative or absurd size and count limits
- `realtime.watch_paths` containing non-strings
- `follow_symlinks` set to true
- `logging.level` not a known level
- malformed JSON in the config file

## Environment-specific examples

### Developer workstation

```json
{
  "realtime": { "watch_paths": ["/home/me/Downloads", "/home/me/Desktop"] },
  "scan": { "max_file_size_mb": 64 },
  "api": { "port": 8765 }
}
```

### Restricted shared machine

```json
{
  "api": {
    "port": 8765,
    "rate_limit_requests": 30,
    "rate_limit_window_seconds": 60,
    "allow_scan_paths": ["/home/shared/scan-target"]
  },
  "scan": { "max_files": 2000 }
}
```

### Android / Termux

```json
{
  "realtime": { "watch_paths": ["/data/data/com.termux/files/home/storage/downloads"],
                "prefer_native": false },
  "scan": { "max_files": 1000 }
}
```
