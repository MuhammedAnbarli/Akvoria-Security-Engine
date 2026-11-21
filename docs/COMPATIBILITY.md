# Platform Compatibility

ASE targets Linux, Windows and Android/Termux with portable Python. No root or
administrator privileges are required for normal operation. Where a capability
is unavailable it is reported as unsupported — never silently assumed.

Check your machine:

```bash
python3 -c "from core.platform_info import PlatformInfo; import json; print(json.dumps(PlatformInfo.current(), indent=2))"
```

## Capability matrix

| Capability | Linux | Windows | Android / Termux |
|---|---|---|---|
| Quick / full / custom scan | Yes | Yes | Yes |
| SHA-256 + local signatures | Yes | Yes | Yes |
| ZIP archive inspection | Yes | Yes | Yes |
| Quarantine + restore | Yes | Yes | Yes |
| Scheduled scans | Yes | Yes | Yes |
| Native filesystem events | inotify | No | No |
| Polling monitor | Yes | Yes | Yes |
| Network inventory | procfs | Not implemented | Not implemented |
| Process inventory | procfs | `tasklist` | `/proc` where readable |
| HTTP API | Yes | Yes | Yes |
| YARA | Optional | Optional | Optional |
| Ed25519 feed verification | Optional | Optional | Optional |

`Python 3.10+` is required on every platform.

## Linux

Everything is supported. Native inotify is used when the kernel exposes
`inotify_init1`, with polling as a fallback.

```bash
bash platform/linux/install.sh
```

Notes:

- `/proc/net/tcp` and `/proc/net/tcp6` provide the connection inventory.
  Containers with a restricted `/proc` will report fewer connections, not wrong
  ones.
- Reading another user's `/proc/<pid>/exe` requires permission. When it is
  denied, `exe_accessible` is `false` and the rest of the row is still reported.

## Windows

```powershell
powershell -File platform/windows/install.ps1
```

Supported: scanning, quarantine, restore, monitoring (polling), scheduled
scans, the API, and process inventory through `tasklist`.

Not supported:

- **Network inventory.** There is no procfs equivalent with the same read-only
  guarantees. `GET /api/network/connections` returns
  `{"supported": false, "mode": "unsupported_platform"}`.
- **Native filesystem events.** The monitor polls. Changes are detected within
  one interval, not instantly.

The API remains loopback-only. Windows Firewall rules are not required and
should not be added.

## Android / Termux

```bash
bash platform/android/install-termux.sh
```

Termux runs as an unprivileged app inside a sandbox. That shapes what is
possible:

- **Supported:** scanning directories Termux can read, quarantine and restore
  inside those directories, polling monitoring, the loopback API, and the CLI.
- **Not supported:** system-wide monitoring. Android does not expose a
  filesystem-wide watch to an unprivileged app, and ASE does not request root.
- **Not supported:** network and process inventory beyond what the app sandbox
  exposes.

Configure the monitor with directories you can actually read:

```bash
python3 main.py monitoring set ~/storage/downloads ~/storage/shared/Documents
```

`python3 main.py monitoring show` reports the resolved roots and the active mode
(`native`, `polling` or `idle_no_paths`). If the list is empty, monitoring is
`idle` — not protecting anything, and it says so.

## Optional packages

| Package | Enables | Behavior when absent |
|---|---|---|
| `cryptography` | Ed25519 signed-feed verification | `intelligence feed` raises `ASEThreatFeedError` explaining the requirement |
| `yara-python` | YARA rule scanning | YARA rules are skipped; scanning continues |
| `psutil` | Richer Windows process data | Falls back to `tasklist` |
| `watchdog` | Alternative native events | Falls back to inotify or polling |

Install them with:

```bash
python3 -m pip install -r requirements-optional.txt
```

## What ASE does not do on any platform

- Kernel-level or system-wide protection.
- Blocking a file from executing.
- Automatic deletion or automatic quarantine.
- Automatic process termination.
- Network scanning, exploitation or credential collection.

These are deliberate boundaries, not gaps to be filled later.
