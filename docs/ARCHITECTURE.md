# Architecture

## Composition root

`core/engine.py` (`ASEEngine`) is the only place that constructs subsystems. It
reads configuration, builds every module, wires the event bus, registers
scheduler tasks and starts the HTTP API. Nothing else instantiates a module
directly, which keeps dependency order in one place.

Startup order matters:

1. `ASEDatabase.start()` — runs migrations, so every later component can persist.
2. `ASEAntivirus.start()` — loads signatures and quarantine metadata.
3. `ModuleManager.start_all()` — dependency-ordered; `analysis` waits for
   `response` so no alert is emitted before a subscriber exists.
4. `ASERealtimeMonitor.start()` — returns `False` and reports `idle` when no
   directories are configured.
5. `ASEScheduler.start()` — periodic health, scan and maintenance tasks.
6. `ASEAPI.start()` — binds loopback and loads or generates the API key.

Shutdown runs in reverse, and each step is individually guarded so one failing
component cannot block the rest of the shutdown.

## Event flow

```
module event  ──►  EventBus  ──►  ASEAnalysis  ──►  ASEResponse  ──►  ASEDatabase
                                     │                   │
                              risk score + reasons   alert + incident
```

`EventBus` isolates subscriber failures: a raising handler is logged and
recorded, and the remaining subscribers still receive the event. History is
bounded so a busy system cannot grow memory without limit.

`ASEAnalysis` normalizes every module's payload into one shape and attaches:

- `risk_score` — 0–100, summed from weighted factors and capped;
- `risk_level` — banded from the score (`low`/`medium`/`high`/`critical`);
- `reasons` — a human-readable list, never empty;
- `correlation` — related events and repetition count for the same subject;
- `requires_review` — true when a human should look at it.

`ASEResponse` decides whether an alert is a duplicate, assigns it to an
incident, attaches a recommendation, and persists it. It performs no
destructive action.

## Module contract

A module is any object exposing `start()` and `stop()`. `start()` may return
`False` to mean "idle, not running" — used by the realtime monitor when no
watch paths are configured. `ModuleManager` reports `idle` in that case rather
than claiming the module is protecting anything.

Dependencies are declared at registration and resolved with a topological
sort. A cycle raises `ASEModuleError`. A module whose dependency is missing is
reported as failed, and the remaining modules still start.

## Persistence

`ASEDatabase` owns a single SQLite connection guarded by an `RLock`. Schema
version lives in `PRAGMA user_version` and migrations apply in order, so a 1.3
database upgrades in place.

`_ensure_columns()` inspects `PRAGMA table_info` for each table and adds any
column introduced after the table was created. This repairs databases written by
earlier builds whose `CREATE TABLE IF NOT EXISTS` silently skipped new columns.

Writes use `INSERT ... ON CONFLICT DO UPDATE` so repeated indicator or baseline
observations update in place instead of failing or duplicating.

`backup()` uses SQLite's online backup API, so it is safe while the engine runs.
`restore_from()` validates the candidate file with `PRAGMA integrity_check`
before replacing the live database.

## Scanning pipeline

```
path ──► symlink check ──► size check ──► SHA-256 ──► signature lookup
                                                    ├─► heuristic rules
                                                    └─► archive inspection
                                                          (bounded)
```

The scanner is read-only. It refuses symlinks so a scan cannot be redirected
outside the requested target, and it enforces size, member-count and
total-uncompressed-size limits so a decompression bomb cannot exhaust memory or
disk. Exceeding a limit yields `scan_incomplete`, never a false "clean".

Cancellation is cooperative: `ScanCancellationToken` is checked between files
and between archive members.

## Real-time monitoring

The monitor prefers native inotify on Linux. It falls back to polling when
native events are unavailable, and reports which mode is active in
`get_status()`. It tracks the last-seen hash per path so a metadata-only change
does not produce a duplicate scan, and it records deletions because a file
disappearing from a watched directory is itself a signal.

Scope is always `configured_directories_only`. The status payload lists the
actual resolved roots.

## API layer

`core/api.py` is a `ThreadingHTTPServer` bound to a loopback address. Each
request passes an IP allowlist, a rate limiter and a bearer check before any
routing happens. `GET /health` short-circuits before authentication and returns
only a static liveness payload.

Input handling is strict: the body must be `application/json`, must fit the
configured byte limit, and must decode to a JSON object. Errors are mapped from
the specific `ASE*Error` types to appropriate status codes and never include a
traceback.

## Concurrency

- `ASEDatabase` — one `RLock` around all access.
- `EventBus` — a lock around the subscriber map; callbacks run outside it.
- `ModuleManager` — a lock around registry mutation.
- `ASEScheduler` — a lock around task state; each task runs in a worker thread
  with overlap protection and error backoff.
- `ASERealtimeMonitor` — a lock around the snapshot map.
