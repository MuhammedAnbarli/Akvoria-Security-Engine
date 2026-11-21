# Release Notes — AKVORIA SECURITY ENGINE 0.1.0 BETA

Release date: 2026-11-20
Type: local release (no cloud functionality)
Platforms: Linux, Windows, Android/Termux

---

## What this release is

ASE 0.1.0 BETA is the first complete, integrated, tested local build of the engine.
The 1.3 prototype had a scanner, a polling monitor and a loopback API. This
release adds the modules that were missing, wires everything through one event
bus, hardens the API, completes the CLI, and puts a 252-test suite behind it.

Everything stated below is covered by an executed test. Anything not
implemented is listed under **Known limitations** rather than described as
working.

## Highlights

### Antivirus engine — complete

Quick, full and custom scans; SHA-256 hashing; local signature matching;
heuristic rules; ZIP archive inspection with member, per-member and
total-uncompressed limits; cooperative cancellation; persistent history and
statistics; per-file explanations and risk scores.

Verdicts are fixed and truthful: `no_known_indicators`, `suspicious`,
`malicious_indicator`, `scan_incomplete`, `scan_error`. The engine never reports
a file as safe.

### Real-time monitoring — complete, with honest scope

Native inotify on Linux with a bounded polling fallback. Creation, modification
and deletion are tracked; changes are scanned automatically; duplicate events
are suppressed by hash. `monitoring show` reports the actual resolved
directories and the active mode (`native`, `polling`, `idle_no_paths`).

Scope is always `configured_directories_only`. There is no system-wide
protection, and the status payload says so.

### Quarantine and restore — complete

Explicit-authorization quarantine with SHA-256 integrity metadata, collision-free
identifiers, `0600` storage and full history. Restore re-hashes the stored copy
before writing anything back and refuses to overwrite an existing file.

Nothing is ever deleted automatically.

### Threat intelligence — complete

Strictly validated IP, domain and SHA-256 indicators with normalization,
confidence, source tracking, expiry, deduplication and persistence.
Import/export as JSON. Signed offline feed import with Ed25519 verification that
rejects unsigned, tampered, wrong-key and rolled-back feeds.

### Network and process inventory — complete, passive

Read-only connection inventory from Linux procfs with indicator matching,
history and duplicate-alert suppression. Read-only process inventory with PID,
name, state and executable metadata where readable. Unsupported platforms report
themselves as unsupported.

No scanning, no exploitation, no credential collection, no process termination.

### Analysis and response — complete, explainable

Every event is normalized, scored and given reasons. Alerts carry severity,
risk score, correlation context and a recommendation. Duplicates are suppressed,
alerts are persisted and acknowledged, and related alerts group into incidents.

Response is recommendation-only. No destructive automatic action exists.

### API — hardened

Loopback-only binding (rejected at config time *and* bind time), bearer
authentication with constant-time comparison, per-client rate limiting, request
size limits, `Content-Type` validation, strict JSON object parsing, security
response headers and secret-free error handling.

The API key is generated with `secrets.token_urlsafe`, stored `0600`, refused if
the path is a symlink, and never logged.

### CLI — 15 commands

`start`, `stop`, `status`, `health`, `self-test`, `scan`, `history`,
`quarantine`, `restore`, `alerts`, `intelligence`, `monitoring`, `diagnostics`,
`report`, `config`. All emit JSON. The 1.3 flag style still works.

### Engine infrastructure

Central event bus with subscriber isolation, dependency-ordered module lifecycle,
validated configuration with atomic writes, versioned SQLite migrations that
upgrade a 1.3 database in place, backup and restore, log rotation, diagnostics,
runtime statistics and graceful shutdown.

---

## Defects fixed

These were found by the new test suite and fixed before release:

1. Quarantine identifier collision for identical files in the same millisecond.
2. Alert `action` and `recommendation` lost when reloaded from the database.
3. `/api/scans/statistics` shadowed by the `/api/scans/<id>` route.
4. Unknown quarantine identifier returned `500` instead of `404`.
5. Health check raised on a partially initialized engine.
6. A missing module dependency aborted the entire start sequence.
7. Modules that returned `False` were still reported as `running`.
8. 1.3-style CLI flags rejected by argparse before the legacy handler ran.
9. Platform support probed inconsistently in three separate places.

Duplicate table definitions and duplicate methods in the database layer were
also removed; one migration path now owns the schema.

---

## Test results

| Metric | Result |
|---|---|
| Tests collected | 252 |
| Passed | 252 |
| Failed | 0 |
| Errors | 0 |
| Skipped | 0 |
| Compilation | Clean |
| Modules imported | 19 / 19 |

Full detail: [`docs/TEST-REPORT.md`](docs/TEST-REPORT.md).

---

## Breaking changes from 1.3

- **Verdict vocabulary changed.** `clean` is gone. Use `no_known_indicators`,
  which means nothing matched — not that the file is safe. Any script matching
  on `clean` must be updated.
- **`/api/status` shape changed.** `protection_scope` is now always present and
  the module status map reports `idle` for modules that are not active.
- **Quarantine requires authorization.** The API needs `"authorized": true`.
  The CLI sets it implicitly because the operator invoked the command.
- **Non-loopback `api.host` is rejected.** Previously it was accepted.
- **Database schema is version 3.** Migration is automatic and preserves data.

---

## Known limitations

| Area | Limitation |
|---|---|
| Protection scope | Configured directories only. No kernel-level or system-wide protection. |
| Android/Termux | Cannot watch the whole device. Only directories the app can read. |
| Windows | No native filesystem events (polling). No network inventory. |
| YARA | Requires optional `yara-python`. |
| Signed feeds | Require optional `cryptography`. |
| Cloud | Not included in this release. |
| Detection | Indicator-based. It cannot prove a file is safe, and it will miss unknown malware. |

---

## Upgrade notes

```bash
git pull
python -m pip install -r requirements.txt
python main.py self-test
```

The database migrates automatically. Back up first if the history matters:

```bash
python main.py diagnostics --backup
```

Update any script that matched on the old `clean` verdict.

---

## Verification

```bash
python3 -m compileall -q core modules main.py tests
python3 -m unittest discover -s tests -t .
python3 scripts/ase_selfcheck.py
```

Expected: `OK`, then `All 19 modules imported successfully.`
