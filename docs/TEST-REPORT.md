# Test Report — AKVORIA SECURITY ENGINE 0.1.0 BETA

Generated: 2026-11-20
Environment: Linux, CPython 3.13.15

## Summary

| Metric | Result |
|---|---|
| Test cases collected | **252** |
| Passed | **252** |
| Failed | **0** |
| Errors | **0** |
| Skipped | **0** |
| Compilation (`compileall`) | Clean |
| Module import check (19 modules) | Clean |
| Total suite runtime | ~13 s |

No test was removed, disabled or skipped to reach this result. Every test in the
suite executed.

## Reproduction

```bash
python3 -m compileall -q core modules main.py tests
python3 -m unittest discover -s tests -t . -v
python3 scripts/ase_selfcheck.py
```

Expected final line: `OK`.

## Coverage by area

| Suite | Tests | What it proves |
|---|---|---|
| `test_core` | 42 | Config merge/validation/rollback, schema migrations, legacy upgrade, event bus isolation, module dependency order, scheduler backoff |
| `test_antivirus` | 32 | Five-verdict discipline, EICAR, double extension, signature match, archives and their limits, cancellation, quarantine/restore integrity |
| `test_api_integration` | 27 | Live HTTP server: auth, hardening, scanning, quarantine, intelligence, monitoring, error mapping |
| `test_cli` | 22 | All 15 commands plus legacy flags, exit codes, JSON output |
| `test_api_security` | 18 | IP allowlist, rate limiting, audit trail, key generation, `0600` permissions, constant-time comparison, rotation |
| `test_intelligence` | 18 | Strict IP/domain/SHA-256 validation, normalization, expiry, dedupe, persistence, import/export |
| `test_analysis` | 17 | Risk scoring, severity bands, reasons on every alert, correlation, dedupe, acknowledgement, no destructive action |
| `test_engine` | 17 | Lifecycle, wiring, persistence across restart, backup/restore, end-to-end detect→alert→quarantine→restore |
| `test_network_process` | 17 | procfs parsing, indicator matching, duplicate suppression, bounded read-only inventories |
| `test_realtime` | 13 | Creation/modification/deletion, dedupe, symlink refusal, honest scope reporting, lifecycle |
| `test_detect_monitor` | 12 | SHA-256 baselines, change detection, static findings, health aggregation without exceptions |
| `test_platform` | 9 | Windows/Android fallbacks, capability reporting, permission errors are non-fatal |
| `test_threat_feed` | 8 | Ed25519 verification, unsigned/tampered/wrong-key/rollback rejection |

## Key behaviors verified

### Truthful verdicts

- `no_known_indicators` explanations include "does not prove" — the engine never
  states a file is safe.
- The verdict vocabulary is asserted against the documented set.

### No silent destruction

- Quarantine without `authorized=True` raises and the file stays put.
- Quarantine of a clean file raises and the file stays put.
- Scanning does not modify file contents (byte-for-byte assertion).
- Response engine leaves `count_quarantined() == 0` after a critical alert.

### Integrity

- Restore re-hashes and refuses on tampering.
- Restore refuses when the original path is occupied.
- Quarantine IDs are unique even for identical files in the same millisecond.
- Quarantine files are stored with mode `0600`.

### API hardening

- Unauthenticated requests → `401` with `WWW-Authenticate`.
- Wrong token → `401`. Missing token → `401`. `Basic` scheme → `401`.
- Wrong `Content-Type` → `415`. Invalid JSON → `400`. Non-object JSON → `400`.
- Oversized body → `413`. Empty body → `400`.
- Non-loopback bind is refused.
- Key file mode is exactly `0600`; a symlinked key path is refused.
- No API key, traceback or internal path appears in any error body.
- `GET /health` returns no engine state.

### Persistence

- A 1.3 database with the old `file_baselines` and `threat_indicators` schemas
  upgrades in place: rows survive, missing columns are added, version advances.
- Running migrations twice is a no-op.
- Data written before a restart is readable after it.

## Defects found and fixed during this test campaign

Each was discovered by a failing test, then fixed, then re-tested.

| # | Defect | Fix |
|---|---|---|
| 1 | Two identical files quarantined in the same millisecond collided on identifier | `_allocate_quarantine_slot()` reserves a unique id under lock |
| 2 | `action` and `recommendation` lost when an alert was reloaded | Derived fields mirrored into the persisted detail blob |
| 3 | `/api/scans/statistics` shadowed by `/api/scans/<id>` | Statistics route matched before the parameterised route |
| 4 | Unknown quarantine id returned `500` | `ASEQuarantineError` mapped to `404` |
| 5 | Health check raised on a partially initialized engine | Every probe wrapped in `_probe`/`_safe_health`/`_capability` |
| 6 | A missing module dependency aborted the whole start sequence | `start_all()` isolates ordering and per-module failures |
| 7 | Modules returning `False` were reported `running` | Manager reports `idle` and excludes it from the started list |
| 8 | 1.3 CLI flags rejected by argparse before the legacy handler | Legacy flags detected before `parse_args` |
| 9 | Platform support probed inconsistently in three places | Centralized in `core.platform_info.PlatformInfo` |
| 10 | `monitoring show` and `/api/monitoring` exposed scope only nested, so a caller reading the documented top-level `scope` got `None` | Scope, mode, roots and running state promoted to the top level in both the CLI and the API |
| 11 | The user-kit verification script resolved `main.py` relative to its own directory, so every check failed once packaged | Root resolved by probing for `main.py`, and rejection checks strengthened to assert the specific exit code and message rather than any nonzero exit |

## Manual verification performed

Beyond the automated suite:

1. **API smoke test** — 22/22 checks against a live engine on port 19020,
   covering auth, hardening, scan, quarantine, restore, indicators, monitoring,
   diagnostics, process and network endpoints.
2. **Secret hygiene** — `grep` for the generated API key and the string `bearer`
   in `storage/logs/ase.log` returned zero matches.
3. **Key permissions** — `stat -c %a storage/ase_api.key` returned `600`.
4. **CLI walkthrough** — every command run in an isolated directory; scan,
   quarantine, restore, intelligence, monitoring, diagnostics, report and config
   all produced the documented output.
5. **Example scripts** — `examples/quickstart.sh` completed the full
   self-test → scan → quarantine → restore → history sequence.
6. **Workflow syntax** — all three GitHub Actions files parse as valid YAML.

## Known limitations of this test campaign

- The suite ran on Linux/CPython 3.13 only. The Windows and Android code paths
  are covered by mocked fallback tests, not by execution on those platforms.
  CI is configured to run the suite on Windows for Python 3.10–3.13.
- `cryptography` was installed for the signed-feed tests. When absent, those
  tests skip by design — the skip is a documented dependency boundary, not a
  suppressed failure.
- No coverage percentage is reported. Coverage was not measured; the table
  above describes behaviors asserted, not lines executed.
- Real-world malware samples were not used. Detection is verified against the
  EICAR standard test string, synthetic indicators and crafted archives.
