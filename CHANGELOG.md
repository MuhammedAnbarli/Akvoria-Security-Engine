# Changelog

All notable changes to AKVORIA SECURITY ENGINE are documented here. This
project follows [Semantic Versioning](https://semver.org/).

## [0.1.0 BETA] — 2026-11-20

Local release. Every capability below is exercised by the automated suite
(252 tests). Capabilities that are not implemented are listed under
"Known limitations" rather than described as working.

### Added

- **Complete antivirus engine.** Quick, full and custom scans; SHA-256 hashing;
  local signature matching; heuristic indicators; ZIP archive inspection with
  member-count, member-size and total-size limits; cooperative cancellation;
  persistent scan history and statistics; per-file explanations and risk scores.
- **Real-time monitoring of configured directories.** Native inotify events on
  Linux with a bounded polling fallback; creation, modification and deletion
  tracking; automatic scanning of changes; duplicate-event suppression;
  configurable interval; health reporting that states its real scope.
- **Quarantine and restore.** Explicit-authorization quarantine with SHA-256
  integrity metadata, collision-free identifiers, `0600` storage, integrity
  verification on restore and refusal to overwrite an existing file.
- **Threat intelligence.** Strictly validated IP, domain and SHA-256 indicators
  with normalization, confidence values, source tracking, expiry, deduplication,
  persistence, import/export and a signed offline feed importer (Ed25519).
- **Passive network inventory.** Read-only connection listing from Linux procfs
  with indicator matching, history and duplicate-alert suppression.
- **Read-only process inventory.** PID, name, state and available executable
  metadata, with bounded output and explicit unsupported-platform reporting.
- **Analysis and response.** Central event normalization, cross-module
  correlation, explainable risk scoring, severity banding, duplicate suppression,
  persistent alert history, acknowledgement, incident grouping and
  recommendation-only response actions.
- **Hardened HTTP API.** Loopback-only binding, bearer authentication with
  constant-time comparison, rate limiting, request size limits, Content-Type
  validation, strict JSON parsing, security response headers and secret-free
  error handling.
- **Full CLI.** Fifteen commands: `start`, `stop`, `status`, `health`,
  `self-test`, `scan`, `history`, `quarantine`, `restore`, `alerts`,
  `intelligence`, `monitoring`, `diagnostics`, `report`, `config`.
- **Versioned database migrations** driven by `PRAGMA user_version`, with
  in-place repair of pre-1.4 tables. Existing user data is preserved.
- **Platform capability reporting** (`core/platform_info.py`) so unsupported
  features are reported, never assumed.
- **Backup and restore** of the runtime database, plus diagnostics export.
- Documentation: architecture, API, CLI, configuration, compatibility and test
  report.

### Fixed

- **Duplicate table definitions and duplicate methods** in the database layer
  removed; a single migration path now owns the schema.
- **Quarantine identifier collisions** when two identical files were quarantined
  within the same millisecond.
- **`/api/scans/statistics`** was shadowed by the `/api/scans/<id>` route.
- **Unknown quarantine identifier** returned HTTP 500 instead of 404.
- **Alert `action` and `recommendation` fields** were lost when an alert was
  reloaded from the database.
- **Health checks** raised an exception on a partially initialized engine
  instead of reporting the failure.
- **A missing module dependency** aborted the whole module start sequence
  instead of isolating the affected module.
- **Module status** reported `running` for modules that explicitly reported
  themselves idle.
- **1.3-style CLI flags** were rejected by argparse before the legacy handler
  could run.
- **Non-loopback API host** is now rejected at both config and bind time.

### Changed

- Engine version is now `0.1.0 BETA`.
- `requirements.txt` declares no mandatory third-party dependency; optional
  extras live in `requirements-optional.txt`.
- Verdict vocabulary is fixed to `no_known_indicators`, `suspicious`,
  `malicious_indicator`, `scan_incomplete`, `scan_error`. ASE never reports a
  file as safe.

### Known limitations

- No kernel-level or operating-system-wide protection.
- Android/Termux monitoring covers only directories the app can read.
- Windows network inventory is not implemented; process inventory uses
  `tasklist`.
- YARA scanning requires the optional `yara-python` package.
- Signed feed verification requires the optional `cryptography` package.
- No cloud functionality in this release.

## [1.3.0]

Initial local prototype: single-file scanner, polling monitor, loopback API.

## [1.2.0] and [1.1.1]

Earlier prototypes, retained in the release notes archive for history.
