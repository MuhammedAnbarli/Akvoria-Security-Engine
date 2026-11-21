# AKVORIA SECURITY ENGINE 0.1.0 BETA — Release Summary

Verification record for this release. Every figure below was produced by
executing the command shown, not estimated.

## Artifacts

| File | Contents | Members | SHA-256 |
|---|---|---|---|
| `AKVORIA-ASE-SOURCE.zip` | Complete GitHub-ready source tree | 77 | see `SHA256SUMS.txt` |
| `AKVORIA-ASE-USER-TEST.zip` | User acceptance kit with `verify_install.py` | 54 | see `SHA256SUMS.txt` |
| `SHA256SUMS.txt` | Checksums for both archives | — | — |

## Verification performed

| Check | Command | Result |
|---|---|---|
| Compilation | `python3 -m compileall -q core modules main.py tests` | Clean |
| Full test suite | `python3 -m unittest discover -s tests -t .` | **252 passed, 0 failed, 0 errors, 0 skipped** |
| Module imports | `python3 scripts/ase_selfcheck.py` | 19 / 19 |
| User acceptance kit | `python3 verify_install.py` | **31 / 31 checks passed** |
| Source archive independence | extract to clean dir, compile + full suite | 252 passed |
| User kit independence | extract to clean dir, run `verify_install.py` | 31 / 31 passed |
| Archive integrity | `zipfile.testzip()` on both | No corrupt members |
| Secret scan | regex sweep of both archives | Clean |
| Real API key absent | search both archives for `storage/ase_api.key` value | Absent (correct) |
| Runtime data absent | inspect member names | No `.db`, `.key`, `.log`, `storage/`, `config/ase.json` |
| Checksums | recompute SHA-256 and compare | Both `OK` |
| Workflow syntax | parse all three with PyYAML | Valid |

## Test breakdown

| Suite | Tests |
|---|---|
| `test_core` | 42 |
| `test_antivirus` | 32 |
| `test_api_integration` | 27 |
| `test_cli` | 22 |
| `test_api_security` | 18 |
| `test_intelligence` | 18 |
| `test_analysis` | 17 |
| `test_engine` | 17 |
| `test_network_process` | 17 |
| `test_realtime` | 13 |
| `test_detect_monitor` | 12 |
| `test_platform` | 9 |
| `test_threat_feed` | 8 |
| **Total** | **252** |

## Defects found and fixed

Eleven defects were found by the test suite and fixed before release:

1. Quarantine ID collision for identical files in the same millisecond.
2. Alert `action` / `recommendation` lost on reload.
3. `/api/scans/statistics` shadowed by `/api/scans/<id>`.
4. Unknown quarantine ID returned `500` instead of `404`.
5. Health check raised on a partially initialized engine.
6. Missing module dependency aborted the whole start sequence.
7. Idle modules reported as `running`.
8. 1.3 CLI flags rejected before the legacy handler ran.
9. Platform support probed inconsistently in three places.
10. Monitoring scope exposed only nested, contradicting the documented contract.
11. User-kit verifier resolved `main.py` relative to its own directory.

## Reproduce

```bash
python3 -m compileall -q core modules main.py tests
python3 -m unittest discover -s tests -t .
python3 scripts/ase_selfcheck.py
python3 scripts/build_release.py
sha256sum -c SHA256SUMS.txt
```

## Honest limitations

- Tests executed on Linux / CPython 3.13 only. Windows and Android paths are
  covered by mocked fallback tests; CI is configured to run the suite on Windows
  for Python 3.10–3.13.
- Detection is indicator-based and cannot prove a file is safe, nor detect
  unknown malware.
- No kernel-level or system-wide protection exists in this release.
- No coverage percentage is reported because coverage was not measured.
