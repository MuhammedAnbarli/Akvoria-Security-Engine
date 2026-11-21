# Security Policy

## Scope

AKVORIA Security Engine is a local defensive tool. The security properties it
claims are listed below, and each is covered by the automated test suite.

### Guarantees

1. **Loopback-only API.** A non-loopback `api.host` is rejected during config
   validation and again when the socket binds.
2. **Authenticated API.** Every state-bearing endpoint requires a bearer token,
   compared with `hmac.compare_digest`. Only `GET /health` is unauthenticated,
   and it returns no engine state.
3. **Protected key material.** The API key is generated with `secrets.token_urlsafe`,
   written with mode `0600`, refused if the path is a symlink, and never logged.
4. **Bounded input.** Request bodies are size-limited, must be `application/json`,
   and must decode to a JSON object.
5. **No secret leakage.** Error responses never contain tracebacks, filesystem
   paths or credentials. API request logs record method, path and status only.
6. **Authorization before quarantine.** A file moves only when the caller passes
   `"authorized": true` *and* the file carries a detection.
7. **Integrity-checked restore.** Restore re-hashes the stored copy and refuses
   on mismatch, leaving the quarantine record intact.
8. **Signed feeds only.** Threat feed imports require a valid Ed25519 signature
   over the canonical payload; unsigned, tampered, replayed and rolled-back
   feeds are refused.
9. **Read-only inspection.** Scanning never writes to the file being scanned.
   Symlinks are refused, so a scan cannot be redirected outside its target.
10. **No automatic destruction.** The engine never deletes files and never
    terminates processes.

### Explicit non-goals

ASE does not implement, and will not accept contributions that add:

- network scanning, port scanning or exploitation;
- credential collection or keylogging;
- stealth, evasion or persistence mechanisms;
- automatic process termination;
- automatic deletion or automatic quarantine of user files;
- any claim of operating-system-wide protection it cannot verify.

## Reporting a vulnerability

Do not open a public issue for a security defect.

1. Email the maintainers with a description, reproduction steps and the
   affected version.
2. State whether the issue is exploitable by an unauthenticated local user.
3. Allow a reasonable disclosure window before publishing details.

You will receive an acknowledgement, an assessment, and a remediation timeline.

## Hardening checklist for operators

- Keep `storage/ase_api.key` readable only by the account running the engine.
- Run the engine as an unprivileged user.
- Exclude `config/ase.json` from version control — it holds machine paths.
- Restrict `api.allow_scan_paths` when other local users can reach the API.
- Review `docs/COMPATIBILITY.md` before relying on a monitoring capability.
