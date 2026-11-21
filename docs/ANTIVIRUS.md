# Antivirus Engine

The scanner is local and read-only. It computes SHA-256, matches local
signatures, applies conservative heuristic rules and inspects ZIP archives
within resource limits.

## Verdicts

| Verdict | Meaning |
|---|---|
| `no_known_indicators` | Nothing matched. **Not proof the file is harmless.** |
| `suspicious` | A weak indicator matched; review recommended. |
| `malicious_indicator` | A known indicator matched. |
| `scan_incomplete` | A configured limit stopped analysis of this file. |
| `scan_error` | The file could not be read. |

The engine never reports a file as safe.

## Detection sources

1. **Local signatures** — `storage/antivirus/signatures.json`, a map of SHA-256
   to a label. Edit it to add your own hashes.
2. **EICAR test pattern** — the industry-standard harmless test string, used to
   verify the pipeline works.
3. **Heuristics** — double extensions (`invoice.pdf.exe`), executable content
   behind a document extension, embedded script markers in archive members.
4. **Threat indicators** — any SHA-256 registered through
   `python main.py intelligence add <hash> --type sha256`.
5. **YARA** — optional, when `yara-python` is installed and rules are present in
   `storage/antivirus/yara/`.

## Resource limits

| Limit | Default | Cap |
|---|---|---|
| File size | 64 MB | 64 MB |
| Files per scan | 10 000 | 10 000 |
| Archive members | 2 000 | 2 000 |
| Archive member size | 32 MB | 32 MB |
| Archive total uncompressed | 128 MB | 128 MB |

Caps are enforced in code so a configuration mistake cannot turn a scan into a
resource-exhaustion vector. A file over a limit yields `scan_incomplete`.

## Why symlinks are refused

Following a symlink lets a scan escape its target — a link inside a scanned
directory could point at `/etc/shadow` or a network share. The scanner refuses
them instead of resolving them.

## Scanning

```bash
python main.py scan ~/Downloads --summary
python main.py scan ~/Downloads --output report.json
python main.py scan --quick
python main.py scan --full
```

## Quarantine

Quarantine is a separate, explicit operation. It requires an authorization flag
at the API level and refuses files with no detection.

```bash
python main.py quarantine add ~/Downloads/suspect.exe
python main.py quarantine list
python main.py restore <quarantine_id>
```

Storage layout:

```
storage/antivirus/quarantine.json          metadata index
storage/antivirus/quarantine/<id>          stored content, mode 0600
```

Metadata records the original path, SHA-256, size, verdict, detection reasons
and timestamps.

Restore verifies the stored copy against its recorded SHA-256 before writing
anything back, and refuses to overwrite an existing file.

## Reports

Every scan produces a structured report:

```json
{
  "scan_type": "custom",
  "status": "completed",
  "total": 120,
  "detections": 1,
  "verdict_counts": {"no_known_indicators": 119, "malicious_indicator": 1},
  "detection_details": [
    {"file": "...", "status": "malicious_indicator",
     "risk_score": 90, "reasons": ["..."]}
  ]
}
```

## Backups

Back up `storage/antivirus/` before manual changes. Use
`python main.py diagnostics --backup` to back up the database.
