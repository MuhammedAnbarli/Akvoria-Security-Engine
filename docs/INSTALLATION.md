# Installation

## Requirements

- Python 3.10 or newer (3.13 tested)
- No root or administrator privileges
- No mandatory third-party package

## Linux

```bash
git clone <repository-url> akvoria-ase
cd akvoria-ase
bash platform/linux/install.sh
. .venv/bin/activate
python main.py self-test
```

Manual equivalent:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

## Windows

```powershell
git clone <repository-url> akvoria-ase
cd akvoria-ase
powershell -ExecutionPolicy Bypass -File platform\windows\install.ps1
.\.venv\Scripts\python.exe main.py self-test
```

Do not add a firewall exception. The API binds to loopback only.

## Android / Termux

```bash
pkg install git
git clone <repository-url> akvoria-ase
cd akvoria-ase
bash platform/android/install-termux.sh
python main.py self-test
```

Grant storage access once, so Termux can read shared directories:

```bash
termux-setup-storage
python main.py monitoring set ~/storage/downloads
```

Termux runs unprivileged inside the app sandbox. Monitoring covers only the
directories you configure. ASE does not request root and does not claim
system-wide protection.

## Optional packages

| Package | Enables |
|---|---|
| `cryptography` | Ed25519 signed threat-feed verification |
| `yara-python` | YARA rule scanning |
| `psutil` | Richer Windows process data |

```bash
python -m pip install -r requirements-optional.txt
```

ASE runs correctly without them. Features that need a missing package raise a
clear error rather than failing silently.

## First run

The first command creates the runtime layout:

```
config/ase.json          configuration (safe defaults)
storage/database/ase.db  SQLite database
storage/logs/ase.log     rotating log
storage/antivirus/       signatures and quarantine
storage/ase_api.key      API key, mode 0600 (created on engine start)
```

Verify the installation:

```bash
python main.py --version
python main.py self-test
python main.py health
```

`self-test` exits `0` when every component reports healthy.

## First scan

```bash
python main.py scan ~/Downloads --summary
```

## Enable monitoring

```bash
python main.py monitoring set ~/Downloads
python main.py start
```

`start` prints the directories actually being watched. If none are configured it
says so and reports monitoring as idle.

## Running in the background

`start` runs in the foreground by design — you can see every log line.

Linux / macOS:

```bash
nohup python3 main.py start > ase.out 2>&1 &
python3 main.py stop
```

Termux:

```bash
python main.py start &
python main.py stop
```

## Using the API

```bash
KEY=$(cat storage/ase_api.key)
curl -H "Authorization: Bearer $KEY" http://127.0.0.1:8765/api/status
```

See [`API.md`](API.md).

## Upgrade

```bash
git pull
python -m pip install -r requirements.txt
python main.py self-test
```

Database migrations apply automatically on the next start. Existing data is
preserved. Back up first if the data matters to you:

```bash
python main.py diagnostics --backup
```

## Uninstall

```bash
rm -rf .venv storage config
```

Remove the directory to delete quarantined files. Confirm you no longer need
them before doing so.

## Troubleshooting

**`python3: command not found`** — install Python 3.10+. On Termux:
`pkg install python`.

**`Address already in use`** — another process holds the API port. Change
`api.port` in `config/ase.json` or stop the other process.

**`API must bind to loopback only`** — `api.host` must be `127.0.0.1`, `::1` or
`localhost`. This is enforced deliberately.

**Monitoring reports `idle_no_paths`** — no directories are configured. Run
`python main.py monitoring set <dir>`.

**Monitoring reports `polling` instead of `native`** — the platform does not
expose native events. Changes are still detected within one interval.

**`Process inventory unsupported`** — the platform has no readable procfs. This
is reported, not hidden.

**`Ed25519 verification requires the optional 'cryptography' package`** — install
it with `python -m pip install cryptography`.

**Scans return `scan_incomplete`** — a file exceeded a configured limit. Raise
`scan.max_file_size_mb` up to its cap of 64.

**A restore failed with an integrity error** — the stored copy no longer matches
its recorded SHA-256. The quarantine record was left intact; investigate before
retrying.
