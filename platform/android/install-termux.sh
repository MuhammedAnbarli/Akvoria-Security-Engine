#!/data/data/com.termux/files/usr/bin/bash
# AKVORIA ASE — Termux setup. Runs unprivileged inside the app sandbox.
set -euo pipefail

pkg update -y
pkg install -y python

python - <<'PYCHECK'
import sys
if sys.version_info < (3, 10):
    raise SystemExit("Python 3.10 or newer is required, found %s" % sys.version.split()[0])
PYCHECK

python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo
echo "Installed."
echo "  Verify : python main.py self-test"
echo "  Monitor: python main.py monitoring set ~/storage/downloads"
echo
echo "Scope note: Termux cannot watch the whole device. Monitoring covers only"
echo "the directories you configure and Termux is permitted to read."
echo "Optional signed-feed support: python -m pip install -r requirements-optional.txt"
