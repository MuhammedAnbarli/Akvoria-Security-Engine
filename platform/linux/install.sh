#!/usr/bin/env bash
# AKVORIA ASE — Linux setup. No root required.
set -euo pipefail

PY=${PYTHON:-python3}
command -v "$PY" >/dev/null 2>&1 || { echo "Python 3.10+ is required."; exit 1; }

"$PY" - <<'PYCHECK'
import sys
if sys.version_info < (3, 10):
    raise SystemExit("Python 3.10 or newer is required, found %s" % sys.version.split()[0])
PYCHECK

"$PY" -m venv .venv
# shellcheck disable=SC1091
. .venv/bin/activate
python -m pip install --upgrade pip >/dev/null
python -m pip install -r requirements.txt

echo
echo "Environment ready."
echo "  Verify : . .venv/bin/activate && python main.py self-test"
echo "  Optional: python -m pip install -r requirements-optional.txt"
