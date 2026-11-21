#!/usr/bin/env bash
# Compile every module, then run the full test suite.
set -u
cd "$(dirname "$0")/.." || exit 1

echo "== compile =="
python3 -m compileall -q core modules main.py tests || exit 1

echo "== tests =="
python3 -m unittest discover -s tests -t . 2>&1 | tail -20
