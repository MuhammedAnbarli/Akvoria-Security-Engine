#!/usr/bin/env bash
# End-to-end walkthrough: self-test, scan, quarantine, restore.
set -u
cd "$(dirname "$0")/.." || exit 1

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/config"
echo '{"api": {"port": 18765}}' > "$WORK/config/ase.json"

# The EICAR pattern is a harmless industry-standard test string.
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$WORK/sample.com"
echo "ordinary document" > "$WORK/notes.txt"

echo "== 1. self-test =="
python3 main.py --config "$WORK/config/ase.json" self-test | head -12

echo
echo "== 2. scan =="
python3 main.py --config "$WORK/config/ase.json" scan "$WORK" --summary

echo
echo "== 3. quarantine the detected file =="
python3 main.py --config "$WORK/config/ase.json" quarantine add "$WORK/sample.com"

echo
echo "== 4. list quarantine =="
python3 main.py --config "$WORK/config/ase.json" quarantine list | head -8

echo
echo "== 5. restore it =="
QID=$(python3 main.py --config "$WORK/config/ase.json" quarantine list \
      | python3 -c "import json,sys; print(json.load(sys.stdin)['items'][0]['quarantine_id'])")
python3 main.py --config "$WORK/config/ase.json" restore "$QID"

echo
echo "== 6. history =="
python3 main.py --config "$WORK/config/ase.json" history --limit 1 | head -14
