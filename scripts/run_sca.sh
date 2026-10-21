#!/usr/bin/env bash
# Run the SCA stage locally: pip-audit against the app's pinned
# requirements. Mirrors the sca job in .github/workflows/appsec.yml.
#
# Usage: ./scripts/run_sca.sh
# Requires: pip-audit (pip install pip-audit).
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="results"
mkdir -p "$OUT"

if ! command -v pip-audit >/dev/null 2>&1; then
  echo "error: install pip-audit first (pip install pip-audit)" >&2
  exit 127
fi

# pip-audit exits non-zero when it finds vulnerabilities -- on this lab
# that is the expected result, so capture it instead of dying on it.
pip-audit \
  --requirement app/requirements.txt \
  --format json \
  --output "$OUT/pip-audit.json" || true

pip-audit --requirement app/requirements.txt --desc on || true

echo "SCA done: $OUT/pip-audit.json"
echo "Apply the gate:  python3 tools/gate.py --pip-audit $OUT/pip-audit.json --threshold high"
