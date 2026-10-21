#!/usr/bin/env bash
# Run the SAST stage locally: Semgrep against the sample app, SARIF out.
# Mirrors the sast-semgrep job in .github/workflows/appsec.yml.
#
# Usage: ./scripts/run_sast.sh
# Requires: semgrep (pip install semgrep) or Docker.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="results"
mkdir -p "$OUT"

if command -v semgrep >/dev/null 2>&1; then
  semgrep scan \
    --config p/python \
    --config p/secrets \
    --config p/owasp-top-ten \
    --sarif --output "$OUT/semgrep.sarif" \
    --metrics off \
    app/ tools/ || true
elif command -v docker >/dev/null 2>&1; then
  docker run --rm -v "$PWD:/src" -w /src semgrep/semgrep:latest \
    semgrep scan \
    --config p/python \
    --config p/secrets \
    --config p/owasp-top-ten \
    --sarif --output "$OUT/semgrep.sarif" \
    --metrics off \
    app/ tools/ || true
else
  echo "error: install semgrep (pip install semgrep) or Docker first" >&2
  exit 127
fi

echo "SAST done: $OUT/semgrep.sarif"
echo "Apply the gate:  python3 tools/gate.py --sarif $OUT/semgrep.sarif --threshold high"
