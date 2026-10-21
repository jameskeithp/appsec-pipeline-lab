#!/usr/bin/env bash
# Run the DAST stage locally: start the intentionally vulnerable app on
# localhost, then run the OWASP ZAP baseline scan against it via Docker
# (the same scan as zaproxy/action-baseline in CI).
#
# Usage: ./scripts/run_dast.sh
# Requires: Docker, python3, and the app dependencies installed
#           (pip install -r app/requirements.txt).
#
# The app binds 127.0.0.1 only. It is a training target: never point
# this script at anything you do not own and have permission to scan.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v docker >/dev/null 2>&1; then
  echo "error: the local DAST demo uses the ZAP Docker image; install Docker first" >&2
  echo "       (CI runs the same baseline via zaproxy/action-baseline.)" >&2
  exit 127
fi

OUT="$PWD/results"
mkdir -p "$OUT"

python3 app/app.py >"$OUT/app.log" 2>&1 &
APP_PID=$!
trap 'kill "$APP_PID" 2>/dev/null || true' EXIT

for _ in $(seq 1 30); do
  curl -sf http://127.0.0.1:5000/ >/dev/null && break || sleep 1
done

# host.docker.internal lets the ZAP container reach the app on the host.
docker run --rm \
  --add-host=host.docker.internal:host-gateway \
  -v "$PWD/.zap:/zap/wrk/.zap:ro" \
  -v "$OUT:/zap/wrk/results:rw" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py \
  -t http://host.docker.internal:5000/ \
  -c .zap/rules.tsv \
  -r results/zap-report.html \
  -J results/zap-report.json || true

echo "DAST done: $OUT/zap-report.html"
