#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="${DATA_DIR:-/data}"
PORT="${FLASK_PORT:-8080}"
TIMEOUT="${GUNICORN_TIMEOUT:-3600}"

mkdir -p "${DATA_DIR}/uploads" "${DATA_DIR}/results"

# Single worker + threads keeps background analysis jobs and the in-memory
# registry inside one process; disk (status.json) is still the source of truth.
exec gunicorn \
    --chdir /opt/app \
    --bind "0.0.0.0:${PORT}" \
    --workers 1 \
    --threads 8 \
    --timeout "${TIMEOUT}" \
    --graceful-timeout 30 \
    --access-logfile - \
    app.app:app
