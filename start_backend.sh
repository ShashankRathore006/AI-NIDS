#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="$SCRIPT_DIR/venv/bin/python"

if [ ! -x "$VENV_PYTHON" ]; then
    echo "[AI-NIDS] ERROR: Virtual environment Python not found!"
    exit 1
fi

cd "$SCRIPT_DIR/backend"

HOST="${NIDS_HOST:-127.0.0.1}"
PORT="${NIDS_PORT:-8000}"

export PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}"

echo "[AI-NIDS] Using: $VENV_PYTHON"
echo "[AI-NIDS] Starting FastAPI Backend on http://${HOST}:${PORT} ..."

exec "$VENV_PYTHON" -m uvicorn main:app --host "$HOST" --port "$PORT"
