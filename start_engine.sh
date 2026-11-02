#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="$SCRIPT_DIR/venv/bin/python"

if [ ! -x "$VENV_PYTHON" ]; then
    echo "ERROR: Virtual environment Python not found"
    exit 1
fi

export PYTHONPATH="$SCRIPT_DIR:$SCRIPT_DIR/capture${PYTHONPATH:+:$PYTHONPATH}"

echo "[VYPR] Engine Python:"
"$VENV_PYTHON" --version

exec "$VENV_PYTHON" "$SCRIPT_DIR/capture/flow_tracker.py" "$@"
