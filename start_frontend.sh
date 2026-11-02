#!/usr/bin/env bash
# Start AI-NIDS Unified Frontend Application (Port 3000)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/frontend"

echo "[AI-NIDS] Starting Unified Frontend Application on http://localhost:3000 ..."
exec python3 server.py --port 3000
