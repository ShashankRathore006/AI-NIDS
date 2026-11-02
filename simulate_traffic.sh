#!/usr/bin/env bash
# Inject simulated attack traffic into AI-NIDS database for testing/demo
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BURST_COUNT="${1:-10}"

echo "[AI-NIDS Test Utility] Simulating burst of $BURST_COUNT attack/benign traffic flows..."
python3 "$SCRIPT_DIR/frontend/simulate_attacks.py" --burst "$BURST_COUNT"
echo "[AI-NIDS Test Utility] Simulation complete. Note: This script is strictly for explicit testing."
