#!/usr/bin/env bash
# Start AI-NIDS Backend (8000), Live Detection Engine (flow_tracker.py), and Frontend (3000)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=========================================================="
echo " Starting AI-NIDS: AI Network Intrusion Detection System "
echo "=========================================================="

cleanup() {
    echo ""
    echo "[AI-NIDS] Shutting down services..."
    # Terminate engine first to flush flows and release PID file
    if [ -n "$ENGINE_PID" ]; then
        kill -TERM $ENGINE_PID 2>/dev/null || true
    fi
    kill $BACKEND_PID $FRONTEND_PID 2>/dev/null || true
    wait $ENGINE_PID 2>/dev/null || true
    wait $BACKEND_PID 2>/dev/null || true
    wait $FRONTEND_PID 2>/dev/null || true
    rm -f /tmp/ai_nids_engine.pid /tmp/ai_nids_status.json
    echo "[AI-NIDS] All services stopped cleanly."
}
trap cleanup INT TERM

# 1. Start FastAPI Backend in background
"$SCRIPT_DIR/start_backend.sh" &
BACKEND_PID=$!

# Wait 2 seconds for backend to initialize
sleep 2

# 2. Start Authoritative Detection Engine in background (flow_tracker.py)
"$SCRIPT_DIR/start_engine.sh" &
ENGINE_PID=$!

# Wait 2 seconds for engine to load model and initialize sniffer
sleep 2

# 3. Start Unified Frontend in background
"$SCRIPT_DIR/start_frontend.sh" &
FRONTEND_PID=$!

echo ""
echo "=========================================================="
echo " AI-NIDS System Active:"
echo " -> Unified Frontend:        http://localhost:3000"
echo " -> Backend API:             http://localhost:8000"
echo " -> Live Monitoring Status:  http://localhost:8000/api/monitoring/status"
echo " -> Flow Telemetry:          http://localhost:8000/api/flows"
echo " -> API Docs (Swagger):      http://localhost:8000/docs"
echo " -> Authoritative Engine:    capture/flow_tracker.py (PID: $ENGINE_PID)"
echo " Press Ctrl+C to stop all services."
echo "=========================================================="

wait
