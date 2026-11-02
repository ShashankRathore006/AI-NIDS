from fastapi import FastAPI, Query, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
import sqlite3
import os
import sys
import fcntl
import json
import signal
import subprocess
import time
from datetime import datetime
from typing import Optional

app = FastAPI(title="AI-NIDS Production Backend")

# Secure CORS: Whitelist local demo origins by default; configurable via ALLOWED_ORIGINS
DEFAULT_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:3001",
    "http://127.0.0.1:3001",
]
env_origins = os.environ.get("ALLOWED_ORIGINS")
if env_origins:
    allowed_origins = [o.strip() for o in env_origins.split(",") if o.strip()]
else:
    allowed_origins = DEFAULT_ALLOWED_ORIGINS

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH = os.path.join(PROJECT_ROOT, "database", "nids.db")
PID_FILE = "/tmp/ai_nids_engine.pid"
STATUS_FILE = "/tmp/ai_nids_status.json"
VENV_SITE_PACKAGES = os.path.join(
    PROJECT_ROOT,
    "venv",
    "lib",
    f"python{sys.version_info.major}.{sys.version_info.minor}",
    "site-packages"
)


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def is_pid_alive_and_active(pid: int) -> bool:
    """Check if process exists, is active, and is not a zombie."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False

    status_file = f"/proc/{pid}/status"
    if os.path.exists(status_file):
        try:
            with open(status_file, "r") as f:
                for line in f:
                    if line.startswith("State:"):
                        state_char = line.split()[1]
                        if state_char == "Z":
                            return False  # Zombie process
                        break
        except (OSError, IndexError):
            return False

    cmdline_file = f"/proc/{pid}/cmdline"
    if os.path.exists(cmdline_file):
        try:
            with open(cmdline_file, "rb") as f:
                cmd = f.read().decode("utf-8", errors="ignore")
                if "flow_tracker" not in cmd and "python" not in cmd:
                    return False
        except OSError:
            pass

    return True


def verify_control_auth(request: Request):
    """
    Control Plane Authentication:
    - In local-demo mode (calls from loopback: 127.0.0.1, ::1, testclient):
      permitted without key unless NIDS_API_KEY is explicitly configured.
    - Remote requests from other network hosts require explicit API key authentication
      via 'X-API-Key' or 'Authorization: Bearer <key>'.
    - If NIDS_API_KEY is configured in the environment, all control calls must provide a matching key.
    """
    configured_key = os.environ.get("NIDS_API_KEY", "").strip()
    client_ip = request.client.host if request.client else "unknown"
    is_local = client_ip in ("127.0.0.1", "::1", "localhost", "testclient")

    provided_key = request.headers.get("X-API-Key", "").strip()
    auth_header = request.headers.get("Authorization", "").strip()
    if not provided_key and auth_header.startswith("Bearer "):
        provided_key = auth_header[7:].strip()

    if configured_key:
        if not provided_key or provided_key != configured_key:
            raise HTTPException(
                status_code=401,
                detail="Unauthorized: Invalid or missing API key for monitoring control plane."
            )
    else:
        if not is_local:
            raise HTTPException(
                status_code=403,
                detail="Forbidden: Unauthenticated remote control access is denied. Set NIDS_API_KEY to enable authenticated remote access."
            )


def is_engine_lock_held() -> tuple[bool, Optional[int]]:
    """
    Test whether an engine currently holds the atomic fcntl lock on PID_FILE.
    Returns (is_locked, pid).
    """
    if not os.path.exists(PID_FILE):
        return False, None

    try:
        fd = os.open(PID_FILE, os.O_RDWR)
    except OSError:
        return False, None

    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # If we successfully acquired LOCK_EX, NO active engine holds the lock!
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
        return False, None
    except (BlockingIOError, IOError):
        # An active engine holds the exclusive lock!
        pid = None
        try:
            with open(PID_FILE, "r") as f:
                content = f.read().strip()
                if content:
                    pid = int(content)
        except Exception:
            pass
        os.close(fd)
        return True, pid
    except Exception:
        os.close(fd)
        return False, None


def get_engine_state():
    """
    Inspect atomic fcntl lock, PID, and status file to report engine health.
    Separates process_alive, heartbeat_healthy, capture_backend_alive, and capturing.
    """
    lock_held, pid = is_engine_lock_held()

    configured_iface = os.environ.get("NIDS_INTERFACE", "wlan0")
    if os.path.exists("/tmp/ai_nids_config.json"):
        try:
            with open("/tmp/ai_nids_config.json") as f:
                configured_iface = json.load(f).get("interface", configured_iface)
        except Exception:
            pass

    status_data = {
        "running": False,
        "healthy": False,
        "process_alive": False,
        "heartbeat_healthy": False,
        "capture_backend_alive": False,
        "capturing": False,
        "pid": pid,
        "interface": configured_iface,
        "packets_captured": 0,
        "active_flows": 0,
        "uptime_seconds": 0,
        "last_packet_time": None,
        "mode": "idle",
        "capture_error": None,
        "timestamp": None,
        "heartbeat_age_seconds": None
    }

    if not lock_held:
        # No active engine holds the atomic lock.
        # Clean up stale status file if left behind from an unclean death.
        # DO NOT delete PID_FILE: it serves as the permanent atomic lock inode.
        if os.path.exists(STATUS_FILE):
            try: os.remove(STATUS_FILE)
            except OSError: pass
        status_data["pid"] = None
        return status_data

    # An engine holds the kernel lock!
    proc_alive = is_pid_alive_and_active(pid) if pid else False
    status_data["process_alive"] = proc_alive

    if not proc_alive:
        status_data["mode"] = "zombie"
        return status_data

    # Read status file if available
    heartbeat_healthy = False
    capture_backend_alive = False
    capturing = False
    mode = "initializing"
    capture_error = None

    if os.path.exists(STATUS_FILE):
        try:
            with open(STATUS_FILE, "r") as f:
                data = json.load(f)
                status_data.update(data)
                status_data["process_alive"] = proc_alive
                status_data["pid"] = pid

                hb = data.get("heartbeat")
                if hb is not None:
                    try:
                        hb_age = time.time() - float(hb)
                        status_data["heartbeat_age_seconds"] = round(hb_age, 1)
                        heartbeat_healthy = (hb_age <= 10.0)
                    except (ValueError, TypeError):
                        heartbeat_healthy = False
                else:
                    ts = data.get("timestamp")
                    if ts:
                        try:
                            t_dt = datetime.fromisoformat(ts)
                            hb_age = (datetime.now() - t_dt).total_seconds()
                            status_data["heartbeat_age_seconds"] = round(hb_age, 1)
                            heartbeat_healthy = (hb_age <= 10.0)
                        except Exception:
                            heartbeat_healthy = False

                capture_backend_alive = bool(data.get("capture_backend_alive", False))
                mode = data.get("mode", "unknown")
                capture_error = data.get("capture_error")
                capturing = bool(data.get("capturing", False) and capture_backend_alive)
        except Exception:
            pass

    status_data["heartbeat_healthy"] = heartbeat_healthy
    status_data["capture_backend_alive"] = capture_backend_alive
    status_data["capturing"] = capturing
    status_data["capture_error"] = capture_error

    # Overall health: healthy if process is alive, heartbeat is healthy, AND capture backend is alive
    is_healthy = proc_alive and heartbeat_healthy and capture_backend_alive
    status_data["healthy"] = is_healthy
    status_data["running"] = is_healthy

    if not heartbeat_healthy and proc_alive:
        status_data["mode"] = "stalled"
    elif not capture_backend_alive and proc_alive:
        status_data["mode"] = "capture_failed"

    return status_data


@app.get("/")
def root():
    return {
        "system": "AI-NIDS",
        "status": "online",
        "engine": get_engine_state()
    }


# ============================================================================
# MONITORING ENGINE LIFECYCLE & CONTROLS
# ============================================================================

@app.get("/api/monitoring/status")
def monitoring_status():
    """Returns real-time operational status of the live packet capture & detection engine."""
    return get_engine_state()


@app.post("/api/monitoring/start")
def start_monitoring(request: Request, interface: Optional[str] = Query(None), mode: Optional[str] = Query(None)):
    """
    Safely start the authoritative live detection engine (flow_tracker.py).
    Sole ownership of PID_FILE belongs to flow_tracker.py via atomic fcntl lock.
    Handles dead processes, stale PID files, healthy engines, and live but stalled engines.
    """
    verify_control_auth(request)

    state = get_engine_state()
    lock_held, active_pid = is_engine_lock_held()

    # Case 1: Healthy engine already active
    if state["running"] and state["healthy"]:
        return {
            "status": "already_running",
            "pid": state["pid"],
            "message": f"Detection engine is already active and healthy on PID {state['pid']}"
        }

    # Case 2: Live but stalled or degraded engine (lock held or process alive, but not healthy)
    if lock_held or state["process_alive"] or (active_pid and is_pid_alive_and_active(active_pid)):
        stalled_pid = active_pid or state["pid"]
        print(f"[AI-NIDS Backend] Detected stalled/degraded engine PID {stalled_pid}. Stopping cleanly before restart...")

        # Stop the old stalled engine cleanly
        if stalled_pid:
            try:
                os.kill(stalled_pid, signal.SIGTERM)
                # Wait up to 3.0s for clean termination and lock release
                for _ in range(30):
                    time.sleep(0.1)
                    held, _ = is_engine_lock_held()
                    if not held and not is_pid_alive_and_active(stalled_pid):
                        break

                # If still alive, force kill
                if is_pid_alive_and_active(stalled_pid):
                    try:
                        os.kill(stalled_pid, signal.SIGKILL)
                        time.sleep(0.2)
                    except OSError:
                        pass
            except OSError:
                pass

        # Verify lock is completely released
        for _ in range(20):
            held, _ = is_engine_lock_held()
            if not held:
                break
            time.sleep(0.1)

        held, _ = is_engine_lock_held()
        if held:
            raise HTTPException(
                status_code=500,
                detail="Failed to release engine lock from stalled instance. Aborting startup."
            )

        # Clean residual status file
        if os.path.exists(STATUS_FILE):
            try: os.remove(STATUS_FILE)
            except OSError: pass

    # Case 3: Start new engine instance
       # Case 3: Start new engine instance
    python_bin = sys.executable

    target_iface = interface or os.environ.get("NIDS_INTERFACE", "wlan0")

    env = os.environ.copy()
    env["NIDS_INTERFACE"] = target_iface
    existing_pypath = env.get("PYTHONPATH", "")
    new_pypaths = [PROJECT_ROOT, os.path.join(PROJECT_ROOT, "capture")]
    if os.path.isdir(VENV_SITE_PACKAGES):
        new_pypaths.append(VENV_SITE_PACKAGES)
    if existing_pypath:
        new_pypaths.append(existing_pypath)
    env["PYTHONPATH"] = ":".join(new_pypaths)

    tracker_script = os.path.join(PROJECT_ROOT, "capture", "flow_tracker.py")
    log_file = open("/tmp/ai_nids_engine.log", "a")

    cmd = [python_bin, tracker_script, "--interface", target_iface]
    if mode:
        cmd.extend(["--mode", mode])

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=PROJECT_ROOT,
            env=env,
            stdout=log_file,
            stderr=log_file,
            start_new_session=True
        )

        with open("/tmp/ai_nids_config.json", "w") as f:
            json.dump({"interface": target_iface}, f)

        # Poll for flow_tracker.py to acquire its atomic fcntl lock and initialize STATUS_FILE
        engine_started = False
        start_deadline = time.time() + 6.0
        while time.time() < start_deadline:
            ret = proc.poll()
            if ret is not None:
                # Engine crashed or exited immediately!
                log_snippet = ""
                if os.path.exists("/tmp/ai_nids_engine.log"):
                    try:
                        with open("/tmp/ai_nids_engine.log", "r") as lf:
                            lines = lf.readlines()
                            log_snippet = " ".join([l.strip() for l in lines[-4:]])
                    except Exception:
                        pass
                raise HTTPException(
                    status_code=500,
                    detail=f"Detection engine exited immediately (code {ret}): {log_snippet}"
                )

            # Check if atomic fcntl lock is held by proc.pid
            locked, pid_holder = is_engine_lock_held()
            if locked and pid_holder == proc.pid and os.path.exists(STATUS_FILE):
                engine_started = True
                break

            time.sleep(0.1)

        if not engine_started:
            if proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=1.0)
                except Exception:
                    pass
            raise HTTPException(
                status_code=500,
                detail="Detection engine initialization timed out before acquiring atomic lock."
            )

        return {
            "status": "started",
            "pid": proc.pid,
            "interface": target_iface,
            "message": f"Live detection engine started on interface {target_iface}"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to launch detection engine: {e}")


@app.post("/api/monitoring/stop")
def stop_monitoring(request: Request):
    """Safely terminate the live detection engine and ensure lock release. Never deletes PID_FILE."""
    verify_control_auth(request)

    lock_held, pid = is_engine_lock_held()
    state = get_engine_state()
    target_pid = pid or state["pid"]

    if not target_pid or not is_pid_alive_and_active(target_pid):
        # Already stopped or dead - clean up any dangling status file only
        if os.path.exists(STATUS_FILE):
            try: os.remove(STATUS_FILE)
            except OSError: pass
        return {"status": "already_stopped", "message": "Detection engine is not currently running"}

    try:
        os.kill(target_pid, signal.SIGTERM)

        # Poll up to 3 seconds for clean exit and lock release
        exited = False
        for _ in range(30):
            time.sleep(0.1)
            held, _ = is_engine_lock_held()
            if not held and not is_pid_alive_and_active(target_pid):
                exited = True
                break

        if not exited:
            try:
                os.kill(target_pid, signal.SIGKILL)
                time.sleep(0.2)
            except OSError:
                pass

        # Cleanup residual status file if lock is freed; NEVER delete PID_FILE
        held, _ = is_engine_lock_held()
        if not held:
            if os.path.exists(STATUS_FILE):
                try: os.remove(STATUS_FILE)
                except OSError: pass

        return {"status": "stopped", "message": f"Detection engine (PID {target_pid}) stopped cleanly"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to stop detection engine: {e}")


@app.post("/api/monitoring/restart")
def restart_monitoring(request: Request, interface: Optional[str] = Query(None), mode: Optional[str] = Query(None)):
    """Safely restart the live detection engine."""
    verify_control_auth(request)
    state = get_engine_state()
    if state["running"] or state["pid"]:
        stop_monitoring(request)
        time.sleep(0.3)
    return start_monitoring(request, interface=interface, mode=mode)


# ============================================================================
# FLOWS & TRAFFIC TELEMETRY
# ============================================================================

@app.get("/api/flows")
def get_flows(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    protocol: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    threats_only: bool = Query(False),
    include_simulation: bool = Query(False)
):
    """
    Expose actual bidirectional network flow records for the Network Traffic page.
    Includes normal BENIGN traffic as well as detected threat flows.
    Excludes simulation records by default unless include_simulation=true.
    """
    conn = get_connection()
    cursor = conn.cursor()

    conditions = []
    params = []

    if not include_simulation:
        conditions.append("COALESCE(detection_type, '') != 'SIMULATION'")

    if threats_only:
        conditions.append("prediction != 'BENIGN'")

    if protocol and protocol.upper() != "ALL":
        conditions.append("UPPER(protocol) = ?")
        params.append(protocol.upper())

    if search:
        s = f"%{search.strip().lower()}%"
        conditions.append("(LOWER(source_ip) LIKE ? OR LOWER(destination_ip) LIKE ? OR CAST(source_port AS TEXT) LIKE ? OR CAST(destination_port AS TEXT) LIKE ?)")
        params.extend([s, s, s, s])

    where_clause = ""
    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)

    # Count matching
    cursor.execute(f"SELECT COUNT(*) FROM alerts {where_clause}", params)
    total_matching = cursor.fetchone()[0]

    # Fetch rows
    fetch_params = list(params)
    fetch_params.extend([limit, offset])
    cursor.execute(f"""
        SELECT * FROM alerts
        {where_clause}
        ORDER BY id DESC
        LIMIT ? OFFSET ?
    """, fetch_params)

    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return {
        "total": total_matching,
        "limit": limit,
        "offset": offset,
        "include_simulation": include_simulation,
        "flows": rows
    }


@app.get("/api/flows/{flow_id}")
def get_flow_by_id(flow_id: int, include_simulation: bool = Query(False)):
    """
    Forensic inspection of a single flow record.
    Returns 404 for simulation records when include_simulation is False.
    Preserves access when explicitly enabled with include_simulation=true.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts WHERE id = ?", (flow_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Flow record not found")

    record = dict(row)
    if not include_simulation and (record.get("detection_type") or "").upper() == "SIMULATION":
        raise HTTPException(status_code=404, detail="Flow record not found")

    return record


# ============================================================================
# STATS & ALERTS
# ============================================================================

@app.get("/api/stats")
def get_stats(include_simulation: bool = Query(False)):
    """
    Returns system-wide aggregated telemetry and attack class distribution.
    Excludes simulation records by default (COALESCE(detection_type, '') != 'SIMULATION').
    """
    conn = get_connection()
    cursor = conn.cursor()

    sim_filter = "" if include_simulation else "WHERE COALESCE(detection_type, '') != 'SIMULATION'"

    cursor.execute(f"SELECT COUNT(*) FROM alerts {sim_filter}")
    total = cursor.fetchone()[0]

    cursor.execute(f"""
        SELECT prediction, COUNT(*) as count
        FROM alerts
        {sim_filter}
        GROUP BY prediction
    """)
    counts = {row["prediction"]: row["count"] for row in cursor.fetchall()}

    cursor.execute(f"SELECT COALESCE(SUM(packets), 0), COALESCE(SUM(bytes), 0) FROM alerts {sim_filter}")
    sum_packets, sum_bytes = cursor.fetchone()

    conn.close()

    engine_state = get_engine_state()

    # Total threat count (non-benign)
    total_threats = sum(v for k, v in counts.items() if k != "BENIGN")

    return {
        "total_flows": total,
        "total_threats": total_threats,
        "benign": counts.get("BENIGN", 0),
        "dos": counts.get("DoS", 0),
        "ddos": counts.get("DDoS", 0),
        "port_scan": counts.get("PORT SCAN", 0),
        "brute_force": counts.get("Brute Force", 0),
        "total_packets": sum_packets,
        "total_bytes": sum_bytes,
        "monitoring": engine_state
    }


@app.get("/api/alerts")
def get_alerts(limit: int = 50, threats_only: bool = False, include_simulation: bool = False):
    """Returns recent alerts or threat incidents, excluding simulation by default."""
    conn = get_connection()
    cursor = conn.cursor()

    conditions = []
    if not include_simulation:
        conditions.append("COALESCE(detection_type, '') != 'SIMULATION'")

    if threats_only:
        conditions.append("prediction != 'BENIGN'")

    where_clause = ""
    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)

    cursor.execute(f"""
        SELECT * FROM alerts
        {where_clause}
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return rows


@app.get("/api/alerts/recent-attacks")
def get_recent_attacks(limit: int = 20, include_simulation: bool = False):
    """Returns recent confirmed attack events (excluding BENIGN and SIMULATION by default)."""
    conn = get_connection()
    cursor = conn.cursor()

    conditions = ["prediction != 'BENIGN'"]
    if not include_simulation:
        conditions.append("COALESCE(detection_type, '') != 'SIMULATION'")

    where_clause = "WHERE " + " AND ".join(conditions)

    cursor.execute(f"""
        SELECT * FROM alerts
        {where_clause}
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return rows


@app.get("/api/system/interfaces")
def get_system_interfaces():
    """Discovers host network interfaces."""
    try:
        res = subprocess.run(["ip", "-br", "addr"], capture_output=True, text=True, check=True)
        lines = res.stdout.strip().split("\n")
        interfaces = []
        for line in lines:
            parts = line.split()
            if len(parts) >= 2:
                iface = parts[0]
                status = parts[1]
                ip_addr = parts[2] if len(parts) > 2 else "none"
                interfaces.append({"interface": iface, "status": status, "address": ip_addr})
        return {"interfaces": interfaces}
    except Exception as e:
        return {"interfaces": [{"interface": "wlan0", "status": "UP", "address": "unknown"}]}
