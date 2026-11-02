import time
import sys
import os
import fcntl
import json
import signal
import subprocess
import pandas as pd
import joblib
from datetime import datetime
from threading import Thread, Lock
from collections import defaultdict

from scapy.all import sniff, IP, TCP, UDP
from scapy.utils import PcapReader

# Path configuration
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))
sys.path.append(PROJECT_ROOT)

from flow import Flow
from database.db import init_db, insert_alert


# =========================================================
# CONFIGURATION
# =========================================================

# Support environment variable or --interface / --mode command-line arguments
cli_iface = None
cli_mode = None
for idx, arg in enumerate(sys.argv):
    if arg in ("--interface", "-i") and idx + 1 < len(sys.argv):
        cli_iface = sys.argv[idx + 1]
    if arg in ("--mode", "-m") and idx + 1 < len(sys.argv):
        cli_mode = sys.argv[idx + 1]

INTERFACE = cli_iface or os.environ.get("NIDS_INTERFACE", "wlan0")
CAPTURE_MODE_PARAM = cli_mode or os.environ.get("NIDS_CAPTURE_MODE", "auto")

FLOW_TIMEOUT = 5

MODEL_FILE = os.path.join(PROJECT_ROOT, "models", "nids_random_forest.pkl")

# Runtime IPC files for single-instance lock and FastAPI status
PID_FILE = "/tmp/ai_nids_engine.pid"
STATUS_FILE = "/tmp/ai_nids_status.json"

# Process-lifetime atomic lock file descriptor
lock_fd = None

# Capture backend state tracking (separated from process liveness and cleanup heartbeat)
capture_backend_alive = False
capture_error = None
capture_thread = None

def is_pid_alive_and_active(pid: int) -> bool:
    """Check if process is alive, active, and not a zombie."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False

    # Check Linux zombie state
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

    # Check cmdline to ensure PID was not recycled by an unrelated system process
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

# Atomic Single Instance Check using Linux kernel fcntl.flock
def check_and_acquire_pid_lock():
    global lock_fd
    try:
        # Open in read-write create mode; do not truncate until lock is acquired!
        lock_fd = os.open(PID_FILE, os.O_RDWR | os.O_CREAT, 0o644)
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (BlockingIOError, IOError):
        # Another running engine holds the exclusive kernel lock!
        existing_pid = "unknown"
        try:
            with open(PID_FILE, "r") as f:
                content = f.read().strip()
                if content:
                    existing_pid = content
        except Exception:
            pass
        print(f"[AI-NIDS Engine] Another detection engine instance is already active (PID {existing_pid}).")
        print("[AI-NIDS Engine] Exiting to ensure only one sniffer runs.")
        if lock_fd is not None:
            try:
                os.close(lock_fd)
            except Exception:
                pass
            lock_fd = None
        sys.exit(0)

    # Exclusively acquired kernel lock: truncate and write current PID
    os.ftruncate(lock_fd, 0)
    os.lseek(lock_fd, 0, os.SEEK_SET)
    os.write(lock_fd, f"{os.getpid()}\n".encode())
    os.fsync(lock_fd)

    # Write immediate initial status with heartbeat and distinct health flags
    try:
        init_status = {
            "process_alive": True,
            "heartbeat_healthy": True,
            "capture_backend_alive": False,
            "capturing": False,
            "running": False,
            "pid": os.getpid(),
            "interface": INTERFACE,
            "uptime_seconds": 0.0,
            "packets_captured": 0,
            "active_flows": 0,
            "last_packet_time": None,
            "mode": "initializing",
            "capture_error": None,
            "heartbeat": round(time.time(), 3),
            "timestamp": datetime.now().isoformat()
        }
        with open(STATUS_FILE, "w") as f:
            json.dump(init_status, f)
    except Exception:
        pass

check_and_acquire_pid_lock()

# Port scan detection
SCAN_WINDOW = 10          # seconds
SCAN_PORT_THRESHOLD = 8   # unique destination ports

# Runtime tracking
packet_count = 0
last_packet_time = None
is_running = True
capture_mode = "native"
start_time = time.time()
dumpcap_proc = None


# =========================================================
# LOAD MODEL
# =========================================================

print("=" * 70)
print("AI NETWORK INTRUSION DETECTION SYSTEM")
print("=" * 70)

print("\nLoading Random Forest model...")

model = joblib.load(MODEL_FILE)

print("Model loaded successfully.")

init_db()

print("Database initialized.")

print(f"Interface: {INTERFACE}")
print(f"Flow timeout: {FLOW_TIMEOUT} seconds")
print(f"Scan window: {SCAN_WINDOW} seconds")
print(f"Scan threshold: {SCAN_PORT_THRESHOLD} ports")

print("\nStarting live detection...")
print("Press CTRL+C to stop.\n")


# =========================================================
# FLOW STORAGE
# =========================================================

flows = {}


# =========================================================
# PORT SCAN TRACKING
# =========================================================

# Structure:
#
# scan_tracker[(source_ip, destination_ip)] = [
#     (timestamp, destination_port, protocol)
# ]
#
scan_tracker = defaultdict(list)

scan_lock = Lock()


# =========================================================
# CREATE FLOW KEY
# =========================================================

def get_flow_key(packet):

    src = packet[IP].src
    dst = packet[IP].dst

    if TCP in packet:

        sport = packet[TCP].sport
        dport = packet[TCP].dport
        protocol = "TCP"

    elif UDP in packet:

        sport = packet[UDP].sport
        dport = packet[UDP].dport
        protocol = "UDP"

    else:

        sport = 0
        dport = 0
        protocol = "OTHER"

    return (
        src,
        dst,
        sport,
        dport,
        protocol
    )


# =========================================================
# REVERSE FLOW KEY
# =========================================================

def reverse_key(key):

    src, dst, sport, dport, protocol = key

    return (
        dst,
        src,
        dport,
        sport,
        protocol
    )


# =========================================================
# PORT SCAN DETECTOR
# =========================================================
def detect_port_scan(packet):

    if IP not in packet:
        return None

    # Only TCP packets
    if TCP not in packet:
        return None

    # Only SYN packets
    flags = str(packet[TCP].flags)

    # SYN must be present
    # ACK must NOT be present
    if "S" not in flags or "A" in flags:
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    dst_port = packet[TCP].dport

    current_time = time.time()

    scan_key = (src_ip, dst_ip)

    with scan_lock:

        # Create tracker entry if it does not exist
        if scan_key not in scan_tracker:
            scan_tracker[scan_key] = []

        # Add current SYN probe
        scan_tracker[scan_key].append(
            (
                current_time,
                dst_port
            )
        )

        # Remove old entries outside the scan window
        scan_tracker[scan_key] = [
            entry
            for entry in scan_tracker[scan_key]
            if current_time - entry[0] <= SCAN_WINDOW
        ]

        # Get unique destination ports
        unique_ports = set(
            entry[1]
            for entry in scan_tracker[scan_key]
        )

        # Detect port scan
        if len(unique_ports) >= SCAN_PORT_THRESHOLD:

            # Prevent repeated alerts for the same source-target pair
            # during the same scan window
            if not hasattr(detect_port_scan, "last_alert"):
                detect_port_scan.last_alert = {}

            last_alert = detect_port_scan.last_alert.get(
                scan_key,
                0
            )

            if current_time - last_alert < SCAN_WINDOW:
                return None

            # Remember alert time
            detect_port_scan.last_alert[scan_key] = current_time

            return {
                "source": src_ip,
                "destination": dst_ip,
                "ports": sorted(unique_ports),
                "count": len(unique_ports)
            }

    return None
# =========================================================
# CLEAN OLD SCAN DATA
# =========================================================

def cleanup_scan_tracker():

    current_time = time.time()

    with scan_lock:

        expired_keys = []

        for key, entries in scan_tracker.items():

            scan_tracker[key] = [
                entry
                for entry in entries
                if current_time - entry[0] <= SCAN_WINDOW
            ]

            if not scan_tracker[key]:

                expired_keys.append(key)

        for key in expired_keys:

            del scan_tracker[key]


# =========================================================
# PREDICT FLOW
# =========================================================

def predict_flow(flow):

    features = flow.to_features()


    print("\n--- DEBUG: RAW FEATURES ---")
    for key, value in features.items():
        print(f"{key}: {value}")
    print("--- END DEBUG ---\n")

    feature_values = pd.DataFrame([[
        features["Destination Port"],
        features["Flow Duration"],
        features["Total Fwd Packets"],
        features["Total Backward Packets"],
        features["Total Length of Fwd Packets"],
        features["Total Length of Bwd Packets"],
        features["Flow Bytes/s"],
        features["Flow Packets/s"],
        features["Fwd Packet Length Mean"],
        features["Bwd Packet Length Mean"],
        features["SYN Flag Count"],
        features["ACK Flag Count"],
        features["RST Flag Count"],
        features["Average Packet Size"]
    ]], columns=[
        "Destination Port",
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
        "Flow Bytes/s",
        "Flow Packets/s",
        "Fwd Packet Length Mean",
        "Bwd Packet Length Mean",
        "SYN Flag Count",
        "ACK Flag Count",
        "RST Flag Count",
        "Average Packet Size"
    ])

    prediction = model.predict(
        feature_values
    )[0]

    probabilities = model.predict_proba(
        feature_values
    )[0]

    confidence = max(probabilities) * 100

    return prediction, confidence


# =========================================================
# PROCESS PACKET
# =========================================================

def process_packet(packet):
    global packet_count, last_packet_time

    if IP not in packet:
        return

    packet_count += 1
    last_packet_time = datetime.now().isoformat()

    # -----------------------------------------------------
    # FIRST: CHECK FOR PORT SCAN
    # -----------------------------------------------------

    scan_result = detect_port_scan(packet)

    if scan_result:

        print("\n" + "=" * 70)
        print("🚨 PORT SCAN DETECTED")
        print("=" * 70)

        print(
            f"Source       : "
            f"{scan_result['source']}"
        )

        print(
            f"Target       : "
            f"{scan_result['destination']}"
        )

        print(
            f"Unique Ports : "
            f"{scan_result['count']}"
        )

        print(
            f"Ports        : "
            f"{scan_result['ports']}"
        )

        print(
            f"Time Window  : "
            f"{SCAN_WINDOW} seconds"
        )

        print(
            "Prediction   : PORT SCAN"
        )

        print(
            "Confidence   : BEHAVIOR-BASED DETECTION"
        )

        print("=" * 70)

        insert_alert(
            timestamp=datetime.now().isoformat(),
            source_ip=scan_result["source"],
            source_port=0,
            destination_ip=scan_result["destination"],
            destination_port=0,
            protocol="TCP",
            packets=scan_result["count"],
            bytes_count=0,
            prediction="PORT SCAN",
            confidence=100.0,
            detection_type="BEHAVIOR"
        )

        # Clear this source-target pair after detection
        # so the same scan does not print repeatedly.
        with scan_lock:

            scan_key = (
                scan_result["source"],
                scan_result["destination"]
            )

            # Clear scan history after detection
            scan_tracker.pop(scan_key, None)

            # Clear previous alert timestamp
            if hasattr(detect_port_scan, "last_alert"):
                detect_port_scan.last_alert.pop(scan_key, None)

    # -----------------------------------------------------
    # NORMAL FLOW PROCESSING
    # -----------------------------------------------------

    key = get_flow_key(packet)

    reverse = reverse_key(key)

    packet_length = len(packet[IP])

    flags = ""

    if TCP in packet:

        flags = str(packet[TCP].flags)

        # ---------------------------------------------------------
    # EXISTING FORWARD FLOW
    # ---------------------------------------------------------

    if key in flows:

        flows[key].update(
            forward=True,
            packet_length=packet_length,
            flags=flags
        )

        return

    # ---------------------------------------------------------
    # EXISTING REVERSE FLOW
    # ---------------------------------------------------------

    if reverse in flows:

        flows[reverse].update(
            forward=False,
            packet_length=packet_length,
            flags=flags
        )

        return

    # ---------------------------------------------------------
    # NEW FLOW
    # ---------------------------------------------------------
    # -----------------------------------------------------
    # NEW FLOW
    # -----------------------------------------------------

    flow = Flow(key)

    flow.update(
        forward=True,
        packet_length=packet_length,
        flags=flags
    )

    flows[key] = flow


# =========================================================
# CHECK EXPIRED FLOWS
# =========================================================

def check_expired_flows():

    current_time = time.time()

    expired = []

    for key, flow in list(flows.items()):

        inactive_time = (
            current_time - flow.last_time
        )

        if inactive_time >= FLOW_TIMEOUT:

            expired.append(key)

    # -----------------------------------------------------
    # PREDICT EXPIRED FLOWS
    # -----------------------------------------------------

    for key in expired:

        flow = flows.pop(key)

        try:

            prediction, confidence = predict_flow(
                flow
            )

            (
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol
            ) = flow.key

            print("\n" + "=" * 70)

            print("FLOW DETECTED")

            print("=" * 70)

            print(
                f"Source      : "
                f"{src_ip}:{src_port}"
            )

            print(
                f"Destination : "
                f"{dst_ip}:{dst_port}"
            )

            print(
                f"Protocol    : {protocol}"
            )

            print(
                f"Packets     : "
                f"{flow.total_packets()}"
            )

            print(
                f"Bytes       : "
                f"{flow.total_bytes()}"
            )

            print(
                f"Prediction  : {prediction}"
            )

            print(
                f"Confidence  : "
                f"{confidence:.2f}%"
            )

            print("=" * 70)

            insert_alert(
                timestamp=datetime.now().isoformat(),
                source_ip=src_ip,
                source_port=src_port,
                destination_ip=dst_ip,
                destination_port=dst_port,
                protocol=protocol,
                packets=flow.total_packets(),
                bytes_count=flow.total_bytes(),
                prediction=prediction,
                confidence=float(confidence),
                detection_type="ML"
            )

        except Exception as error:

            print(
                f"\nPrediction error: {error}"
            )


# =========================================================
# SYSTEM SIGNALS & SINGLE INSTANCE LOCK
# =========================================================

def write_status(mode_override=None, error_override=None):
    global packet_count, flows, capture_mode, start_time, last_packet_time
    global is_running, capture_backend_alive, capture_error, dumpcap_proc, capture_thread
    try:
        active_mode = mode_override or capture_mode
        active_error = error_override or capture_error

        # Real-time backend check based on active mode
        backend_alive = capture_backend_alive
        if active_mode == "native":
            if capture_thread is not None:
                if not capture_thread.is_alive():
                    backend_alive = False
                    if not active_error:
                        active_error = "Native capture worker thread is not alive"
            else:
                backend_alive = False
        elif active_mode == "dumpcap_stream":
            if dumpcap_proc is not None:
                poll_ret = dumpcap_proc.poll()
                if poll_ret is not None:
                    backend_alive = False
                    if not active_error:
                        active_error = f"dumpcap subprocess terminated with exit code {poll_ret}"
            else:
                backend_alive = False

        capturing_state = bool(is_running and backend_alive)
        status_data = {
            "process_alive": True,
            "heartbeat_healthy": True,
            "capture_backend_alive": backend_alive,
            "capturing": capturing_state,
            "running": capturing_state,
            "pid": os.getpid(),
            "interface": INTERFACE,
            "uptime_seconds": round(time.time() - start_time, 1),
            "packets_captured": packet_count,
            "active_flows": len(flows),
            "last_packet_time": last_packet_time,
            "mode": active_mode if backend_alive else "capture_failed",
            "capture_error": active_error,
            "heartbeat": round(time.time(), 3),
            "timestamp": datetime.now().isoformat()
        }
        with open(STATUS_FILE + ".tmp", "w") as f:
            json.dump(status_data, f)
        os.replace(STATUS_FILE + ".tmp", STATUS_FILE)
    except Exception as e:
        pass


def remove_pid_and_status():
    global lock_fd
    if lock_fd is not None:
        try:
            # Clear PID content while lock is held before releasing flock
            os.ftruncate(lock_fd, 0)
            os.lseek(lock_fd, 0, os.SEEK_SET)
            os.fsync(lock_fd)
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
        except Exception:
            pass
        lock_fd = None

    # DO NOT delete PID_FILE! Leave the lock file permanently in place on the filesystem.

    try:
        if os.path.exists(STATUS_FILE):
            os.remove(STATUS_FILE)
    except Exception:
        pass


def signal_handler(signum, frame):
    global is_running, dumpcap_proc
    print(f"\n[AI-NIDS Engine] Received signal {signum}. Shutting down cleanly...")
    is_running = False

    if dumpcap_proc and dumpcap_proc.poll() is None:
        try:
            dumpcap_proc.terminate()
            dumpcap_proc.wait(timeout=1.0)
        except Exception:
            pass

    # Flush any remaining flows
    try:
        check_expired_flows()
    except Exception:
        pass

    remove_pid_and_status()
    print("[AI-NIDS Engine] Shutdown complete.")
    sys.exit(0)


# =========================================================
# CAPTURE BACKEND WORKERS
# =========================================================

def native_capture_worker():
    """Dedicated worker thread for native Scapy packet capture."""
    global capture_backend_alive, capture_error, is_running
    try:
        capture_backend_alive = True
        capture_error = None
        write_status()
        sniff(
            iface=INTERFACE,
            prn=process_packet,
            store=False,
            stop_filter=lambda p: not is_running
        )
    except Exception as e:
        capture_backend_alive = False
        capture_error = f"Native sniff worker exception: {e}"
        write_status(mode_override="capture_failed", error_override=capture_error)
        print(f"[AI-NIDS Engine] {capture_error}")
        return

    # If sniff returned while engine is still marked running, worker terminated unexpectedly
    if is_running:
        capture_backend_alive = False
        if not capture_error:
            capture_error = "Native sniff worker terminated unexpectedly"
        write_status(mode_override="capture_failed", error_override=capture_error)
        print(f"[AI-NIDS Engine] {capture_error}")
    else:
        capture_backend_alive = False


def start_dumpcap_capture():
    """Wireshark dumpcap capture stream pipeline."""
    global dumpcap_proc, capture_backend_alive, capture_error, is_running
    try:
        cmd = ["dumpcap", "-i", INTERFACE, "-q", "-P", "-w", "-"]
        dumpcap_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL
        )
        time.sleep(0.08)
        poll_init = dumpcap_proc.poll()
        if poll_init is not None:
            capture_backend_alive = False
            capture_error = f"dumpcap failed to start on '{INTERFACE}' (exit code {poll_init})"
            write_status(mode_override="capture_failed", error_override=capture_error)
            print(f"[AI-NIDS Engine] {capture_error}")
            while is_running:
                time.sleep(1)
        else:
            capture_backend_alive = True
            capture_error = None
            write_status()

            reader = PcapReader(dumpcap_proc.stdout)
            for packet in reader:
                if not is_running:
                    break
                process_packet(packet)

            if is_running and dumpcap_proc and dumpcap_proc.poll() is not None:
                capture_backend_alive = False
                capture_error = f"dumpcap stream ended unexpectedly (exit code {dumpcap_proc.poll()})"
                write_status(mode_override="capture_failed", error_override=capture_error)
                print(f"[AI-NIDS Engine] {capture_error}")
                while is_running:
                    time.sleep(1)
    except Exception as e:
        capture_backend_alive = False
        capture_error = str(e)
        write_status(mode_override="capture_failed", error_override=capture_error)
        print(f"[AI-NIDS Engine] Packet capture stream error: {e}")
        while is_running:
            time.sleep(1)
    finally:
        if dumpcap_proc and dumpcap_proc.poll() is None:
            try:
                dumpcap_proc.terminate()
            except Exception:
                pass


# =========================================================
# MAIN LOOP
# =========================================================

def main():
    global is_running, capture_mode, dumpcap_proc, capture_thread, capture_backend_alive, capture_error

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # -----------------------------------------------------
    # FLOW CLEANUP THREAD (Runs independently with distinct heartbeat)
    # -----------------------------------------------------

    def cleanup_loop():
        global is_running, capture_backend_alive, capture_error, capture_thread, dumpcap_proc
        while is_running:
            time.sleep(1)
            try:
                # Detect if capture backend stopped unexpectedly
                if capture_mode == "native":
                    if capture_thread and not capture_thread.is_alive():
                        capture_backend_alive = False
                        if not capture_error:
                            capture_error = "Native capture worker thread terminated unexpectedly"
                        write_status(mode_override="capture_failed", error_override=capture_error)
                elif capture_mode == "dumpcap_stream":
                    if dumpcap_proc and dumpcap_proc.poll() is not None:
                        capture_backend_alive = False
                        if not capture_error:
                            capture_error = f"dumpcap subprocess terminated with exit code {dumpcap_proc.poll()}"
                        write_status(mode_override="capture_failed", error_override=capture_error)

                check_expired_flows()
                cleanup_scan_tracker()
                write_status()
            except Exception as e:
                pass

    cleanup_thread = Thread(
        target=cleanup_loop,
        name="FlowCleanupThread",
        daemon=True
    )
    cleanup_thread.start()

    # Initial status write
    write_status()

    # -----------------------------------------------------
    # PACKET CAPTURE INITIALIZATION
    # -----------------------------------------------------

    try:
        if CAPTURE_MODE_PARAM == "native":
            capture_mode = "native"
            capture_thread = Thread(target=native_capture_worker, name="NativeCaptureWorker", daemon=True)
            capture_thread.start()
            while is_running:
                time.sleep(0.5)
        elif CAPTURE_MODE_PARAM == "dumpcap":
            capture_mode = "dumpcap_stream"
            start_dumpcap_capture()
        else:
            # Auto mode: probe raw socket permission
            can_native = False
            try:
                import socket
                probe_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
                probe_sock.close()
                can_native = True
            except (AttributeError, PermissionError, OSError):
                can_native = False

            if can_native:
                capture_mode = "native"
                capture_thread = Thread(target=native_capture_worker, name="NativeCaptureWorker", daemon=True)
                capture_thread.start()
                while is_running:
                    time.sleep(0.5)
            else:
                print(f"[AI-NIDS Engine] Notice: Native raw socket requires elevated privileges.")
                print(f"[AI-NIDS Engine] Activating Wireshark dumpcap capture stream on interface '{INTERFACE}'...")
                capture_mode = "dumpcap_stream"
                start_dumpcap_capture()
    finally:
        remove_pid_and_status()


# =========================================================
# START
# =========================================================

if __name__ == "__main__":

    main()