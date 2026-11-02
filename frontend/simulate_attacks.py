#!/usr/bin/env python3
"""
AI-NIDS Demo Attack Simulator
Inserts realistic network attacks into ../database/nids.db for live hackathon presentations.
Demonstrates:
  - DoS (SYN Flood / HTTP Flood)
  - DDoS (Distributed Volumetric Flood)
  - PORT SCAN (Nmap Reconnaissance Sweep)
  - Brute Force (SSH / RDP Credential Cracking)
  - BENIGN (Normal Web / DNS / API traffic)
"""

import sys
import os
import sqlite3
import random
import time
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "database", "nids.db")

ATTACK_TEMPLATES = [
    {
        "prediction": "DoS",
        "protocol": "TCP",
        "source_ip": lambda: f"192.168.1.{random.randint(100, 250)}",
        "source_port": lambda: random.randint(10000, 65000),
        "destination_ip": "10.223.112.75",
        "destination_port": 80,
        "packets": lambda: random.randint(120, 800),
        "bytes": lambda: random.randint(8000, 95000),
        "confidence": lambda: round(random.uniform(92.0, 99.8), 1),
        "detection_type": "SIMULATION"
    },
    {
        "prediction": "DDoS",
        "protocol": "UDP",
        "source_ip": lambda: f"{random.randint(45, 185)}.{random.randint(10, 220)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
        "source_port": lambda: random.randint(1024, 65535),
        "destination_ip": "10.223.112.75",
        "destination_port": 53,
        "packets": lambda: random.randint(1500, 14000),
        "bytes": lambda: random.randint(250000, 3500000),
        "confidence": lambda: round(random.uniform(96.5, 100.0), 1),
        "detection_type": "SIMULATION"
    },
    {
        "prediction": "PORT SCAN",
        "protocol": "TCP",
        "source_ip": lambda: f"172.16.4.{random.randint(10, 80)}",
        "source_port": lambda: random.randint(40000, 60000),
        "destination_ip": "10.223.112.75",
        "destination_port": lambda: random.choice([21, 22, 23, 25, 80, 110, 139, 443, 445, 3306, 3389, 8080]),
        "packets": lambda: random.randint(1, 8),
        "bytes": lambda: random.randint(40, 520),
        "confidence": lambda: round(random.uniform(88.0, 97.4), 1),
        "detection_type": "SIMULATION"
    },
    {
        "prediction": "Brute Force",
        "protocol": "TCP",
        "source_ip": lambda: f"198.51.100.{random.randint(5, 180)}",
        "source_port": lambda: random.randint(30000, 65000),
        "destination_ip": "10.223.112.75",
        "destination_port": 22,
        "packets": lambda: random.randint(35, 180),
        "bytes": lambda: random.randint(2400, 18500),
        "confidence": lambda: round(random.uniform(91.0, 99.2), 1),
        "detection_type": "SIMULATION"
    },
    {
        "prediction": "BENIGN",
        "protocol": lambda: random.choice(["TCP", "UDP"]),
        "source_ip": lambda: f"10.223.112.{random.randint(100, 220)}",
        "source_port": lambda: random.randint(30000, 60000),
        "destination_ip": "10.223.112.75",
        "destination_port": lambda: random.choice([53, 80, 443]),
        "packets": lambda: random.randint(4, 20),
        "bytes": lambda: random.randint(300, 3200),
        "confidence": lambda: 100.0,
        "detection_type": "SIMULATION"
    }
]

def get_connection():
    return sqlite3.connect(DB_PATH)

def insert_flow(template):
    conn = get_connection()
    c = conn.cursor()

    ts = datetime.now(timezone.utc).isoformat()
    src_ip = template["source_ip"]() if callable(template["source_ip"]) else template["source_ip"]
    src_port = template["source_port"]() if callable(template["source_port"]) else template["source_port"]
    dst_ip = template["destination_ip"]() if callable(template["destination_ip"]) else template["destination_ip"]
    dst_port = template["destination_port"]() if callable(template["destination_port"]) else template["destination_port"]
    protocol = template["protocol"]() if callable(template["protocol"]) else template["protocol"]
    packets = template["packets"]() if callable(template["packets"]) else template["packets"]
    bytes_count = template["bytes"]() if callable(template["bytes"]) else template["bytes"]
    prediction = template["prediction"]
    confidence = template["confidence"]() if callable(template["confidence"]) else template["confidence"]
    detection_type = template["detection_type"]

    c.execute("""
        INSERT INTO alerts (
            timestamp, source_ip, source_port, destination_ip,
            destination_port, protocol, packets, bytes,
            prediction, confidence, detection_type
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        ts, src_ip, src_port, dst_ip, dst_port, protocol,
        packets, bytes_count, prediction, confidence, detection_type
    ))
    flow_id = c.lastrowid
    conn.commit()
    conn.close()
    return flow_id, prediction, src_ip, dst_port

def run_burst(count=12):
    print(f"\n[+] Injecting burst of {count} mixed flows into nids.db...")
    # Bias towards attacks for presentation impact
    weights = [0.25, 0.25, 0.20, 0.20, 0.10]
    for _ in range(count):
        tmpl = random.choices(ATTACK_TEMPLATES, weights=weights)[0]
        flow_id, pred, src, port = insert_flow(tmpl)
        print(f"    --> Flow #{flow_id:03d} | [{pred:^11}] | Src: {src:<15} -> Target Port: {port}")
        time.sleep(0.1)
    print("\n[✓] Burst complete! Check dashboard at http://localhost:3000 to see live telemetry updates.")

def run_continuous(interval=2.5):
    print(f"\n[+] Starting continuous traffic simulation (Ctrl+C to stop)...")
    print(f"[+] Pushing 1 flow every ~{interval}s to demonstrate live dashboard reactions\n")
    weights = [0.22, 0.22, 0.18, 0.18, 0.20]
    try:
        while True:
            tmpl = random.choices(ATTACK_TEMPLATES, weights=weights)[0]
            flow_id, pred, src, port = insert_flow(tmpl)
            now_str = datetime.now().strftime("%H:%M:%S")
            print(f"[{now_str}] Injected Flow #{flow_id:03d} | {pred:<11} | {src} -> Port {port}")
            time.sleep(interval + random.uniform(-0.5, 0.8))
    except KeyboardInterrupt:
        print("\n[!] Simulation stopped.")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--loop":
        run_continuous()
    elif len(sys.argv) > 1 and sys.argv[1] == "--burst":
        count = int(sys.argv[2]) if len(sys.argv) > 2 else 15
        run_burst(count)
    else:
        print("=" * 60)
        print("  AI-NIDS DEMO ATTACK SIMULATOR")
        print("=" * 60)
        print("  1) Inject attack burst (12 flows - instant impact)")
        print("  2) Continuous live stream (pushes 1 flow every 2-3s)")
        print("  3) Exit")
        choice = input("\nSelect option [1-3] (default 1): ").strip()
        if choice == "2":
            run_continuous()
        elif choice == "3":
            sys.exit(0)
        else:
            run_burst(12)
