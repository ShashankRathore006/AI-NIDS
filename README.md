# AI-NIDS: AI-Powered Network Intrusion Detection System

An enterprise-grade, machine-learning-driven Network Intrusion Detection System built with real-time packet telemetry, bidirectional flow aggregation, random forest attack classification, and an Editorial Light single-page operations console.

---

## Architecture Overview

```
                                      +-------------------------+
                                      |   Live Network Interface |
                                      |     (Scapy Sniffer)     |
                                      +------------+------------+
                                                   |
                                                   v
                                      +-------------------------+
                                      | Bidirectional Flow      |
                                      | Assembler & Feature Ext |
                                      +------------+------------+
                                                   |
                                                   v
+------------------------+            +-------------------------+
| Trained Random Forest  | ---------> | Attack Classification   |
| Model (CICIDS2017)     |            | (5 Traffic Classes)     |
+------------------------+            +------------+------------+
                                                   |
                                                   v
                                      +-------------------------+
                                      | SQLite Persistent Store |
                                      |      (database/nids.db) |
                                      +------------+------------+
                                                   |
                                                   v
                                      +-------------------------+
                                      |  FastAPI Backend (8000) |
                                      +------------+------------+
                                                   |
                                                   v
                                      +-------------------------+
                                      | Unified Editorial Light |
                                      | Frontend Console (3000) |
                                      +-------------------------+
```

---

## Directory Structure

```
AI-NIDS/
├── backend/
│   └── main.py                 # FastAPI REST API (stats, alerts, flows, DEFCON risk)
├── capture/
│   ├── flow.py                 # 5-tuple flow object & bidirectional metrics
│   ├── flow_tracker.py         # Real-time stateful flow tracking & timeout reaper
│   ├── packet_capture.py       # Scapy live interface packet sniffer
│   └── test_flow.py            # Unit tests for flow reconstruction
├── database/
│   ├── db.py                   # SQLite schema & query interfaces
│   └── nids.db                 # Operational flow & alert database
├── datasets/
│   └── processed/
│       └── nids_5class.csv     # 65,000-sample balanced CICIDS2017 dataset
├── frontend/
│   ├── index.html              # Unified 6-page operational web application
│   ├── styles.css              # Editorial Light visual design system
│   ├── app.js                  # SPA Router, Chart.js managers, Audio synth, Triage
│   ├── server.py               # Zero-dependency Python SPA HTTP server (port 3000)
│   ├── simulate_attacks.py     # Attack burst generator for testing & demo
│   ├── package.json            # Node metadata & scripts
│   ├── README.md               # Frontend-specific architecture documentation
│   ├── vendor/
│   │   └── chart.umd.min.js    # Bundled Chart.js library (no external CDN required)
│   └── showcase/               # Editorial research & architecture showcase site
│       ├── index.html
│       ├── how-it-works.html
│       ├── results.html
│       ├── technology.html
│       ├── about.html
│       └── serve.py            # Showcase server (port 3001)
├── ml/
│   ├── train_model.py          # Random Forest model training pipeline
│   ├── test_model.py           # Evaluation script generating confusion matrix & metrics
│   ├── prepare_dataset.py      # CICIDS2017 balance & preprocessing script
│   ├── inspect_dataset.py      # Column & data distribution inspector
│   └── count_labels.py         # Label frequency verification
├── models/
│   └── nids_random_forest.pkl  # Trained Random Forest classifier (99.74% accuracy)
├── requirements.txt            # Python dependencies
├── start_all.sh                # Single script to launch backend & frontend
├── start_backend.sh            # Launch FastAPI backend on port 8000
├── start_frontend.sh           # Launch frontend server on port 3000
└── simulate_traffic.sh         # Generate live attack bursts for demonstration
```

---

## Classification Classes & Model Evaluation

Trained and evaluated on the **CICIDS2017** benchmark dataset (65,000 samples, 13,000 per class; 20% stratified test split of 13,000 samples):

| Attack Class | Precision | Recall | F1-Score | Status |
| :--- | :--- | :--- | :--- | :--- |
| **BENIGN** | 0.9931 | 0.9954 | 0.9942 | Normal baseline |
| **DoS** | 0.9961 | 0.9935 | 0.9948 | High volume SYN/UDP floods |
| **DDoS** | 0.9988 | 0.9996 | 0.9992 | Distributed denial-of-service |
| **PORT SCAN** | 0.9988 | 0.9988 | 0.9988 | Reconnaissance sweeps |
| **BRUTE FORCE** | 1.0000 | 0.9996 | 0.9998 | SSH/FTP credential stuffing |
| **Overall Macro Avg** | **0.9974** | **0.9974** | **0.9974** | **99.74% Test Accuracy** |

---

## Unified Frontend Operations Console (6 Pages)

The frontend adopts a bespoke **Editorial Light** aesthetic (`#F8F8F5` canvas, `#191C20` primary ink, `#245B85` accent, Inter and IBM Plex Mono typography) providing 6 operational modules:

1. **Page 1: Overview** (`/#/overview`)  
   High-level SOC posture, real-time telemetry counters, live attack distribution doughnut chart, and incident triage table.
2. **Page 2: Live SOC Dashboard** (`/#/soc`)  
   Active operations center with dynamic DEFCON risk meter (0–100), packets/sec timeline, live attack classification telemetry, audio chimes (Web Audio API), and quick pause/resume controls.
3. **Page 3: Network Traffic** (`/#/traffic`)  
   Full socket flow inspection table showing source/destination IPs, ports, protocol badges, packet size, volume, and search filters.
4. **Page 4: Threat Detection** (`/#/threats`)  
   Dedicated multi-class detection view with class-based filtering, ML confidence scores, detection attribution, and forensic inspection modals.
5. **Page 5: Alerts & Incidents** (`/#/alerts`)  
   Incident triage console with one-click "Acknowledge" state tracking, status filters, and forensic drill-down modal displaying full flow metrics.
6. **Page 6: Analytics & Reports** (`/#/analytics`)  
   Strictly decoupled telemetry analytics (live protocol breakdown and hourly volumes) alongside verified offline CICIDS2017 confusion matrix and benchmark performance metrics.

---

## Quickstart Guide

### 1. Environment Setup

Install the required Python packages into your environment:

```bash
pip install -r requirements.txt
```

### 2. Launch Services

#### Option A: One-Command Startup
```bash
./start_all.sh
```

#### Option B: Individual Service Launch
Start backend:
```bash
./start_backend.sh
```
*(Runs FastAPI on http://localhost:8000)*

Start frontend:
```bash
./start_frontend.sh
```
*(Runs unified console on http://localhost:3000)*

### 3. Generate Simulated Attack Traffic
To simulate live incoming attack packets and observe the SOC dashboard detect threats in real time:
```bash
./simulate_traffic.sh
# or specify burst count:
python3 frontend/simulate_attacks.py --burst 20
```

---

## License & Attribution

Designed and engineered for cybersecurity research, SOC operations demonstration, and academic evaluation.
