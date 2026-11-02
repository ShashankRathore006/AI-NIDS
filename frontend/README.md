# AI-NIDS // Autonomous Network Intrusion Detection System

A unified, functional web application for real-time network intrusion detection, flow analysis, and security incident management.

Engineered with the **Editorial Light** design system (`#F8F8F5`, `#191C20`, `#245B85`, `#DCDDDA`, Inter, and IBM Plex Mono).

---

## ⚡ Quick Start

### 1. Launch FastAPI Backend
The backend service runs on `http://localhost:8000`:
```bash
cd backend
python3 -m uvicorn main:app --port 8000
```

### 2. Launch Frontend Application
The unified application server runs on `http://localhost:3000`:
```bash
cd frontend
python3 server.py
```

Open your browser to:
👉 **[http://localhost:3000](http://localhost:3000)**

### 3. Simulate Network Attacks (Optional Demo Stream)
Inject realistic flow vectors into `database/nids.db`:
```bash
python3 simulate_attacks.py --burst 15
```
*(Or continuous background loop: `python3 simulate_attacks.py --loop`)*

---

## 🎯 Unified Application Pages (Six Core Features)

All pages are integrated into ONE unified single-page application with synchronized state and live polling:

1. **Overview (`/#/overview`)**:
   - Executive & operational defense posture.
   - Network monitoring status (`wlan0/eth0`, Scapy `store=False`).
   - Flow metrics: Total flows, total packets, total detected threats, threat ratio.
   - Attack class distribution breakdown across the 5 target classes.
   - Latest security incidents feed with quick inspection.

2. **Live SOC Dashboard (`/#/soc`)**:
   - High-density tactical defense console.
   - Perimeter Threat Posture: Real-time DEFCON score (0–100) and 5-tier segmented risk meter.
   - Live Ingress Velocity timeline chart & Traffic distribution donut chart.
   - Live Alerts table with multi-criteria search, category filters, and row flash on incoming alerts.
   - Recent detections feed with tactical threat cards.
   - One-click CSV and JSON export.

3. **Network Traffic Analysis (`/#/traffic`)**:
   - Deep conversational flow analysis.
   - Protocol share: TCP, UDP, ICMP distribution.
   - Cumulative volume (bytes, packets, average packet size).
   - Real-time flow table with bidirectional packet and byte counters, flow rates, and socket pairs.
   - Protocol and volume filtering.

4. **Threat Detection (`/#/threats`)**:
   - Dedicated attack classification and machine learning inference analysis.
   - 5 detection classes breakdown: `BENIGN`, `DoS`, `DDoS`, `PORT SCAN`, and `BRUTE FORCE`.
   - Model telemetry: Random Forest (100 trees), 14 statistical features, <10ms CPU inference.
   - Attack classification feed with confidence scores and detection method (`ML` vs `BEHAVIOR`).

5. **Alerts & Incidents (`/#/alerts`)**:
   - Security incident management and triage.
   - Acknowledgment tracking (mark individual or all incidents as reviewed).
   - Multi-criteria filtering by confidence threshold, detection engine, and attack vector.
   - Incident export to CSV / JSON for SIEM integration.

6. **Analytics & Reports (`/#/analytics`)**:
   - Operational telemetry: Live attack distribution bar chart, protocol breakdown, and threat velocity.
   - Offline Model Evaluation (strictly separated from live traffic):
     - Accuracy: **99.74%** on 65,000 balanced CICIDS2017 samples (13,000 test split).
     - Verified Precision, Recall, and F1-Score table per class.
     - Verified 5×5 Confusion Matrix.
     - Documented findings (multi-device DDoS class-overlap and live feature reconstruction gap).
   - One-click security report export.

---

## 🛠️ Technology Stack

- **Ingestion**: Scapy (promiscuous socket frame sniffing, `store=False`)
- **Flow Engine**: In-memory bidirectional 5-tuple hash tracker & 10s sliding window
- **Feature Extraction**: 14 statistical indicators matching CICIDS2017 schema
- **Machine Learning**: scikit-learn Random Forest (100 estimators, CPU execution)
- **API Service**: FastAPI + Uvicorn ASGI (`/api/stats`, `/api/alerts`, `/api/alerts/recent-attacks`)
- **Persistence**: SQLite (`database/nids.db`, 12-column structured schema)
- **Frontend**: Vanilla ES6+, HTML5, CSS3, Chart.js (Zero node build step required)
