# IoT Threat Hunting Dashboard

> **Blue Team / SOC Portfolio Project** — Real-time IoT network threat detection using Machine Learning  
> RF Classifier · 7-class · CICIoT2023 · Streamlit · Suricata · Docker

---

## Overview

A full-stack threat hunting dashboard that classifies IoT network traffic into 7 attack categories using a Random Forest model trained on the CICIoT2023 dataset. Designed to simulate a Blue Team analyst workflow: ingest network flows, classify threats in real time, and visualize results.

**Live demo pipeline:**
```
Network Traffic → Suricata (IDS) → eve.json → Feature Bridge → RF Classifier → Streamlit Dashboard
```

---

## Features

| Feature | Description |
|---|---|
| **CSV Batch Analysis** | Upload any CICIoT2023 CSV → instant 7-class prediction on all flows |
| **Analytics Tab** | Traffic distribution, confidence histogram, class breakdown summary |
| **Live Monitor** | Auto-refresh every 10s from Suricata eve.json; demo mode if Suricata offline |
| **7-Class Detection** | DDoS · DoS · Recon · BruteForce · Mirai · Spoofing · BENIGN |
| **Confidence Scoring** | Per-flow probability scores for all 7 classes |

---

## Model Performance

| Metric | Value |
|---|---|
| Algorithm | Random Forest (n=300, max_depth=30) |
| Dataset | CICIoT2023 — 34 attack types → 7 classes |
| Training samples | ~987,000 flows |
| Test accuracy | **94%** |
| DDoS / DoS / Mirai F1 | **1.00** |
| BruteForce F1 | 0.67 |
| Features | 43 network flow features |

### Class Mapping (34 → 7)

```python
DDoS-*_Flood, DDoS-SlowLoris           → DDoS
DoS-*_Flood                             → DoS
Recon-*, VulnerabilityScan              → Recon
SqlInjection, XSS, BruteForce, ...     → BruteForce
Mirai-*, Backdoor_Malware               → Mirai
MITM-ArpSpoofing, DNS_Spoofing          → Spoofing
BenignTraffic                           → BENIGN
```

---

## Project Structure

```
IoT_Dashboard/
├── models/
│   └── rf_model_v3.pkl       # Trained RF bundle (model + encoder + features)
├── suricata/
│   └── logs/
│       └── eve.json          # Suricata output (live traffic)
├── data/processed/           # Sample CSVs for batch analysis
├── dashboard.py              # Streamlit app (3 tabs)
├── feature_bridge.py         # Model loader + predict_flow / predict_batch
├── parser.py                 # Suricata eve.json parser
├── test_bridge.py            # Unit tests for feature bridge
└── requirements.txt
```

---

## Tech Stack

- **Python 3.12** — core runtime
- **scikit-learn 1.6.1** — Random Forest classifier
- **Streamlit** — dashboard UI
- **Plotly** — interactive charts
- **Suricata 8.0.4** — network IDS (Docker)
- **Docker** — containerized Suricata deployment
- **WSL2 (Ubuntu)** — Linux network capture on Windows 11

---

## Quick Start

### Prerequisites
- Python 3.12
- Docker Desktop + WSL2 (Windows) or Docker (Linux)

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Run dashboard (CSV mode — no Suricata needed)
```powershell
cd C:\...\IoT_Dashboard
streamlit run dashboard.py
```
Open `http://localhost:8501` → upload any CICIoT2023 CSV → view predictions.

### 3. Run with live Suricata (WSL2)
```bash
# In WSL terminal
cd /mnt/c/Users/PC/OneDrive/Desktop/IoT_Dashboard

docker run -d \
  --name suricata-iot \
  --net=host \
  --cap-add net_admin \
  --cap-add sys_nice \
  -v "$(pwd)/suricata/logs:/var/log/suricata" \
  jasonish/suricata:latest \
  -i eth0 --init-errors-fatal no
```
Then open **Live Monitor** tab in dashboard → enable Auto-refresh.

---

## Dataset

**CICIoT2023** — Canadian Institute for Cybersecurity  
- 169 CSV files · ~2.77GB · 47 columns  
- 34 attack label types across IoT traffic scenarios  
- Source: [Kaggle — akashdogra/cic-iot-2023](https://www.kaggle.com/datasets/madhavmalhotra/unb-cic-iot-dataset)

---

## Key Design Decisions

**Why drop `Header_Length` and `IAT`?**  
`Header_Length` cannot be reliably estimated from Suricata flow logs. `IAT` (Inter-Arrival Time) showed near-identical mean (~8.3×10⁷) across all classes, indicating it captured noise rather than signal — removed to prevent overfitting.

**Why merge 34 labels into 7 classes?**  
Many sub-types (e.g. DDoS-ICMP_Flood vs DDoS-UDP_Flood) share identical feature distributions. Grouping them improves generalization and reflects real-world SOC triage categories.

**Why Random Forest over deep learning?**  
Interpretability matters in SOC environments. RF provides per-feature importance, runs inference in milliseconds on CPU, and achieves 94% accuracy without GPU requirements.

---

## Limitations & Future Work

- BruteForce F1 = 0.67 — overlaps with Recon feature space; planned improvement via sub-class separation
- Live Suricata capture limited to WSL2 `eth0` interface on Windows
- No real-time PCAP → CICFlowMeter feature extraction pipeline (next milestone)
- Model trained on lab-generated data; real-world deployment requires retraining on production traffic

