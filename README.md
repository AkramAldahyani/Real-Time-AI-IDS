# 🛡️ AI-Enabled Network Intrusion Detection System

<div align="center">

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-RandomForest-F7931E?style=for-the-badge&logo=scikitlearn&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-Live%20Capture-009688?style=for-the-badge)
![Tkinter](https://img.shields.io/badge/Tkinter-GUI-blue?style=for-the-badge)
![Accuracy](https://img.shields.io/badge/Model%20Accuracy-99.99%25-brightgreen?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

**An end-to-end Machine Learning pipeline for real-time network intrusion detection — from isolated lab design and custom dataset generation to a trained Random Forest model and a live-capture GUI.**

[Overview](#-overview) • [Pipeline](#-full-pipeline) • [Dataset](#-dataset) • [Models](#-model-results) • [IDS Tool](#-ids-tool) • [Setup](#-setup--usage) • [Results](#-results)

</div>

---

## 📌 Overview

This project implements a complete **AI-powered Network Intrusion Detection System (NIDS)** built from scratch — including a custom isolated virtual lab, self-generated network traffic, a preprocessed and balanced dataset, five trained ML models, and a deployable Python IDS application with a real-time GUI.

The system classifies network flows as **Normal** or **Attack** (SYN flood / DDoS) with **99.99% accuracy** using a Random Forest classifier trained on 302,757 CICFlowMeter flow records generated entirely within a controlled lab environment.

### Key Highlights

- 🔬 **Custom dataset** — captured from a real isolated VirtualBox lab (not a public dataset)
- 🧠 **5 ML models** trained and compared — Random Forest selected as best
- ⚡ **Live IDS** — real-time packet capture, flow extraction, and classification
- 📊 **CSV analysis mode** — classify any CICFlowMeter-format CSV through the GUI
- 🎯 **99.99% accuracy** with balanced SMOTE training

---

## 🏗️ Full Pipeline

The project follows a complete end-to-end ML pipeline for cybersecurity:

```
┌─────────────────────────────────────────────────────────────────────┐
│                         FULL PIPELINE                               │
│                                                                     │
│  1. Lab Design        →   Isolated VirtualBox network topology      │
│  2. Traffic Gen       →   Normal + attack traffic generation        │
│  3. PCAP Capture      →   Wireshark / tcpdump on all interfaces     │
│  4. Feature Extract   →   CICFlowMeter: PCAP → 84-feature CSV       │
│  5. Preprocessing     →   Clean, select 17 features, SMOTE          │
│  6. Model Training    →   5 ML models trained and compared          │
│  7. IDS Deployment    →   Real-time GUI with live RF classification │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🖥️ Stage 1 — Lab Design & Network Topology

A fully isolated virtual lab was designed and built using **Oracle VirtualBox** with an **Internal Network adapter** (no internet, no host access) to ensure ethical and contained attack simulation.

### Virtual Machines

| VM | OS | Role | IP Address |
|----|-----|------|------------|
| **Attacker** | Kali Linux 2024 | Launches SYN floods, UDP floods, port scans using `hping3`, `nping` | `192.168.22.14` |
| **Target Server** | Windows Server 2022 | Hosts HTTP/SMB services — the attack target | `192.168.22.12` |
| **Normal Client** | Windows 10 | Generates benign browsing, file transfer, and SSH traffic | `192.168.22.10` |

### Network Topology

```
  ┌──────────────────────────────────────────────────┐
  │           VirtualBox Internal Network            │
  │              (192.168.22.0/24)                   │
  │                                                  │
  │   ┌──────────────┐      ┌──────────────────┐     │
  │   │  Kali Linux  │      │  Windows Server  │     │
  │   │  (Attacker)  │─────>│  2022 (Target)   │     │
  │   │ 192.168.22.14│      │  192.168.22.12   │     │
  │   └──────────────┘      └──────────────────┘     │
  │                                   ▲              │
  │   ┌──────────────┐                │              │
  │   │  Windows 10  │────────────────┘              │
  │   │  (Client)    │   Normal Traffic              │
  │   │ 192.168.22.10│                               │
  │   └──────────────┘                               │
  └──────────────────────────────────────────────────┘
```

> ⚠️ All attacks were conducted exclusively within this isolated environment. No external systems were affected.

---

## 🚦 Stage 2 — Traffic Generation

### Normal Traffic (Windows 10 → Windows Server)
Simulated realistic user behaviour using automated scripts:
- HTTP/HTTPS web requests via `curl` and browser automation
- File transfers (SMB/FTP)
- Ping and basic connectivity tests

### Attack Traffic (Kali Linux → Windows Server)
Two categories of attacks were simulated using Kali tools:

| Attack Type | Tool | Command |
|-------------|------|---------|
| **SYN Flood** | `hping3` | `sudo hping3 -S --flood -p 80 192.168.22.12` |
| **UDP Flood** | `nping` | `sudo nping --udp --rate 1000 -p 53 192.168.22.12` |
| **Port Scan** | `nmap` | `nmap -sS -p- 192.168.22.12` |

### Traffic Capture
All traffic was captured using **Wireshark** (packet capture to `.pcap`) then converted to flow-level CSV using **CICFlowMeter**, producing 84 network flow features per row.

---

## 🔧 Stage 3 — Feature Engineering & Preprocessing

### Feature Extraction
Raw PCAP files were processed through **CICFlowMeter** to extract flow-level features. From 84 available features, **17 were selected** based on their relevance to attack detection:

```python
keep_cols = [
    'Flow Duration',
    'Tot Fwd Pkts',     'Tot Bwd Pkts',
    'TotLen Fwd Pkts',  'TotLen Bwd Pkts',
    'Fwd Pkt Len Mean', 'Bwd Pkt Len Mean',
    'Fwd IAT Mean',     'Bwd IAT Mean',
    'Fwd Header Len',   'Bwd Header Len',
    'FIN Flag Cnt',     'SYN Flag Cnt',     'RST Flag Cnt',
    'PSH Flag Cnt',     'ACK Flag Cnt',     'URG Flag Cnt',
]
```

These features capture the most discriminative properties of SYN floods and DDoS attacks:
- **SYN Flag Cnt** — SYN floods show high SYN counts with no corresponding ACKs
- **Flow Duration** — attack micro-flows are extremely short
- **Tot Fwd/Bwd Pkts** — flood flows are often unidirectional
- **IAT (Inter-Arrival Time)** — flooding produces very regular, minimal inter-arrival times

### Preprocessing Steps

```
Raw CSV (302,757 rows × 84 cols)
        │
        ▼ Drop identity columns (Flow ID, IP, Port, Timestamp)
        ▼ Select 17 relevant features
        ▼ Replace Inf / -Inf → NaN
        ▼ Coerce all columns to numeric
        ▼ Drop columns with >50% missing
        ▼ Fill remaining NaN → 0
        │
        ▼ Train/Test Split  (70% / 30%, stratified)
        ▼ StandardScaler  (fit on train only)
        ▼ SMOTE  (balance: 142,776 Normal + 142,776 Attack)
        │
        ▼ Ready for model training
```

### Dataset Statistics

| Metric | Value |
|--------|-------|
| Total flows | 302,757 |
| Normal (Label=0) | 203,966 (67.4%) |
| Attack (Label=1) | 98,791 (32.6%) |
| Features used | 17 |
| Train size (after SMOTE) | 285,552 (balanced) |
| Test size | 90,828 |

---

## 🤖 Stage 4 — Model Training & Selection

Five ML models were implemented and compared:

### Model Results

| Model | Accuracy | Precision | Recall | F1-Score |
|-------|----------|-----------|--------|----------|
| **Random Forest** ✅ | **99.99%** | **1.00** | **1.00** | **1.00** |
| Decision Tree | 99.96% | 1.00 | 1.00 | 1.00 |
| XGBoost | 99.97% | 1.00 | 1.00 | 1.00 |
| K-Nearest Neighbours | 99.87% | 1.00 | 1.00 | 1.00 |
| Logistic Regression | 97.23% | 0.97 | 0.97 | 0.97 |

### Why Random Forest was selected

Random Forest was chosen as the final IDS model for several reasons:
- **Highest accuracy** (99.99%) on the held-out test set
- **Ensemble averaging** across 100 decision trees makes it robust to overfitting
- **No feature scaling sensitivity** — though we scale for consistency with training
- **Probability outputs** — `predict_proba()` gives confidence scores shown in the GUI
- **Interpretable** — feature importances can be extracted to explain decisions
- **Fast inference** — classifies flows in microseconds, suitable for real-time use

### Classification Report (Random Forest on test set)

```
              precision    recall  f1-score   support

      Normal       1.00      1.00      1.00     61190
      Attack       1.00      1.00      1.00     29638

    accuracy                           1.00     90828
   macro avg       1.00      1.00      1.00     90828
weighted avg       1.00      1.00      1.00     90828

Accuracy: 0.9999889901792399
```

---

## 🛡️ Stage 5 — IDS Tool

The trained model is deployed as a Python application with a **Tkinter GUI** supporting two operational modes:

### Mode 1 — Live Capture (`ids_main.py`)

Real-time packet capture using **Scapy**, flow extraction matching CICFlowMeter's methodology, and instant RF classification.

**Architecture:**
```
Live Packets (Scapy sniff)
        │
        ▼
  FlowManager
  ├─ Directional 5-tuple key (src_ip, src_port, dst_ip, dst_port, proto)
  ├─ Accumulates: lengths, IATs, TCP flags, header sizes
  ├─ Exports on: idle timeout (2s) | FIN/RST flag | 50-packet flood guard
        │
        ▼
  ClassifierWorker (background thread)
  ├─ Builds 17-feature vector in training order
  ├─ StandardScaler.transform()
  └─ RandomForest.predict() + predict_proba()
        │
        ▼
  Tkinter GUI (polls every 150ms)
  ├─ Colour-coded flow table (red=ATTACK, green=Normal)
  ├─ Live stats: Total / Normal / Attacks / Attack Rate
  └─ Timestamped alert log
```

**Key design decision — directional flow keys:**
CICFlowMeter treats each direction as its own flow. When `hping3 --flood` fires SYN probes with random source ports, each probe becomes a *separate* `FlowRecord` with `SYN=1, Fwd Pkts=1, Duration≈500µs` — exactly matching the attack pattern in the training data.

### Mode 2 — CSV Analysis (`ids_csv.py`)

Upload any CICFlowMeter-format CSV and classify all rows instantly. No live capture, no admin privileges required.

**Features:**
- File browser dialog
- Background processing thread (GUI stays responsive)
- Colour-coded results table with sorting
- Summary stats (Total / Normal / Attacks / Attack Rate)
- Export classified results as a new CSV

### GUI Screenshots

| Live Capture Mode | CSV Analysis Mode |
|:-----------------:|:-----------------:|
| Real-time flow table with red/green rows | Upload CSV → instant batch classification |
| Stats bar: Total / Normal / Attacks / Rate | Export results with Prediction + Confidence columns |

---


## ⚙️ Setup & Usage

### Prerequisites

- Python 3.9 or higher
- Windows: Run CMD as **Administrator** for live capture
- Linux/Kali: Run with **sudo** for live capture

### Installation

```bash
# Clone the repository
git clone https://github.com/AkramAldahyani/Real-Time-AI-IDS
cd ai-ids-project

# Install dependencies
pip install -r requirements.txt

# On Kali/Linux
pip install -r requirements.txt --break-system-packages
```

### Verify Model Pipeline

```bash
python ids_test.py
```

Expected output:
```
✓  ids_model.pkl    loaded  (RandomForestClassifier)
✓  ids_scaler.pkl   loaded  (StandardScaler)
✓  ids_features.pkl loaded  (17 features)
✓  Feature list matches the 17 training features exactly.
✓  Predicted: ATTACK   (99.x% conf)   [expected: ATTACK]
✓  Predicted: Normal   (99.x% conf)   [expected: Normal]
All checks passed.
```

### Run Live Capture IDS

```bash
# Linux / Kali
sudo python ids_main.py

# Windows (run CMD as Administrator)
python ids_main.py
```

1. Select your network interface from the dropdown
2. Click **▶ Start Capture**
3. Watch flows classified in real time — red rows = ATTACK, green = Normal
4. Click **■ Stop** when done

### Run CSV Analysis Mode

```bash
python ids_csv.py
```

1. Click **📂 Browse CSV** and select a CICFlowMeter `.csv` file
2. Click **▶ Classify**
3. View colour-coded results and summary statistics
4. Click **💾 Export Results CSV** to save predictions



---

## 🔧 Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `Missing: 'ids_model.pkl'` | .pkl files not found | Place all three `.pkl` files in the same directory as the `.py` script |
| `Permission denied` | Not running as root/Admin | `sudo python ids_main.py` on Linux; run CMD as Administrator on Windows |
| `No module named 'scapy'` | Scapy not installed | `pip install scapy --break-system-packages` |
| All flows show "Normal" during attack | Wrong interface selected | Select the interface on the same subnet as your lab VMs |
| `_tkinter` error on Kali | tkinter not installed | `sudo apt install python3-tk` |
| `No module named 'imbalanced_learn'` | imblearn not installed | `pip install imbalanced-learn --break-system-packages` |

---

## 📦 Dependencies

```
scapy>=2.5.0           # Packet capture and dissection
scikit-learn>=1.3.0    # Random Forest, StandardScaler
imbalanced-learn>=0.11.0  # SMOTE for class balancing
joblib>=1.3.0          # Model serialisation (.pkl)
numpy>=1.24.0          # Numerical computation
pandas>=2.0.0          # Data manipulation
```

---

## 👤 Author

Built as part of **IT8520 – Digital Transformation** coursework.

*End-to-end implementation: lab design → data generation → preprocessing → model training → IDS deployment.*

---