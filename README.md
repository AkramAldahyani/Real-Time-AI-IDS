# AI-Enabled Intrusion Detection System
### Real Time IDS 

---

## Project Context

This IDS is the final component of a complete AI cybersecurity pipeline:

| Stage | What was done |
|-------|--------------|
| Lab Design | Kali Linux (attacker) · Windows 10 (client) · Windows Server 2022 (target) on isolated internal network |
| Traffic Generation | Normal traffic from Windows 10; SYN/UDP flood attacks from Kali |
| Feature Extraction | CICFlowMeter converted PCAPs → CSV with 84 flow features |
| Preprocessing | Dropped identity columns, selected 17 features, cleaned NaN/Inf, applied SMOTE |
| Model Training | Trained 5 ML models; Random Forest achieved **99.99% accuracy** |
| **IDS** | **This tool – loads the trained RF model, captures live traffic, classifies flows in real-time** |

---

## File Structure

```
ids/
├── ids_main.py          ← Full IDS with live capture + Tkinter GUI  (PRIMARY SUBMISSION FILE)
├── ids_test.py          ← Headless test to verify model pipeline
├── requirements.txt     ← Python dependencies
├── README.md            ← This file
│
│   ── Produced by your ML training script ──
├── ids_model.pkl        ← Trained Random Forest model
├── ids_scaler.pkl       ← Fitted StandardScaler
└── ids_features.pkl     ← Ordered list of 17 feature names
```

> **All six files (three .py + three .pkl) must be in the same directory.**

---

## The 17 Features (must match training exactly)

```
Flow Duration, Tot Fwd Pkts, Tot Bwd Pkts,
TotLen Fwd Pkts, TotLen Bwd Pkts,
Fwd Pkt Len Mean, Bwd Pkt Len Mean,
Fwd IAT Mean, Bwd IAT Mean,
Fwd Header Len, Bwd Header Len,
FIN Flag Cnt, SYN Flag Cnt, RST Flag Cnt,
PSH Flag Cnt, ACK Flag Cnt, URG Flag Cnt
```

These are identical to the features selected in the training script (`keep_cols` in the ML code).

---

## Installation

### Step 1 – Python version
Requires **Python 3.9 or higher**.  Verify:
```bash
python --version
```

### Step 2 – Install dependencies

**Linux / Kali (recommended for live capture):**
```bash
pip install -r requirements.txt --break-system-packages
```

**Windows (run CMD as Administrator):**
```cmd
pip install -r requirements.txt
```

### Step 3 – Verify .pkl files are present
```
ids_model.pkl
ids_scaler.pkl
ids_features.pkl
```
These are produced by running the training script (`ids_train.py` / your ML notebook).  Copy them into the same folder as the IDS `.py` files.

### Step 4 – Verify everything with the test script (no root needed)
```bash
python ids_test.py
```
Expected output:
```
✓  ids_model.pkl    loaded
✓  ids_scaler.pkl   loaded
✓  ids_features.pkl loaded
✓  Feature list matches the 17 training features exactly.
✓  Predicted: ATTACK   (99.x% conf)   [expected: ATTACK]
✓  Predicted: Normal   (99.x% conf)   [expected: Normal]
All checks passed.
```

---

## Running the IDS

### Full Live Capture (requires root / Administrator)

**On Kali Linux (monitoring your lab):**
```bash
sudo python ids_main.py
```

**On Windows Server (monitoring from the target):**
```
Right-click CMD → "Run as administrator"
python ids_main.py
```

## How to Use the GUI

1. **Launch** the application with the command above.
2. **Select interface** from the dropdown:
   - On Kali/Linux: typically `eth0` or `ens33` (the interface on your lab network)
   - On Windows: look for "Ethernet" or "Local Area Connection" names
3. **Click "▶ Start Capture"** – the status indicator turns green.
4. Watch the **flow table** populate with classified flows.
   - Green rows = **Normal** traffic
   - Red rows = **ATTACK** detected
5. Watch the **Alert Log** at the bottom for timestamped attack warnings.
6. **Stats bar** at the top shows Total Flows / Normal / Attacks / Attack Rate live.
7. **Click "■ Stop"** when done.  **"🗑 Clear"** resets the display.

---

## Selecting the Correct Network Interface

### On Kali Linux
```bash
ip a         # list all interfaces
```
Look for the interface connected to your internal/host-only network, e.g.:
- `eth0` – most common in VirtualBox
- `ens33` / `ens34` – VMware
- `enp0s3` – VirtualBox alternative

Use that exact name in the dropdown.

### On Windows
Open Device Manager → Network Adapters, or:
```cmd
ipconfig /all
```
The IDS dropdown will show the same names as Scapy detects (e.g., `\Device\NPF_{GUID}`).


---

## Common Errors and Fixes

| Error | Cause | Fix |
|-------|-------|-----|
| `FileNotFoundError: Missing artifact: 'ids_model.pkl'` | .pkl files not in same folder | Copy all three .pkl files next to ids_main.py |
| `Permission denied` / `Operation not permitted` | Not running as root/Admin | Run with `sudo` on Linux; "Run as administrator" on Windows |
| `ImportError: No module named 'scapy'` | Scapy not installed | `pip install scapy --break-system-packages` |
| `No interfaces listed` | Scapy not installed or no permissions | Install scapy and run as root |
| GUI does not open / `_tkinter` error | tkinter not installed | `sudo apt install python3-tk` on Kali |
| Flows appear but all predicted "Normal" | Wrong interface selected | Make sure you pick the interface on the same subnet as your lab VMs |
| `ImportError: cannot import name 'SMOTE'` | imbalanced-learn not installed | `pip install imbalanced-learn --break-system-packages` |

---

## Architecture Overview

```
Live Packets (Scapy sniff)
        │
        ▼
  FlowManager              ← Groups packets into bidirectional flows by 5-tuple
  (per-flow stats)         ← Tracks packet lengths, IATs, TCP flag counts
        │
        │  (flow expires after 5s idle)
        ▼
  flow_queue (Queue)
        │
        ▼
  ClassifierWorker         ← Background thread
        │
        ├─ Build 17-feature vector (same order as training)
        ├─ Apply StandardScaler (loaded from ids_scaler.pkl)
        └─ Random Forest predict (loaded from ids_model.pkl)
                │
                ▼
         gui_queue (Queue)
                │
                ▼
        Tkinter GUI          ← Polls every 200ms, updates table + log + stats
```

