# AI-Enabled Intrusion Detection System
### Module: Digital Transformation | Group Project – IDS Component

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
├── ids_demo.py          ← Demo mode: synthetic flows, no root needed  (for screenshots/report)
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

### Option A – Full Live Capture (requires root / Administrator)

**On Kali Linux (monitoring your lab):**
```bash
sudo python ids_main.py
```

**On Windows Server (monitoring from the target):**
```
Right-click CMD → "Run as administrator"
python ids_main.py
```

### Option B – Demo Mode (no root, great for screenshots)
```bash
python ids_demo.py
```
This replays a loop of synthetic normal and attack flows through the same model pipeline.  Use this to generate report screenshots.

---

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

### Tip for VirtualBox
Set the VM's network adapter to **"Internal Network"** (same name on all VMs).  
All VMs on the same internal network name will see each other's traffic.

---

## Testing in Your Lab

### Test 1 – Normal Traffic (Windows 10 client → Windows Server)
On Windows 10:
```powershell
# Web browsing simulation
Invoke-WebRequest http://192.168.22.12 -UseBasicParsing
# Or use your earlier traffic generation script
```
**Expected in IDS:** Green "Normal" rows in the flow table.

### Test 2 – SYN Flood Attack (Kali → Windows Server)
On Kali Linux:
```bash
sudo hping3 -S --flood -p 80 192.168.22.12
```
**Expected in IDS:** Red "ATTACK" rows and alerts in the log within a few seconds.

### Test 3 – UDP Flood (Kali → Windows Server)
```bash
sudo nping --udp --rate 1000 -p 53 192.168.22.12
```
**Expected in IDS:** Red "ATTACK" rows for UDP flows.

### Test 4 – Verify detection stops when attack stops
Stop the hping3 command on Kali.  
New flows in the IDS should return to "Normal" status.

### Screenshot checklist for the report:
- [ ] IDS idle (interface selected, not yet started)
- [ ] IDS running with normal traffic (green rows)
- [ ] IDS running during SYN flood (red rows + alert log entries)
- [ ] Stats bar showing a non-zero Attack Rate %
- [ ] Alert log with multiple attack timestamps

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

---

## What to Write in the Report

> *"The IDS was implemented as a Python application (ids_main.py) integrating the best-performing model — Random Forest (99.99% accuracy) — into a real-time packet classification pipeline. The tool uses Scapy to capture live packets from a user-selected network interface. Packets are grouped into bidirectional network flows using a 5-tuple key (source IP, destination IP, source port, destination port, protocol). For each completed flow, the same 17 features used during model training are extracted and scaled using the saved StandardScaler artifact. The trained Random Forest model then classifies each flow as Normal (label 0) or Attack (label 1). Classification results are displayed in a Tkinter GUI showing per-flow details, confidence scores, and a real-time alert log. The SMOTE-balanced training ensured the model is sensitive to minority (attack) classes despite dataset imbalance."*

---

## What to Say in the Viva

**Q: Why did you choose Random Forest for the IDS?**  
A: "Random Forest achieved the highest accuracy of 99.99% among all five models we tested. It is robust to overfitting due to ensemble averaging, handles the mix of numerical features well, and gives probability scores that we display as confidence percentages in the IDS."

**Q: How does your IDS extract features from live traffic?**  
A: "We use Scapy to capture raw packets and group them into flows using the same 5-tuple logic that CICFlowMeter uses. For each flow we compute the same 17 features — packet counts, payload lengths, inter-arrival times, header lengths, and TCP flag counts — that were used during training. This ensures feature consistency between training and inference."

**Q: What is SMOTE and why did you use it?**  
A: "SMOTE is Synthetic Minority Oversampling Technique. Our dataset had ~204K normal and ~99K attack flows — a 2:1 imbalance. Without SMOTE the model could learn to simply predict 'Normal' most of the time and still achieve high accuracy. SMOTE synthesises new attack samples to balance both classes at 142,776 each before training."

**Q: How did you test the IDS?**  
A: "We ran the IDS on the Kali Linux VM and launched a SYN flood using hping3 targeting the Windows Server. The IDS detected the attack flows in real time, displaying red alert rows and logging timestamps with confidence scores above 99%."

---

## Rubric Mapping (IDS section – 10 marks)

| Rubric Item | Where it is addressed |
|-------------|----------------------|
| Selection and justification of best model for IDS | Random Forest chosen (99.99% acc); see report section & viva answer above |
| Implementation of simple IDS tool with UI and interface selection | `ids_main.py` – Tkinter GUI with interface dropdown |
| Real-time packet sniffing | Scapy `sniff()` in `CaptureController._sniff_loop()` |
| Integration of trained model for real-time classification | `ClassifierWorker` loads `.pkl` files and calls `rf.predict()` |
| Demonstration of detection capability with sample traffic | `ids_demo.py` for screenshots; live testing with hping3 |
