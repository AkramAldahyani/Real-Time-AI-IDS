"""
AI-Enabled Intrusion Detection System
===============================================
Random Forest–based IDS with real-time packet capture and a Tkinter GUI.

Requirements:
    pip install scapy scikit-learn imbalanced-learn joblib numpy pandas
    (scapy requires root / Administrator privileges for live capture)

Usage:
    sudo python ids_main.py          # Linux / Kali
    python ids_main.py               # Windows (run as Administrator)
"""

import warnings
warnings.filterwarnings("ignore")

import os
import sys
import time
import threading
import queue
import joblib
import numpy as np
import pandas as pd
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from collections import defaultdict
from datetime import datetime

# ── Scapy imports ─────────────────────────────────────────────────────────────
try:
    from scapy.all import sniff, get_if_list, IP, TCP, UDP, conf
    conf.verb = 0          # suppress scapy noise
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 – MODEL LOADING
# ══════════════════════════════════════════════════════════════════════════════

MODEL_FILE    = "ids_model.pkl"
SCALER_FILE   = "ids_scaler.pkl"
FEATURES_FILE = "ids_features.pkl"

def load_artifacts():
    """
    Load the pre-trained Random Forest model, StandardScaler, and
    the ordered list of feature names that were used during training.
    Returns (model, scaler, feature_names) or raises FileNotFoundError.
    """
    for f in (MODEL_FILE, SCALER_FILE, FEATURES_FILE):
        if not os.path.exists(f):
            raise FileNotFoundError(
                f"Missing artifact: '{f}'\n"
                "Place ids_model.pkl, ids_scaler.pkl, and ids_features.pkl "
                "in the same directory as ids_main.py"
            )
    model    = joblib.load(MODEL_FILE)
    scaler   = joblib.load(SCALER_FILE)
    features = joblib.load(FEATURES_FILE)
    return model, scaler, features


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 – FLOW TRACKER
# ══════════════════════════════════════════════════════════════════════════════

# Flows are keyed by the 5-tuple (src_ip, dst_ip, src_port, dst_port, proto).
# We accumulate per-packet stats and periodically compute the 17 features that
# match what the Random Forest was trained on.

FLOW_TIMEOUT = 5.0          # seconds of inactivity before a flow is exported

FEATURE_NAMES = [
    'Flow Duration',
    'Tot Fwd Pkts', 'Tot Bwd Pkts',
    'TotLen Fwd Pkts', 'TotLen Bwd Pkts',
    'Fwd Pkt Len Mean', 'Bwd Pkt Len Mean',
    'Fwd IAT Mean', 'Bwd IAT Mean',
    'Fwd Header Len', 'Bwd Header Len',
    'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt',
    'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt',
]


class FlowRecord:
    """Accumulates statistics for a single network flow."""

    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto, ts):
        self.src_ip    = src_ip
        self.dst_ip    = dst_ip
        self.src_port  = src_port
        self.dst_port  = dst_port
        self.proto     = proto
        self.start_ts  = ts
        self.last_ts   = ts

        # Forward = src → dst direction
        self.fwd_pkts       = []    # (timestamp, payload_len, header_len)
        self.bwd_pkts       = []

        # Flag counters (TCP only)
        self.fin_cnt = self.syn_cnt = self.rst_cnt = 0
        self.psh_cnt = self.ack_cnt = self.urg_cnt = 0

    # ── Packet ingestion ──────────────────────────────────────────────────────

    def add_packet(self, ts, is_fwd, payload_len, header_len, flags):
        self.last_ts = ts
        pkt_info = (ts, payload_len, header_len)
        if is_fwd:
            self.fwd_pkts.append(pkt_info)
        else:
            self.bwd_pkts.append(pkt_info)

        # Accumulate TCP flags
        if flags is not None:
            if flags & 0x01: self.fin_cnt += 1
            if flags & 0x02: self.syn_cnt += 1
            if flags & 0x04: self.rst_cnt += 1
            if flags & 0x08: self.psh_cnt += 1
            if flags & 0x10: self.ack_cnt += 1
            if flags & 0x20: self.urg_cnt += 1

    # ── Feature extraction ────────────────────────────────────────────────────

    @staticmethod
    def _mean_iat(timestamps):
        """Mean inter-arrival time across a list of packet timestamps."""
        if len(timestamps) < 2:
            return 0.0
        iats = [timestamps[i+1] - timestamps[i]
                for i in range(len(timestamps)-1)]
        return float(np.mean(iats)) * 1e6   # convert seconds → microseconds

    def to_feature_vector(self):
        """
        Return a dict with the 17 features used during training.
        Units match what CICFlowMeter produces:
          - durations in microseconds
          - lengths in bytes
        """
        duration = max((self.last_ts - self.start_ts) * 1e6, 1.0)

        fwd_ts   = [p[0] for p in self.fwd_pkts]
        bwd_ts   = [p[0] for p in self.bwd_pkts]
        fwd_lens = [p[1] for p in self.fwd_pkts]
        bwd_lens = [p[1] for p in self.bwd_pkts]
        fwd_hdr  = [p[2] for p in self.fwd_pkts]
        bwd_hdr  = [p[2] for p in self.bwd_pkts]

        tot_fwd_len = sum(fwd_lens)
        tot_bwd_len = sum(bwd_lens)

        fwd_pkt_mean = float(np.mean(fwd_lens)) if fwd_lens else 0.0
        bwd_pkt_mean = float(np.mean(bwd_lens)) if bwd_lens else 0.0

        fwd_iat_mean = self._mean_iat(fwd_ts)
        bwd_iat_mean = self._mean_iat(bwd_ts)

        fwd_hdr_total = sum(fwd_hdr)
        bwd_hdr_total = sum(bwd_hdr)

        return {
            'Flow Duration':   duration,
            'Tot Fwd Pkts':    len(self.fwd_pkts),
            'Tot Bwd Pkts':    len(self.bwd_pkts),
            'TotLen Fwd Pkts': tot_fwd_len,
            'TotLen Bwd Pkts': tot_bwd_len,
            'Fwd Pkt Len Mean': fwd_pkt_mean,
            'Bwd Pkt Len Mean': bwd_pkt_mean,
            'Fwd IAT Mean':    fwd_iat_mean,
            'Bwd IAT Mean':    bwd_iat_mean,
            'Fwd Header Len':  fwd_hdr_total,
            'Bwd Header Len':  bwd_hdr_total,
            'FIN Flag Cnt':    self.fin_cnt,
            'SYN Flag Cnt':    self.syn_cnt,
            'RST Flag Cnt':    self.rst_cnt,
            'PSH Flag Cnt':    self.psh_cnt,
            'ACK Flag Cnt':    self.ack_cnt,
            'URG Flag Cnt':    self.urg_cnt,
        }


class FlowManager:
    """
    Maintains a table of active FlowRecords, accepts incoming packets,
    and pushes completed flows to a results queue for classification.
    """

    def __init__(self, result_queue):
        self.flows   = {}           # flow_key → FlowRecord
        self.result_q = result_queue

    # ── Key construction ──────────────────────────────────────────────────────

    @staticmethod
    def _flow_key(src_ip, dst_ip, src_port, dst_port, proto):
        """Bidirectional flow key (canonical order)."""
        a = (src_ip, src_port)
        b = (dst_ip, dst_port)
        if a > b:
            a, b = b, a
        return (*a, *b, proto)

    # ── Packet processing ─────────────────────────────────────────────────────

    def process_packet(self, pkt):
        """Extract fields from a Scapy packet and feed them to the flow table."""
        if not pkt.haslayer(IP):
            return

        ip    = pkt[IP]
        proto = ip.proto
        ts    = float(pkt.time)

        src_ip, dst_ip = ip.src, ip.dst
        src_port = dst_port = 0
        flags    = None
        header_len = len(ip) - len(ip.payload)   # IP header length

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_port, dst_port = tcp.sport, tcp.dport
            flags = int(tcp.flags)
            header_len += tcp.dataofs * 4         # add TCP header length
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            src_port, dst_port = udp.sport, udp.dport
            header_len += 8                       # UDP header is fixed 8 bytes

        payload_len = len(ip.payload)
        key = self._flow_key(src_ip, dst_ip, src_port, dst_port, proto)

        if key not in self.flows:
            self.flows[key] = FlowRecord(
                src_ip, dst_ip, src_port, dst_port, proto, ts
            )

        flow = self.flows[key]
        is_fwd = (src_ip == flow.src_ip and src_port == flow.src_port)
        flow.add_packet(ts, is_fwd, payload_len, header_len, flags)

    def expire_flows(self, now):
        """Export and remove flows that have been idle longer than FLOW_TIMEOUT."""
        expired = [k for k, f in self.flows.items()
                   if (now - f.last_ts) >= FLOW_TIMEOUT]
        for key in expired:
            flow = self.flows.pop(key)
            self.result_q.put(flow)

    def flush_all(self):
        """Export all remaining flows (called when capture stops)."""
        for flow in self.flows.values():
            self.result_q.put(flow)
        self.flows.clear()


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 – CLASSIFIER WORKER
# ══════════════════════════════════════════════════════════════════════════════

class ClassifierWorker(threading.Thread):
    """
    Background thread that reads FlowRecord objects from a queue,
    builds the feature vector, scales it, and classifies it with
    the Random Forest model.  Results are forwarded to the GUI queue.
    """

    def __init__(self, model, scaler, feature_names, flow_queue, gui_queue):
        super().__init__(daemon=True)
        self.model         = model
        self.scaler        = scaler
        self.feature_names = feature_names
        self.flow_queue    = flow_queue
        self.gui_queue     = gui_queue

    def run(self):
        while True:
            try:
                flow = self.flow_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            if flow is None:          # poison pill → stop
                break

            feat_dict = flow.to_feature_vector()

            # Align features with training order; fill any missing with 0
            row = [feat_dict.get(f, 0.0) for f in self.feature_names]
            X   = np.array(row, dtype=float).reshape(1, -1)

            # Replace any inf / nan that might slip through
            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

            X_scaled = self.scaler.transform(X)
            pred     = self.model.predict(X_scaled)[0]
            proba    = self.model.predict_proba(X_scaled)[0]

            label    = "ATTACK" if int(pred) == 1 else "Normal"
            conf_pct = float(max(proba)) * 100

            result = {
                "time":     datetime.now().strftime("%H:%M:%S"),
                "src":      f"{flow.src_ip}:{flow.src_port}",
                "dst":      f"{flow.dst_ip}:{flow.dst_port}",
                "proto":    flow.proto,
                "pkts":     len(flow.fwd_pkts) + len(flow.bwd_pkts),
                "label":    label,
                "conf":     conf_pct,
                "features": feat_dict,
            }
            self.gui_queue.put(result)
            self.flow_queue.task_done()


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4 – CAPTURE CONTROLLER
# ══════════════════════════════════════════════════════════════════════════════

class CaptureController:
    """
    Manages the Scapy sniff thread, the FlowManager, and the periodic
    expiry timer.  Decoupled from the GUI so it can also be used headlessly.
    """

    def __init__(self, iface, flow_queue):
        self.iface      = iface
        self.flow_queue = flow_queue
        self.manager    = FlowManager(flow_queue)
        self._stop_evt  = threading.Event()
        self._threads   = []

    def start(self):
        self._stop_evt.clear()

        # Thread 1: packet sniffer
        t_sniff = threading.Thread(target=self._sniff_loop, daemon=True)
        t_sniff.start()
        self._threads.append(t_sniff)

        # Thread 2: periodic flow expiry (every 2 s)
        t_expire = threading.Thread(target=self._expire_loop, daemon=True)
        t_expire.start()
        self._threads.append(t_expire)

    def stop(self):
        self._stop_evt.set()
        self.manager.flush_all()        # push remaining flows for classification

    def _sniff_loop(self):
        sniff(
            iface=self.iface,
            prn=self.manager.process_packet,
            store=False,
            stop_filter=lambda _: self._stop_evt.is_set(),
        )

    def _expire_loop(self):
        while not self._stop_evt.is_set():
            time.sleep(2.0)
            self.manager.expire_flows(time.time())


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5 – TKINTER GUI
# ══════════════════════════════════════════════════════════════════════════════

class IDSApp(tk.Tk):
    """Main application window."""

    # Colours
    CLR_BG      = "#1e1e2e"
    CLR_PANEL   = "#2a2a3e"
    CLR_ACCENT  = "#7c6af7"
    CLR_TEXT    = "#cdd6f4"
    CLR_ATTACK  = "#f38ba8"
    CLR_NORMAL  = "#a6e3a1"
    CLR_WARN    = "#fab387"
    CLR_BTN     = "#313244"

    def __init__(self, model, scaler, feature_names):
        super().__init__()
        self.model         = model
        self.scaler        = scaler
        self.feature_names = feature_names

        self.flow_queue    = queue.Queue()
        self.gui_queue     = queue.Queue()
        self.capture_ctrl  = None
        self.classifier    = None
        self.is_capturing  = False

        self.total_count  = 0
        self.attack_count = 0
        self.normal_count = 0

        self._build_ui()
        self._refresh_gui()   # start the polling loop

    # ── UI Construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        self.title("AI Intrusion Detection System")
        self.geometry("1100x700")
        self.configure(bg=self.CLR_BG)
        self.resizable(True, True)

        self._build_header()
        self._build_controls()
        self._build_stats_bar()
        self._build_table()
        self._build_log()

    def _lbl(self, parent, text, **kw):
        defaults = dict(bg=self.CLR_BG, fg=self.CLR_TEXT,
                        font=("Helvetica", 10))
        defaults.update(kw)
        return tk.Label(parent, text=text, **defaults)

    def _build_header(self):
        hdr = tk.Frame(self, bg=self.CLR_ACCENT, height=50)
        hdr.pack(fill="x")
        tk.Label(
            hdr,
            text="🛡  AI-Enabled Intrusion Detection System",
            bg=self.CLR_ACCENT, fg="white",
            font=("Helvetica", 14, "bold")
        ).pack(side="left", padx=20, pady=10)

        # Model badge
        tk.Label(
            hdr,
            text="Model: Random Forest",
            bg=self.CLR_ACCENT, fg="white",
            font=("Helvetica", 10)
        ).pack(side="right", padx=20)

    def _build_controls(self):
        ctrl = tk.Frame(self, bg=self.CLR_PANEL, pady=8)
        ctrl.pack(fill="x", padx=10, pady=(10, 0))

        # Interface selector
        tk.Label(ctrl, text="Network Interface:",
                 bg=self.CLR_PANEL, fg=self.CLR_TEXT,
                 font=("Helvetica", 10, "bold")).pack(side="left", padx=(15, 5))

        ifaces = self._get_interfaces()
        self.iface_var = tk.StringVar(value=ifaces[0] if ifaces else "")
        cb = ttk.Combobox(ctrl, textvariable=self.iface_var,
                          values=ifaces, width=28, state="readonly")
        cb.pack(side="left", padx=5)

        # Buttons
        self.btn_start = tk.Button(
            ctrl, text="▶  Start Capture",
            bg="#40a02b", fg="white", activebackground="#2d7a1e",
            font=("Helvetica", 10, "bold"), relief="flat",
            padx=12, pady=5,
            command=self._start_capture
        )
        self.btn_start.pack(side="left", padx=10)

        self.btn_stop = tk.Button(
            ctrl, text="■  Stop",
            bg="#d20f39", fg="white", activebackground="#9b0d2a",
            font=("Helvetica", 10, "bold"), relief="flat",
            padx=12, pady=5, state="disabled",
            command=self._stop_capture
        )
        self.btn_stop.pack(side="left", padx=5)

        tk.Button(
            ctrl, text="🗑  Clear",
            bg=self.CLR_BTN, fg=self.CLR_TEXT, activebackground="#45475a",
            font=("Helvetica", 10), relief="flat",
            padx=12, pady=5,
            command=self._clear
        ).pack(side="left", padx=5)

        # Status indicator
        self.status_lbl = tk.Label(
            ctrl, text="● Idle",
            bg=self.CLR_PANEL, fg=self.CLR_WARN,
            font=("Helvetica", 10, "bold")
        )
        self.status_lbl.pack(side="right", padx=20)

    def _build_stats_bar(self):
        bar = tk.Frame(self, bg=self.CLR_BG)
        bar.pack(fill="x", padx=10, pady=8)

        def stat_box(parent, title, var, colour):
            f = tk.Frame(parent, bg=self.CLR_PANEL, padx=20, pady=8)
            f.pack(side="left", expand=True, fill="both", padx=5)
            tk.Label(f, text=title, bg=self.CLR_PANEL,
                     fg=self.CLR_TEXT, font=("Helvetica", 9)).pack()
            tk.Label(f, textvariable=var, bg=self.CLR_PANEL,
                     fg=colour, font=("Helvetica", 20, "bold")).pack()

        self.var_total   = tk.StringVar(value="0")
        self.var_normal  = tk.StringVar(value="0")
        self.var_attack  = tk.StringVar(value="0")
        self.var_rate    = tk.StringVar(value="0%")

        stat_box(bar, "Total Flows",    self.var_total,  self.CLR_TEXT)
        stat_box(bar, "Normal",         self.var_normal, self.CLR_NORMAL)
        stat_box(bar, "Attacks",        self.var_attack, self.CLR_ATTACK)
        stat_box(bar, "Attack Rate",    self.var_rate,   self.CLR_WARN)

    def _build_table(self):
        frame = tk.Frame(self, bg=self.CLR_BG)
        frame.pack(fill="both", expand=True, padx=10, pady=(0, 5))

        cols = ("Time", "Source", "Destination", "Proto",
                "Packets", "Label", "Confidence")
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
                        background=self.CLR_PANEL, foreground=self.CLR_TEXT,
                        fieldbackground=self.CLR_PANEL, rowheight=24,
                        font=("Helvetica", 10))
        style.configure("Treeview.Heading",
                        background=self.CLR_ACCENT, foreground="white",
                        font=("Helvetica", 10, "bold"))
        style.map("Treeview", background=[("selected", "#45475a")])

        self.tree = ttk.Treeview(frame, columns=cols, show="headings",
                                 height=12)
        widths = (80, 180, 180, 60, 70, 90, 100)
        for col, w in zip(cols, widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, anchor="center")

        # Tag colours for rows
        self.tree.tag_configure("attack", foreground=self.CLR_ATTACK)
        self.tree.tag_configure("normal", foreground=self.CLR_NORMAL)

        vsb = ttk.Scrollbar(frame, orient="vertical",
                            command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

    def _build_log(self):
        lf = tk.LabelFrame(self, text=" Alert Log ",
                           bg=self.CLR_BG, fg=self.CLR_ACCENT,
                           font=("Helvetica", 9, "bold"))
        lf.pack(fill="x", padx=10, pady=(0, 10))

        self.log = scrolledtext.ScrolledText(
            lf, height=5, bg="#181825", fg=self.CLR_TEXT,
            font=("Courier", 9), state="disabled", relief="flat"
        )
        self.log.pack(fill="x", padx=5, pady=5)
        self.log.tag_configure("attack", foreground=self.CLR_ATTACK)
        self.log.tag_configure("normal", foreground=self.CLR_NORMAL)
        self.log.tag_configure("info",   foreground=self.CLR_WARN)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get_interfaces(self):
        if not SCAPY_OK:
            return ["(scapy not installed)"]
        try:
            return get_if_list() or ["eth0"]
        except Exception:
            return ["eth0", "lo"]

    def _log(self, msg, tag="info"):
        self.log.configure(state="normal")
        self.log.insert("end", msg + "\n", tag)
        self.log.see("end")
        self.log.configure(state="disabled")

    # ── Capture control ───────────────────────────────────────────────────────

    def _start_capture(self):
        if not SCAPY_OK:
            messagebox.showerror("Error",
                "Scapy is not installed.\n"
                "Run:  pip install scapy")
            return

        iface = self.iface_var.get()
        if not iface:
            messagebox.showwarning("Warning", "Please select a network interface.")
            return

        self.is_capturing = True
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.status_lbl.configure(text="● Capturing", fg=self.CLR_NORMAL)

        # Start classifier worker
        self.classifier = ClassifierWorker(
            self.model, self.scaler, self.feature_names,
            self.flow_queue, self.gui_queue
        )
        self.classifier.start()

        # Start capture
        self.capture_ctrl = CaptureController(iface, self.flow_queue)
        self.capture_ctrl.start()

        self._log(f"[{datetime.now().strftime('%H:%M:%S')}] "
                  f"Capture started on interface: {iface}", "info")

    def _stop_capture(self):
        if self.capture_ctrl:
            self.capture_ctrl.stop()
            self.capture_ctrl = None

        if self.classifier:
            self.flow_queue.put(None)   # poison pill

        self.is_capturing = False
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.status_lbl.configure(text="● Idle", fg=self.CLR_WARN)
        self._log(f"[{datetime.now().strftime('%H:%M:%S')}] Capture stopped.", "info")

    def _clear(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.total_count  = 0
        self.attack_count = 0
        self.normal_count = 0
        self._update_stats()
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    # ── GUI refresh loop ──────────────────────────────────────────────────────

    def _refresh_gui(self):
        """Poll the GUI queue every 200 ms and update the display."""
        processed = 0
        while not self.gui_queue.empty() and processed < 50:
            result = self.gui_queue.get_nowait()
            self._display_result(result)
            processed += 1

        self.after(200, self._refresh_gui)

    def _display_result(self, r):
        label   = r["label"]
        is_atk  = (label == "ATTACK")
        tag     = "attack" if is_atk else "normal"

        # Update counters
        self.total_count += 1
        if is_atk:
            self.attack_count += 1
        else:
            self.normal_count += 1
        self._update_stats()

        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(r["proto"], str(r["proto"]))

        # Insert row into table (newest at top)
        row_id = self.tree.insert(
            "", 0,
            values=(
                r["time"],
                r["src"],
                r["dst"],
                proto_name,
                r["pkts"],
                label,
                f"{r['conf']:.1f}%",
            ),
            tags=(tag,),
        )

        # Keep table manageable (max 500 rows)
        children = self.tree.get_children()
        if len(children) > 500:
            self.tree.delete(children[-1])

        # Alert log: only log attacks and first-time normals
        if is_atk:
            self._log(
                f"[{r['time']}] ⚠  ATTACK detected  |  "
                f"{r['src']} → {r['dst']}  |  {proto_name}  |  "
                f"conf={r['conf']:.1f}%",
                "attack"
            )

    def _update_stats(self):
        self.var_total.set(str(self.total_count))
        self.var_normal.set(str(self.normal_count))
        self.var_attack.set(str(self.attack_count))
        rate = (self.attack_count / self.total_count * 100
                if self.total_count else 0)
        self.var_rate.set(f"{rate:.1f}%")

    # ── Graceful shutdown ─────────────────────────────────────────────────────

    def on_close(self):
        if self.is_capturing:
            self._stop_capture()
        self.destroy()


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6 – ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    # ── Check privileges ──────────────────────────────────────────────────────
    if os.name != "nt" and os.geteuid() != 0:
        print("[WARNING] Root privileges are required for live packet capture.")
        print("          Re-run with: sudo python ids_main.py")

    # ── Load model artifacts ──────────────────────────────────────────────────
    print("Loading model artifacts...")
    try:
        model, scaler, feature_names = load_artifacts()
        print(f"  ✓ Model loaded   : {MODEL_FILE}")
        print(f"  ✓ Scaler loaded  : {SCALER_FILE}")
        print(f"  ✓ Features ({len(feature_names)}): {feature_names}")
    except FileNotFoundError as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)

    # ── Launch GUI ────────────────────────────────────────────────────────────
    app = IDSApp(model, scaler, feature_names)
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    print("\nIDS GUI launched.  Select an interface and click 'Start Capture'.")
    app.mainloop()


if __name__ == "__main__":
    main()
