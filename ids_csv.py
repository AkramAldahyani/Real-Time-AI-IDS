"""
(CSV Mode)
===========================================================
Upload a CSV file (CICFlowMeter format) via the GUI, and the IDS
will classify every row as normal or attack . This is
designed for testing in the absence of a testing lab environment.

"""

import warnings
warnings.filterwarnings("ignore")

import os, sys, threading, queue, joblib
import numpy as np
import pandas as pd
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from datetime import datetime

# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTS  –  must match training script exactly
# ══════════════════════════════════════════════════════════════════════════════

MODEL_FILE    = "ids_model.pkl"
SCALER_FILE   = "ids_scaler.pkl"
FEATURES_FILE = "ids_features.pkl"

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

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 – MODEL LOADING
# ══════════════════════════════════════════════════════════════════════════════

def load_artifacts():
    """Load the three .pkl files saved by the training script."""
    base = os.path.dirname(os.path.abspath(__file__))
    for fname in (MODEL_FILE, SCALER_FILE, FEATURES_FILE):
        path = os.path.join(base, fname)
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"Missing: '{fname}'  (looked in: {base})\n"
                "Copy ids_model.pkl, ids_scaler.pkl, ids_features.pkl "
                "into the same folder as ids_csv.py"
            )
    model  = joblib.load(os.path.join(base, MODEL_FILE))
    scaler = joblib.load(os.path.join(base, SCALER_FILE))
    feats  = joblib.load(os.path.join(base, FEATURES_FILE))
    return model, scaler, feats


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 – CSV CLASSIFIER
# ══════════════════════════════════════════════════════════════════════════════

def classify_csv(filepath, model, scaler, feature_names):
    """
    Load a CSV, extract the 17 required features, run the model, and
    return a DataFrame with an added 'Prediction' and 'Confidence' column.

    Handles:
      - Missing feature columns (filled with 0)
      - Inf / NaN values (replaced with 0)
      - Numeric coercion for any string-typed columns
    """
    df = pd.read_csv(filepath)

    # ── Align columns ─────────────────────────────────────────────────────────
    missing_cols = [f for f in feature_names if f not in df.columns]
    for col in missing_cols:
        df[col] = 0.0   # fill absent features with 0

    X = df[feature_names].copy()

    # ── Clean ─────────────────────────────────────────────────────────────────
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors='coerce')
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)

    # ── Scale + predict ───────────────────────────────────────────────────────
    X_scaled = scaler.transform(X.values)
    preds    = model.predict(X_scaled)
    probas   = model.predict_proba(X_scaled)

    df['Prediction']  = ['ATTACK' if p == 1 else 'Normal' for p in preds]
    df['Confidence']  = [f"{max(p)*100:.1f}%" for p in probas]

    return df, missing_cols


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 – BACKGROUND WORKER THREAD
# ══════════════════════════════════════════════════════════════════════════════

class ClassifyWorker(threading.Thread):
    """
    Runs classify_csv() in a background thread so the GUI stays responsive
    during large file processing.  Posts results to a queue when done.
    """

    def __init__(self, filepath, model, scaler, feature_names, result_queue):
        super().__init__(daemon=True)
        self.filepath     = filepath
        self.model        = model
        self.scaler       = scaler
        self.feature_names = feature_names
        self.result_queue = result_queue

    def run(self):
        try:
            df, missing = classify_csv(
                self.filepath, self.model, self.scaler, self.feature_names)
            self.result_queue.put(("ok", df, missing))
        except Exception as e:
            self.result_queue.put(("error", str(e), []))


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4 – TKINTER GUI
# ══════════════════════════════════════════════════════════════════════════════

class IDSApp(tk.Tk):

    # Colour palette (same as live version for consistency)
    CLR_BG     = "#1e1e2e"
    CLR_PANEL  = "#2a2a3e"
    CLR_ACCENT = "#7c6af7"
    CLR_TEXT   = "#cdd6f4"
    CLR_ATTACK = "#f38ba8"
    CLR_NORMAL = "#a6e3a1"
    CLR_WARN   = "#fab387"
    CLR_BTN    = "#313244"
    CLR_LOWC   = "#cba6f7"

    def __init__(self, model, scaler, feature_names):
        super().__init__()
        self.model         = model
        self.scaler        = scaler
        self.feature_names = feature_names
        self.result_queue  = queue.Queue()
        self.current_df    = None   # holds the last classified DataFrame

        self._build_ui()
        self._poll_results()   # start background-result polling loop

    # ── UI Construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        self.title("AI Intrusion Detection System  (CSV Mode)")
        self.geometry("1200x750")
        self.configure(bg=self.CLR_BG)
        self.resizable(True, True)
        self._build_header()
        self._build_file_panel()
        self._build_summary_bar()
        self._build_table()
        self._build_log()

    def _build_header(self):
        hdr = tk.Frame(self, bg=self.CLR_ACCENT, height=50)
        hdr.pack(fill="x")
        tk.Label(hdr,
                 text="🛡  AI-Enabled Intrusion Detection System  ",
                 bg=self.CLR_ACCENT, fg="white",
                 font=("Helvetica", 14, "bold")).pack(side="left", padx=20, pady=10)
        tk.Label(hdr, text="Model: Random Forest  |  CSV Analysis Mode",
                 bg=self.CLR_ACCENT, fg="white",
                 font=("Helvetica", 10)).pack(side="right", padx=20)

    def _build_file_panel(self):
        panel = tk.Frame(self, bg=self.CLR_PANEL, pady=10)
        panel.pack(fill="x", padx=10, pady=(10, 0))

        # ── Row 1: file picker ─────────────────────────────────────────────
        row1 = tk.Frame(panel, bg=self.CLR_PANEL)
        row1.pack(fill="x", padx=15, pady=(0, 6))

        tk.Label(row1, text="CSV File:",
                 bg=self.CLR_PANEL, fg=self.CLR_TEXT,
                 font=("Helvetica", 10, "bold")).pack(side="left", padx=(0, 8))

        self.path_var = tk.StringVar(value="No file selected")
        tk.Label(row1, textvariable=self.path_var,
                 bg=self.CLR_PANEL, fg=self.CLR_WARN,
                 font=("Helvetica", 9),
                 anchor="w", width=80).pack(side="left", padx=(0, 10))

        tk.Button(row1, text="📂  Browse CSV",
                  bg=self.CLR_BTN, fg=self.CLR_TEXT,
                  font=("Helvetica", 10, "bold"), relief="flat",
                  padx=12, pady=5,
                  command=self._browse).pack(side="left", padx=5)

        # ── Row 2: action buttons + status ────────────────────────────────
        row2 = tk.Frame(panel, bg=self.CLR_PANEL)
        row2.pack(fill="x", padx=15)

        self.btn_classify = tk.Button(
            row2, text="▶  Classify",
            bg="#40a02b", fg="white", activebackground="#2d7a1e",
            font=("Helvetica", 10, "bold"), relief="flat",
            padx=14, pady=5, state="disabled",
            command=self._run_classify)
        self.btn_classify.pack(side="left", padx=(0, 8))

        self.btn_export = tk.Button(
            row2, text="💾  Export Results CSV",
            bg=self.CLR_BTN, fg=self.CLR_TEXT,
            font=("Helvetica", 10), relief="flat",
            padx=12, pady=5, state="disabled",
            command=self._export_csv)
        self.btn_export.pack(side="left", padx=5)

        tk.Button(row2, text="🗑  Clear",
                  bg=self.CLR_BTN, fg=self.CLR_TEXT,
                  font=("Helvetica", 10), relief="flat",
                  padx=12, pady=5,
                  command=self._clear).pack(side="left", padx=5)

        self.status_lbl = tk.Label(
            row2, text="● Ready",
            bg=self.CLR_PANEL, fg=self.CLR_WARN,
            font=("Helvetica", 10, "bold"))
        self.status_lbl.pack(side="right", padx=10)

        # Progress bar (hidden until classifying)
        self.progress = ttk.Progressbar(
            panel, mode="indeterminate", length=300)
        self.progress.pack(padx=15, pady=(6, 4), anchor="w")

    def _build_summary_bar(self):
        bar = tk.Frame(self, bg=self.CLR_BG)
        bar.pack(fill="x", padx=10, pady=8)

        def box(title, var, colour):
            f = tk.Frame(bar, bg=self.CLR_PANEL, padx=20, pady=8)
            f.pack(side="left", expand=True, fill="both", padx=5)
            tk.Label(f, text=title, bg=self.CLR_PANEL,
                     fg=self.CLR_TEXT, font=("Helvetica", 9)).pack()
            tk.Label(f, textvariable=var, bg=self.CLR_PANEL,
                     fg=colour, font=("Helvetica", 20, "bold")).pack()

        self.var_total  = tk.StringVar(value="–")
        self.var_normal = tk.StringVar(value="–")
        self.var_attack = tk.StringVar(value="–")
        self.var_rate   = tk.StringVar(value="–")
        box("Total Flows",  self.var_total,  self.CLR_TEXT)
        box("Normal",       self.var_normal, self.CLR_NORMAL)
        box("Attacks",      self.var_attack, self.CLR_ATTACK)
        box("Attack Rate",  self.var_rate,   self.CLR_WARN)

    def _build_table(self):
        frame = tk.Frame(self, bg=self.CLR_BG)
        frame.pack(fill="both", expand=True, padx=10, pady=(0, 5))

        # Display columns (subset of CSV + our two new columns)
        self.display_cols = [
            "Row", "Src IP", "Src Port", "Dst IP", "Dst Port",
            "Protocol", "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts",
            "SYN Flag Cnt", "Prediction", "Confidence"
        ]

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

        self.tree = ttk.Treeview(frame, columns=self.display_cols,
                                  show="headings", height=14)

        col_widths = {
            "Row": 50, "Src IP": 130, "Src Port": 75, "Dst IP": 130,
            "Dst Port": 75, "Protocol": 65, "Flow Duration": 110,
            "Tot Fwd Pkts": 95, "Tot Bwd Pkts": 95,
            "SYN Flag Cnt": 90, "Prediction": 90, "Confidence": 90
        }
        for col in self.display_cols:
            self.tree.heading(col, text=col,
                              command=lambda c=col: self._sort_column(c))
            self.tree.column(col, width=col_widths.get(col, 90),
                              anchor="center")

        self.tree.tag_configure("attack", foreground=self.CLR_ATTACK)
        self.tree.tag_configure("normal", foreground=self.CLR_NORMAL)

        # Scrollbars
        vsb = ttk.Scrollbar(frame, orient="vertical",   command=self.tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right",  fill="y")
        hsb.pack(side="bottom", fill="x")

    def _build_log(self):
        lf = tk.LabelFrame(self, text=" Classification Log ",
                            bg=self.CLR_BG, fg=self.CLR_ACCENT,
                            font=("Helvetica", 9, "bold"))
        lf.pack(fill="x", padx=10, pady=(0, 10))
        self.log = scrolledtext.ScrolledText(
            lf, height=4, bg="#181825", fg=self.CLR_TEXT,
            font=("Courier", 9), state="disabled", relief="flat")
        self.log.pack(fill="x", padx=5, pady=5)
        self.log.tag_configure("attack", foreground=self.CLR_ATTACK)
        self.log.tag_configure("normal", foreground=self.CLR_NORMAL)
        self.log.tag_configure("info",   foreground=self.CLR_WARN)
        self.log.tag_configure("warn",   foreground="#f9e2af")

    # ── Logging helper ────────────────────────────────────────────────────────

    def _log(self, msg, tag="info"):
        self.log.configure(state="normal")
        self.log.insert("end", msg + "\n", tag)
        self.log.see("end")
        self.log.configure(state="disabled")

    # ── File browsing ─────────────────────────────────────────────────────────

    def _browse(self):
        path = filedialog.askopenfilename(
            title="Select CICFlowMeter CSV file",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if path:
            self.path_var.set(path)
            self.btn_classify.configure(state="normal")
            self._log(f"[{datetime.now().strftime('%H:%M:%S')}] "
                      f"File selected: {os.path.basename(path)}", "info")

    # ── Classification ────────────────────────────────────────────────────────

    def _run_classify(self):
        path = self.path_var.get()
        if not path or path == "No file selected":
            messagebox.showwarning("No File", "Please select a CSV file first.")
            return

        # Lock UI during processing
        self.btn_classify.configure(state="disabled")
        self.btn_export.configure(state="disabled")
        self.status_lbl.configure(text="● Processing…", fg=self.CLR_WARN)
        self.progress.pack(padx=15, pady=(6, 4), anchor="w")
        self.progress.start(10)
        self._clear_table()

        self._log(f"[{datetime.now().strftime('%H:%M:%S')}] "
                  f"Classifying: {os.path.basename(path)} …", "info")

        # Run in background thread so GUI does not freeze
        worker = ClassifyWorker(
            path, self.model, self.scaler, self.feature_names,
            self.result_queue)
        worker.start()

    def _poll_results(self):
        """Check every 100 ms whether the background worker finished."""
        try:
            status, data, extra = self.result_queue.get_nowait()
            self.progress.stop()
            self.progress.pack_forget()
            self.btn_classify.configure(state="normal")

            if status == "ok":
                self._display_results(data, extra)
            else:
                messagebox.showerror("Classification Error", data)
                self.status_lbl.configure(text="● Error", fg=self.CLR_ATTACK)
                self._log(f"[ERROR] {data}", "attack")

        except queue.Empty:
            pass   # nothing ready yet

        self.after(100, self._poll_results)

    # ── Results display ───────────────────────────────────────────────────────

    def _display_results(self, df, missing_cols):
        self.current_df = df

        total   = len(df)
        attacks = int((df['Prediction'] == 'ATTACK').sum())
        normals = total - attacks
        rate    = attacks / total * 100 if total else 0

        # Update stats bar
        self.var_total.set(str(total))
        self.var_normal.set(str(normals))
        self.var_attack.set(str(attacks))
        self.var_rate.set(f"{rate:.1f}%")

        # Status
        colour = self.CLR_ATTACK if attacks > 0 else self.CLR_NORMAL
        label  = f"● {attacks} Attack{'s' if attacks != 1 else ''} detected" \
                 if attacks > 0 else "● All Normal"
        self.status_lbl.configure(text=label, fg=colour)

        # Log summary
        ts = datetime.now().strftime('%H:%M:%S')
        self._log(f"[{ts}] Done  –  {total} flows  |  "
                  f"{normals} Normal  |  {attacks} ATTACK", "info")
        if attacks > 0:
            self._log(f"[{ts}] ⚠  Attack rate: {rate:.1f}%", "attack")
        if missing_cols:
            self._log(f"[{ts}] ⚠  Missing columns filled with 0: "
                      f"{missing_cols}", "warn")

        # Populate table (up to 2000 rows for performance)
        MAX_ROWS = 2000
        subset   = df.head(MAX_ROWS)

        # Column name mapping: display name → actual CSV column name
        col_map = {
            "Src IP":        "Src IP",
            "Src Port":      "Src Port",
            "Dst IP":        "Dst IP",
            "Dst Port":      "Dst Port",
            "Protocol":      "Protocol",
            "Flow Duration": "Flow Duration",
            "Tot Fwd Pkts":  "Tot Fwd Pkts",
            "Tot Bwd Pkts":  "Tot Bwd Pkts",
            "SYN Flag Cnt":  "SYN Flag Cnt",
            "Prediction":    "Prediction",
            "Confidence":    "Confidence",
        }

        for i, (_, row) in enumerate(subset.iterrows(), start=1):
            tag = "attack" if row['Prediction'] == 'ATTACK' else "normal"
            vals = [i]
            for col in self.display_cols[1:]:  # skip "Row"
                csv_col = col_map.get(col, col)
                val = row.get(csv_col, "–")
                # Truncate floats
                try:
                    val = f"{float(val):.2f}" if "." in str(val) else val
                except (ValueError, TypeError):
                    pass
                vals.append(val)

            self.tree.insert("", "end", values=vals, tags=(tag,))

        if len(df) > MAX_ROWS:
            self._log(
                f"[INFO] Table shows first {MAX_ROWS} rows. "
                f"Export CSV to see all {len(df)}.", "warn")

        self.btn_export.configure(state="normal")

    # ── Export ────────────────────────────────────────────────────────────────

    def _export_csv(self):
        if self.current_df is None:
            return
        path = filedialog.asksaveasfilename(
            title="Save Results As",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")])
        if path:
            self.current_df.to_csv(path, index=False)
            self._log(f"[{datetime.now().strftime('%H:%M:%S')}] "
                      f"Exported to: {path}", "info")
            messagebox.showinfo("Exported", f"Results saved to:\n{path}")

    # ── Sort column ───────────────────────────────────────────────────────────

    def _sort_column(self, col):
        """Click a column header to sort the table by that column."""
        rows = [(self.tree.set(child, col), child)
                for child in self.tree.get_children("")]
        try:
            rows.sort(key=lambda x: float(x[0]))
        except (ValueError, TypeError):
            rows.sort()
        for idx, (_, child) in enumerate(rows):
            self.tree.move(child, "", idx)

    # ── Clear ─────────────────────────────────────────────────────────────────

    def _clear(self):
        self._clear_table()
        self.current_df = None
        self.path_var.set("No file selected")
        self.btn_classify.configure(state="disabled")
        self.btn_export.configure(state="disabled")
        self.status_lbl.configure(text="● Ready", fg=self.CLR_WARN)
        for v in (self.var_total, self.var_normal, self.var_attack, self.var_rate):
            v.set("–")
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def _clear_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

    def on_close(self):
        self.destroy()


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5 – ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    print("Loading model artifacts …")
    try:
        model, scaler, feature_names = load_artifacts()
        print(f"  ✓  {MODEL_FILE}    ({type(model).__name__})")
        print(f"  ✓  {SCALER_FILE}")
        print(f"  ✓  {FEATURES_FILE}  ({len(feature_names)} features)")
    except FileNotFoundError as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)

    app = IDSApp(model, scaler, feature_names)
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    print("\nGUI ready. Click 'Browse CSV' to load a CICFlowMeter file.")
    app.mainloop()


if __name__ == "__main__":
    main()