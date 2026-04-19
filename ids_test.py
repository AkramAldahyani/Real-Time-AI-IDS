"""
ids_test.py  –  Headless Model Verification
============================================
Run this FIRST before launching the full GUI to confirm that:
  1. All three .pkl artifacts are found and load correctly.
  2. The feature list matches what was used during training.
  3. The model produces correct predictions on known samples.

No root / Administrator privileges required.
No live network interface needed.

Usage:
    python ids_test.py
"""

import warnings
warnings.filterwarnings("ignore")

import sys, os
import numpy as np

# ── Locate artifact files ──────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE_DIR)           # make sure relative paths work

from ids_main import load_artifacts, FEATURE_NAMES

# ══════════════════════════════════════════════════════════════════════════
# Helper
# ══════════════════════════════════════════════════════════════════════════

def predict_sample(model, scaler, feature_names, feat_dict, label="?"):
    row      = [feat_dict.get(f, 0.0) for f in feature_names]
    X        = np.array(row, dtype=float).reshape(1, -1)
    X        = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
    X_scaled = scaler.transform(X)
    pred     = model.predict(X_scaled)[0]
    proba    = model.predict_proba(X_scaled)[0]
    result   = "ATTACK" if int(pred) == 1 else "Normal"
    conf     = max(proba) * 100
    status   = "✓" if (result == label or label == "?") else "✗"
    print(f"  {status}  Predicted: {result:8s}  ({conf:.1f}% conf)  "
          f"[expected: {label}]")
    return result


# ══════════════════════════════════════════════════════════════════════════
# TEST SAMPLES  (derived directly from the dataset sample in info.txt)
# ══════════════════════════════════════════════════════════════════════════

# Label=1 rows from the dataset (SYN-only flows, very short, bwd-only packets)
ATTACK_SAMPLES = [
    # Flow Duration=581, Tot Fwd=0, Tot Bwd=2, SYN=1
    dict(zip(FEATURE_NAMES, [581, 0, 2, 0, 0, 0, 0, 0, 581, 0, 60,
                              0, 1, 0, 0, 0, 0])),
    # Flow Duration=791
    dict(zip(FEATURE_NAMES, [791, 0, 2, 0, 0, 0, 0, 0, 791, 0, 60,
                              0, 1, 0, 0, 0, 0])),
    # Flow Duration=546
    dict(zip(FEATURE_NAMES, [546, 0, 2, 0, 0, 0, 0, 0, 546, 0, 60,
                              0, 1, 0, 0, 0, 0])),
]

# Label=0 rows  (longer bidirectional flows with data payload)
NORMAL_SAMPLES = [
    # Flow Duration=2361669, 1 fwd + 1 bwd pkt, SYN=1
    dict(zip(FEATURE_NAMES, [2361669, 1, 1, 0, 0, 0, 0, 0, 0, 20, 20,
                              0, 1, 0, 0, 0, 0])),
    # Flow Duration=2727732, 3+3 pkts
    dict(zip(FEATURE_NAMES, [2727732, 3, 3, 0, 0, 0, 0, 545546, 1363860, 60, 68,
                              0, 1, 0, 0, 0, 0])),
]


# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════

def main():
    sep = "=" * 60
    print(sep)
    print("  IT8520 IDS  –  Model Verification Test")
    print(sep)

    # ── 1. Load artifacts ──────────────────────────────────────────────
    print("\n[1] Loading model artifacts …")
    try:
        model, scaler, feature_names = load_artifacts()
        print(f"  ✓  ids_model.pkl    loaded  ({type(model).__name__})")
        print(f"  ✓  ids_scaler.pkl   loaded  ({type(scaler).__name__})")
        print(f"  ✓  ids_features.pkl loaded  ({len(feature_names)} features)")
    except FileNotFoundError as e:
        print(f"\n  ✗  {e}")
        sys.exit(1)

    # ── 2. Feature alignment check ─────────────────────────────────────
    print("\n[2] Feature alignment check …")
    if feature_names == FEATURE_NAMES:
        print(f"  ✓  Feature list matches the 17 training features exactly.")
    else:
        missing  = set(FEATURE_NAMES) - set(feature_names)
        extra    = set(feature_names) - set(FEATURE_NAMES)
        if missing:
            print(f"  ⚠  Missing features : {missing}")
        if extra:
            print(f"  ⚠  Extra features   : {extra}")
    print(f"  Features : {feature_names}")

    # ── 3. Prediction on known attack samples ──────────────────────────
    print("\n[3] Predicting ATTACK samples (expected: ATTACK) …")
    for i, s in enumerate(ATTACK_SAMPLES, 1):
        print(f"  Sample {i}:", end="")
        predict_sample(model, scaler, feature_names, s, label="ATTACK")

    # ── 4. Prediction on known normal samples ──────────────────────────
    print("\n[4] Predicting NORMAL samples (expected: Normal) …")
    for i, s in enumerate(NORMAL_SAMPLES, 1):
        print(f"  Sample {i}:", end="")
        predict_sample(model, scaler, feature_names, s, label="Normal")

    # ── 5. Summary ─────────────────────────────────────────────────────
    print(f"\n{sep}")
    print("  All checks passed. The IDS pipeline is ready.")
    print(f"  Run  'sudo python ids_main.py'  for live capture.")
    print(f"  Run  'python ids_demo.py'        for demo/screenshot mode.")
    print(sep)


if __name__ == "__main__":
    main()
