#!/usr/bin/env python3
import os
import sys
import pandas as pd
import joblib

MODEL_FILE = "gb_final_v2.joblib"
NEW_FEATURES_FILE = "features.csv"
OUTPUT_FILE = "predictions.csv"

VERBOSE = ("--verbose" in sys.argv)

def log(msg: str):
    if VERBOSE:
        print(msg)

def main():
    # ---- checks ----
    if not os.path.exists(MODEL_FILE):
        print(f"[!] Model file not found: {MODEL_FILE}")
        sys.exit(1)

    if not os.path.exists(NEW_FEATURES_FILE):
        print(f"[!] Features file not found: {NEW_FEATURES_FILE}")
        sys.exit(1)

    # ---- load model ----
    bundle = joblib.load(MODEL_FILE)
    if "model" not in bundle or "feature_columns" not in bundle:
        print("[!] joblib bundle must contain keys: 'model' and 'feature_columns'")
        sys.exit(1)

    model = bundle["model"]
    feature_columns = bundle["feature_columns"]
    log(f"[i] Model expects {len(feature_columns)} features")

    # ---- load data ----
    df_new = pd.read_csv(NEW_FEATURES_FILE)
    if len(df_new) == 0:
        # create empty predictions file anyway
        pd.DataFrame(columns=["pcap", "predicted_label"]).to_csv(OUTPUT_FILE, index=False, sep="\t")
        print(f"[!] No samples in {NEW_FEATURES_FILE} (empty).")
        sys.exit(0)

    # ---- keep pcap column ----
    if "pcap" in df_new.columns:
        pcap_names = df_new["pcap"].astype(str)
    else:
        pcap_names = pd.Series([str(i) for i in range(len(df_new))], name="pcap")

    # ---- drop non-feature columns ----
    X_new = df_new.drop(columns=["pcap"], errors="ignore")

    # ---- align features ----
    missing = [c for c in feature_columns if c not in X_new.columns]
    if missing:
        print(f"[!] Missing {len(missing)} required features: {missing[:10]}")
        sys.exit(1)

    X_new = X_new[feature_columns]
    X_new = X_new.apply(pd.to_numeric, errors="coerce").fillna(0)

    # ---- predict ----
    y_pred = model.predict(X_new)

    # ---- save ----
    results = pd.DataFrame({
        "pcap": pcap_names,
        "predicted_label": y_pred
    })

    results.to_csv(OUTPUT_FILE, index=False, sep="\t")

    # ✅ output mínimo en realtime
    print(f"[✓] Saved predictions -> {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
