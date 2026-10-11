import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os
import sys
import json
import shutil
import socket
import platform
from datetime import datetime
from pathlib import Path
import warnings

warnings.filterwarnings("ignore")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

DATA_FILE = PROJECT_ROOT / "data" / "system_data.csv"
MODELS_DIR = PROJECT_ROOT / "models"
BACKUPS_DIR = MODELS_DIR / "backups"
MODELS_DIR.mkdir(exist_ok=True)
BACKUPS_DIR.mkdir(exist_ok=True)

from src.features.feature_engineering import engineer_features, FEATURES

REQUIRED = ["cpu", "ram", "disk", "sent_delta", "recv_delta", "proc"]

def get_current_metadata():
    meta_path = MODELS_DIR / "metadata.json"
    if meta_path.exists():
        try:
            with open(meta_path, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def backup_current_model(current_version_num):
    if current_version_num < 1:
        return None
    backup_path = BACKUPS_DIR / f"model_v{current_version_num}"
    backup_path.mkdir(exist_ok=True)
    
    files_to_backup = ["anomaly_model.pkl", "scaler.pkl", "feature_list.pkl", "baseline_stats.pkl", "metadata.json"]
    backed_up = []
    for fname in files_to_backup:
        src_file = MODELS_DIR / fname
        if src_file.exists():
            shutil.copy2(src_file, backup_path / fname)
            backed_up.append(fname)
    return backup_path if backed_up else None

def restore_backup(backup_path):
    if not backup_path or not backup_path.exists():
        return
    for bfile in backup_path.glob("*"):
        if bfile.is_file():
            shutil.copy2(bfile, MODELS_DIR / bfile.name)

def train():
    print("=" * 60)
    print("  AI Sentinel — Model Retraining Pipeline")
    print("=" * 60)

    if not DATA_FILE.exists():
        print(f"ERROR: Telemetry file '{DATA_FILE}' not found.")
        print("Run scripts/collect_data.py first to collect baseline system data.")
        sys.exit(1)

    curr_meta = get_current_metadata()
    current_version_num = int(curr_meta.get("model_version_num", 0))
    if current_version_num == 0 and curr_meta.get("model_version"):
        import re
        m = re.search(r"\d+", str(curr_meta.get("model_version", "")))
        current_version_num = int(m.group()) if m else 1
        
    new_version_num = current_version_num + 1 if current_version_num >= 1 else 1
    new_version_str = f"V{new_version_num}"
    
    backup_path = None
    if current_version_num >= 1:
        print(f"Archiving current Model V{current_version_num} to backups...")
        backup_path = backup_current_model(current_version_num)

    try:
        df_raw = pd.read_csv(DATA_FILE)
        if len(df_raw) < 50:
            print(f"ERROR: Not enough telemetry in CSV (found {len(df_raw)} rows, need at least 50).")
            if backup_path:
                restore_backup(backup_path)
            sys.exit(1)

        # Handle numeric conversion and drop corrupt/incomplete rows
        df = df_raw.copy()
        for col in REQUIRED:
            df[col] = pd.to_numeric(df[col], errors="coerce")
        df = df.dropna(subset=REQUIRED)

        if len(df) < 50:
            print(f"ERROR: Usable telemetry rows after quality filter < 50 (found {len(df)} rows).")
            if backup_path:
                restore_backup(backup_path)
            sys.exit(1)

        print(f"Loaded {len(df)} accumulated telemetry rows from {DATA_FILE}")

        df_engineered = engineer_features(df)

        # Compute quantile thresholds for clean baseline subset from continuous series
        cpu_cutoff = min(35.0, max(20.0, float(df["cpu"].quantile(0.60))))
        ram_cutoff = min(95.0, max(85.0, float(df["ram"].quantile(0.85))))
        baseline_engineered = df_engineered[(df_engineered["cpu"] <= cpu_cutoff) & (df_engineered["ram"] <= ram_cutoff)].copy()
        print(f"Baseline filter: cpu <= {cpu_cutoff:.1f}% and ram <= {ram_cutoff:.1f}%")
        print(f"Clean baseline rows selected: {len(baseline_engineered)}")

        if len(baseline_engineered) < 50:
            print("WARNING: Very few clean baseline rows — using full accumulated dataset.")
            baseline_engineered = df_engineered.copy()

        X_train = baseline_engineered[FEATURES].values

        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)

        model = IsolationForest(
            n_estimators=200,
            contamination=0.01,
            random_state=42,
            max_samples="auto"
        )
        print(f"\nTraining IsolationForest {new_version_str} on {len(X_train_scaled)} baseline samples...")
        model.fit(X_train_scaled)

        # Dry-run validation test pass
        dummy_input = np.zeros((1, len(FEATURES)))
        dummy_scaled = scaler.transform(dummy_input)
        _ = model.score_samples(dummy_scaled)

        # Evaluate full dataset self-check
        X_full = scaler.transform(df_engineered[FEATURES].values)
        preds = model.predict(X_full)
        scores = model.score_samples(X_full)
        df_engineered["anomaly"] = preds
        df_engineered["score"]   = scores

        n_anom = (preds == -1).sum()
        print(f"\nValidation pass on full accumulated dataset ({len(df_engineered)} rows):")
        print(f"  Flagged anomalies : {n_anom}  ({n_anom/len(df_engineered)*100:.1f}%)")
        print(f"  Normal            : {(preds == 1).sum()}")

        # Save artifacts atomically
        joblib.dump(model,    MODELS_DIR / "anomaly_model.pkl")
        joblib.dump(scaler,   MODELS_DIR / "scaler.pkl")
        joblib.dump(FEATURES, MODELS_DIR / "feature_list.pkl")

        stats = {
            "mean": dict(zip(FEATURES, scaler.mean_)),
            "std": dict(zip(FEATURES, scaler.scale_))
        }
        joblib.dump(stats, MODELS_DIR / "baseline_stats.pkl")

        new_metadata = {
            "model_version": new_version_str,
            "model_version_num": new_version_num,
            "feature_version": "1.0.0",
            "training_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "training_samples": int(len(df)),
            "baseline_clean_samples": int(len(X_train_scaled)),
            "model_type": "IsolationForest",
            "contamination": 0.01,
            "feature_list": FEATURES,
            "pc_name": socket.gethostname(),
            "os": platform.platform()
        }

        with open(MODELS_DIR / "metadata.json", "w") as f:
            json.dump(new_metadata, f, indent=2)

        print("\n--- Training Complete ---")
        print(f"Active Model activated: {new_version_str}")
        print(f"Accumulated Dataset Rows: {len(df)}")
        print(f"Saved: {MODELS_DIR / 'anomaly_model.pkl'}")
        print(f"Saved: {MODELS_DIR / 'scaler.pkl'}")
        print(f"Saved: {MODELS_DIR / 'feature_list.pkl'}")
        print(f"Saved: {MODELS_DIR / 'baseline_stats.pkl'}")
        print(f"Saved: {MODELS_DIR / 'metadata.json'}")

    except Exception as e:
        import traceback
        print(f"\nERROR during model training: {e}")
        traceback.print_exc()
        if backup_path:
            print("Restoring active model from backup due to training failure...")
            restore_backup(backup_path)
        sys.exit(1)

if __name__ == "__main__":
    train()
