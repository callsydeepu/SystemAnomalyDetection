import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os
import sys
from pathlib import Path
import warnings

warnings.filterwarnings("ignore")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

DATA_FILE = PROJECT_ROOT / "data" / "system_data.csv"
MODELS_DIR = PROJECT_ROOT / "models"
MODELS_DIR.mkdir(exist_ok=True)

from src.features.feature_engineering import engineer_features, FEATURES

REQUIRED = ["cpu", "ram", "disk", "sent_delta", "recv_delta", "proc"]

def train():
    print("=" * 50)
    print("  AI Sentinel — Model Training")
    print("=" * 50)

    if not DATA_FILE.exists():
        print(f"ERROR: Telemetry file '{DATA_FILE}' not found.")
        print("Run scripts/collect_data.py first to collect baseline system data.")
        sys.exit(1)

    try:
        df = pd.read_csv(DATA_FILE)
        if len(df) < 50:
            print(f"ERROR: Not enough data in CSV (found {len(df)} rows, need at least 50).")
            print("Keep scripts/collect_data.py running longer before training.")
            sys.exit(1)

        for col in REQUIRED:
            df[col] = pd.to_numeric(df[col], errors="coerce")
        df = df.dropna(subset=REQUIRED)

        print(f"Loaded {len(df)} usable rows from {DATA_FILE}")

        df_engineered = engineer_features(df)

        cpu_cutoff = min(35.0, max(20.0, float(df["cpu"].quantile(0.60))))
        ram_cutoff = min(95.0, max(85.0, float(df["ram"].quantile(0.85))))
        baseline = df[(df["cpu"] <= cpu_cutoff) & (df["ram"] <= ram_cutoff)].copy()
        print(f"Baseline filter: cpu <= {cpu_cutoff:.1f}% and ram <= {ram_cutoff:.1f}%")
        print(f"Clean baseline rows selected: {len(baseline)}")

        if len(baseline) < 100:
            print("WARNING: Very few clean rows — falling back to full dataset.")
            baseline = df.copy()

        baseline = engineer_features(baseline)

        X_train = baseline[FEATURES].values

        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)

        model = IsolationForest(
            n_estimators=200,
            contamination=0.01,
            random_state=42,
            max_samples="auto"
        )
        print(f"\nTraining IsolationForest on {len(X_train_scaled)} clean rows...")
        model.fit(X_train_scaled)

        df_full = df_engineered
        X_full = scaler.transform(df_full[FEATURES].values)
        preds = model.predict(X_full)
        scores = model.score_samples(X_full)
        df_full["anomaly"] = preds
        df_full["score"]   = scores

        n_anom = (preds == -1).sum()
        print(f"\nSelf-check on full dataset ({len(df_full)} rows):")
        print(f"  Flagged anomalies : {n_anom}  ({n_anom/len(df_full)*100:.1f}%)")
        print(f"  Normal            : {(preds == 1).sum()}")

        if "top_process" in df_full.columns:
            print("\nTop processes in flagged rows:")
            print(df_full[df_full["anomaly"] == -1]["top_process"].value_counts().head(8).to_string())

        # Save all 4 artifacts to models/
        joblib.dump(model,    MODELS_DIR / "anomaly_model.pkl")
        joblib.dump(scaler,   MODELS_DIR / "scaler.pkl")
        joblib.dump(FEATURES, MODELS_DIR / "feature_list.pkl")

        stats = {
            "mean": dict(zip(FEATURES, scaler.mean_)),
            "std": dict(zip(FEATURES, scaler.scale_))
        }
        joblib.dump(stats, MODELS_DIR / "baseline_stats.pkl")

        print("\n--- Training Complete ---")
        print(f"Saved: {MODELS_DIR / 'anomaly_model.pkl'}")
        print(f"Saved: {MODELS_DIR / 'scaler.pkl'}")
        print(f"Saved: {MODELS_DIR / 'feature_list.pkl'}")
        print(f"Saved: {MODELS_DIR / 'baseline_stats.pkl'}")

    except Exception as e:
        import traceback
        print(f"Error during training: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    train()
