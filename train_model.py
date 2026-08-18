import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ─────────────────────────────────────────────
# Feature engineering — MUST match app.py exactly
# WINDOW = 30 (both files must use same value)
# ─────────────────────────────────────────────
def engineer_features(df):
    df = df.copy()
    for col in ["cpu", "ram", "disk", "sent_delta", "recv_delta", "proc"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    df["cpu_delta"]     = df["cpu"].diff().fillna(0).abs()
    df["ram_delta"]     = df["ram"].diff().fillna(0).abs()
    WINDOW = 30
    df["cpu_roll_mean"] = df["cpu"].rolling(WINDOW, min_periods=1).mean()
    df["cpu_roll_std"]  = df["cpu"].rolling(WINDOW, min_periods=1).std().fillna(1)
    df["cpu_z"]         = (df["cpu"] - df["cpu_roll_mean"]) / (df["cpu_roll_std"] + 0.001)
    df["cpu_z"]         = df["cpu_z"].replace([np.inf, -np.inf], 0).fillna(0)
    df["net_total"]     = (df["sent_delta"] + df["recv_delta"]).clip(lower=0)
    df["net_roll"]      = df["net_total"].rolling(WINDOW, min_periods=1).mean().fillna(0)
    return df

FEATURES = [
    "cpu", "ram", "disk", "proc",
    "cpu_delta", "cpu_z",
    "net_total", "net_roll",
]

def train():
    print("=" * 50)
    print("  AI Sentinel — Model Training")
    print("=" * 50)

    try:
        df = pd.read_csv("system_data.csv")

        # FIX BUG 1: dropna with subset only — NOT df.dropna()
        # df.dropna() drops ALL rows if ANY column has NaN, including
        # new columns like ram_used_gb that old rows don't have.
        # This was silently wiping all training data on mixed CSVs.
        REQUIRED = ["cpu", "ram", "disk", "sent_delta", "recv_delta", "proc"]
        df = df.dropna(subset=REQUIRED)

        # Force numeric on key columns
        for col in REQUIRED:
            df[col] = pd.to_numeric(df[col], errors="coerce")
        df = df.dropna(subset=REQUIRED)

        print(f"Loaded {len(df)} usable rows from system_data.csv")

        # FIX BUG 6: dynamic baseline filter instead of hardcoded cpu<35
        # On machines that idle at 30-34%, hardcoded filter leaves almost
        # no training rows. Use 50th percentile as adaptive cutoff.
        cpu_cutoff = min(35.0, max(20.0, float(df["cpu"].quantile(0.60))))
        ram_cutoff = min(95.0, max(85.0, float(df["ram"].quantile(0.85))))
        baseline = df[(df["cpu"] <= cpu_cutoff) & (df["ram"] <= ram_cutoff)].copy()
        print(f"Baseline filter: cpu <= {cpu_cutoff:.1f}% and ram <= {ram_cutoff:.1f}%")
        print(f"Clean baseline rows selected: {len(baseline)}")

        if len(baseline) < 100:
            print("WARNING: Very few clean rows — collect more idle data before attacks.")
            print("         Falling back to full dataset (may reduce detection quality).")
            baseline = df.copy()

        baseline = engineer_features(baseline)
        X_train  = baseline[FEATURES].fillna(0)

        scaler   = StandardScaler()
        X_scaled = scaler.fit_transform(X_train)

        model = IsolationForest(
            n_estimators=200,
            contamination=0.01,
            max_samples="auto",
            random_state=42
        )

        print(f"\nTraining IsolationForest on {len(X_train)} clean rows...")
        model.fit(X_scaled)

        # Self-check on full dataset
        df_full = engineer_features(df)
        X_full  = scaler.transform(df_full[FEATURES].fillna(0))
        df["anomaly"] = model.predict(X_full)
        df["score"]   = model.score_samples(X_full)

        n_flagged = (df["anomaly"] == -1).sum()
        pct       = n_flagged / len(df) * 100
        print(f"\nSelf-check on full dataset ({len(df)} rows):")
        print(f"  Flagged anomalies : {n_flagged}  ({pct:.1f}%)")
        print(f"  Normal            : {len(df) - n_flagged}")

        if "top_process" in df.columns:
            print("\nTop processes in flagged rows:")
            print(df[df["anomaly"] == -1]["top_process"].value_counts().head(8).to_string())

        # Save all 4 artifacts
        joblib.dump(model,    "anomaly_model.pkl")
        joblib.dump(scaler,   "scaler.pkl")
        joblib.dump(FEATURES, "feature_list.pkl")

        # Save baseline stats for explainability (Z-score breakdown)
        stats = {
            "mean": dict(zip(FEATURES, scaler.mean_)),
            "std": dict(zip(FEATURES, scaler.scale_))
        }
        joblib.dump(stats, "baseline_stats.pkl")

        print("\n--- Training Complete ---")
        print("Saved: anomaly_model.pkl")
        print("Saved: scaler.pkl")
        print("Saved: feature_list.pkl")
        print("Saved: baseline_stats.pkl")

    except Exception as e:
        import traceback
        print(f"Error during training: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    train()