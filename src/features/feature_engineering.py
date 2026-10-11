import pandas as pd
import numpy as np
import warnings

warnings.filterwarnings("ignore")

FEATURES = [
    "cpu",
    "ram",
    "disk",
    "proc",
    "cpu_delta",
    "cpu_z",
    "net_total",
    "net_roll",
]

BASE_COLUMNS = ["cpu", "ram", "disk", "sent_delta", "recv_delta", "proc"]

def engineer_features(df):
    """
    Computes exact 8 ML features from raw telemetry data.
    Protects against NaN / Inf hazards and missing columns using clean replacements.
    """
    if df is None or len(df) == 0:
        empty_df = pd.DataFrame(columns=FEATURES + ["top_process", "timestamp"])
        for col in FEATURES:
            empty_df[col] = empty_df[col].astype(float)
        return empty_df

    df = df.copy()

    # Ensure all foundational telemetry columns exist as clean numeric series
    for col in BASE_COLUMNS:
        if col not in df.columns:
            df[col] = 0.0
        else:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)

    df["cpu_delta"] = df["cpu"].diff().fillna(0.0).abs()
    df["ram_delta"] = df["ram"].diff().fillna(0.0).abs()

    WINDOW = 30
    df["cpu_roll_mean"] = df["cpu"].rolling(WINDOW, min_periods=1).mean()
    df["cpu_roll_std"]  = df["cpu"].rolling(WINDOW, min_periods=1).std().fillna(0.001)

    cpu_z_raw = (df["cpu"] - df["cpu_roll_mean"]) / (df["cpu_roll_std"] + 1e-5)
    df["cpu_z"] = cpu_z_raw.replace([np.inf, -np.inf], 0.0).fillna(0.0)

    df["net_total"] = df["sent_delta"] + df["recv_delta"]
    df["net_roll"]  = df["net_total"].rolling(WINDOW, min_periods=1).mean().fillna(0.0)

    # Enforce numeric float dtype and finite values across all ML feature columns
    for col in FEATURES:
        if col not in df.columns:
            df[col] = 0.0
        else:
            df[col] = pd.to_numeric(df[col], errors="coerce").replace([np.inf, -np.inf], 0.0).fillna(0.0).astype(float)

    return df
