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

def engineer_features(df):
    """
    Computes exact 8 ML features from raw telemetry data.
    Protects against NaN / Inf hazards using clean replacements.
    """
    df = df.copy()
    for col in ["cpu", "ram", "disk", "sent_delta", "recv_delta", "proc"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    df["cpu_delta"]     = df["cpu"].diff().fillna(0).abs()
    df["ram_delta"]     = df["ram"].diff().fillna(0).abs()
    WINDOW = 30
    df["cpu_roll_mean"] = df["cpu"].rolling(WINDOW, min_periods=1).mean()
    df["cpu_roll_std"]  = df["cpu"].rolling(WINDOW, min_periods=1).std().fillna(0.001)

    cpu_z_raw = (df["cpu"] - df["cpu_roll_mean"]) / (df["cpu_roll_std"] + 1e-5)
    df["cpu_z"] = cpu_z_raw.replace([np.inf, -np.inf], 0).fillna(0)

    df["net_total"] = df["sent_delta"] + df["recv_delta"]
    df["net_roll"]  = df["net_total"].rolling(WINDOW, min_periods=1).mean()

    for col in FEATURES:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").replace([np.inf, -np.inf], 0).fillna(0)

    return df
