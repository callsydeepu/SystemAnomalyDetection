import numpy as np
import pandas as pd
from src.monitoring.process_monitor import is_process_currently_running
import warnings

warnings.filterwarnings("ignore")

def evaluate_latest_sample(df_engineered, model, scaler, features, threshold=-0.600):
    """
    Evaluates latest row from engineered telemetry DataFrame against IsolationForest.
    Returns dict containing:
    - score (float)
    - raw_is_anomaly (bool)
    - culprit_proc (str)
    - is_currently_running (bool)
    """
    if df_engineered.empty or model is None or scaler is None:
        return {
            "score": 0.0,
            "raw_is_anomaly": False,
            "culprit_proc": "Unknown",
            "is_currently_running": False
        }
        
    latest_row = df_engineered.iloc[-1]
    X_latest = latest_row[features].values.reshape(1, -1)
    X_scaled = scaler.transform(X_latest)
    
    score = float(model.score_samples(X_scaled)[0])
    raw_is_anomaly = score < threshold
    
    culprit = str(latest_row.get("top_process", "Unknown"))
    currently_running = is_process_currently_running(culprit)
    
    return {
        "score": score,
        "raw_is_anomaly": raw_is_anomaly,
        "culprit_proc": culprit,
        "is_currently_running": currently_running
    }
