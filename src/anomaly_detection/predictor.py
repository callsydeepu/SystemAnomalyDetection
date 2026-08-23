import numpy as np
import pandas as pd
from src.monitoring.process_monitor import is_process_currently_running
import warnings

warnings.filterwarnings("ignore")

def evaluate_latest_sample(df_engineered, model, scaler, features, threshold=-0.600, whitelist=None):
    """
    Evaluates latest row from engineered telemetry DataFrame against IsolationForest and resource thresholds.
    Returns dict containing:
    - score (float)
    - raw_is_anomaly (bool)
    - culprit_proc (str)
    - is_currently_running (bool)
    - threat_confidence (float)
    - sample_state (str)
    - system_state (str)
    """
    if df_engineered.empty or model is None or scaler is None:
        return {
            "score": 0.0,
            "raw_is_anomaly": False,
            "culprit_proc": "Unknown",
            "is_currently_running": False,
            "threat_confidence": 0.0,
            "sample_state": "NORMAL",
            "system_state": "SECURE"
        }
        
    latest_row = df_engineered.iloc[-1]
    X_latest = latest_row[features].values.reshape(1, -1)
    X_scaled = scaler.transform(X_latest)
    
    score = float(model.score_samples(X_scaled)[0])
    raw_is_anomaly = score < threshold
    
    culprit = str(latest_row.get("top_process", "Unknown"))
    currently_running = is_process_currently_running(culprit)
    
    # Process Whitelisting normalization
    whitelist_set = {w.strip().lower() for w in whitelist} if whitelist else set()
    is_whitelisted = culprit.lower() in whitelist_set
    
    # Calculate threat confidence contributions
    effective_latest_score = threshold + 1.0 if is_whitelisted else score
    ml_confidence = max(0.0, min(100.0, (threshold - effective_latest_score) / (abs(threshold) + 1e-5) * 100.0))
    
    cpu_latest = float(latest_row.get("cpu", 0))
    if cpu_latest < 50.0:
        cpu_confidence = 0.0
    elif cpu_latest < 80.0:
        cpu_confidence = (cpu_latest - 50.0) / 30.0 * 30.0
    elif cpu_latest < 95.0:
        cpu_confidence = 30.0 + (cpu_latest - 80.0) / 15.0 * 50.0
    else:
        cpu_confidence = 80.0 + (cpu_latest - 95.0) / 5.0 * 20.0
        
    ram_latest = float(latest_row.get("ram", 0))
    if ram_latest < 70.0:
        ram_confidence = 0.0
    elif ram_latest < 85.0:
        ram_confidence = (ram_latest - 70.0) / 15.0 * 30.0
    elif ram_latest < 95.0:
        ram_confidence = 30.0 + (ram_latest - 85.0) / 10.0 * 50.0
    else:
        ram_confidence = 80.0 + (ram_latest - 95.0) / 5.0 * 20.0
        
    threat_confidence = max(ml_confidence, cpu_confidence, ram_confidence)
    
    # Determine states for recent samples to enforce temporal persistence
    last_n = min(3, len(df_engineered))
    recent_rows = df_engineered.tail(last_n)
    X_recent = recent_rows[features].values
    X_recent_scaled = scaler.transform(X_recent)
    recent_scores = model.score_samples(X_recent_scaled)
    
    recent_sample_states = []
    for i in range(last_n):
        r = recent_rows.iloc[i]
        c = float(r.get("cpu", 0))
        m = float(r.get("ram", 0))
        s = float(recent_scores[i])
        p = str(r.get("top_process", "Unknown")).lower()
        
        is_proc_whitelisted = p in whitelist_set
        effective_score = threshold + 1.0 if is_proc_whitelisted else s
        
        if c >= 95.0 or m >= 95.0 or effective_score < threshold:
            st = "CRITICAL"
        elif c >= 80.0 or m >= 80.0 or effective_score < (threshold + 0.1):
            st = "WARNING"
        else:
            st = "NORMAL"
        recent_sample_states.append(st)
        
    latest_sample_state = recent_sample_states[-1] if recent_sample_states else "NORMAL"
    
    # System state with temporal persistence
    if len(recent_sample_states) > 0 and all(st == "CRITICAL" for st in recent_sample_states):
        # We need at least 3 samples to confirm CRITICAL, otherwise if history is too short we warn
        if len(df_engineered) >= 3:
            system_state = "CRITICAL"
        else:
            system_state = "WARNING"
    elif any(st in ["CRITICAL", "WARNING"] for st in recent_sample_states):
        system_state = "WARNING"
    else:
        system_state = "SECURE"
        
    return {
        "score": score,
        "raw_is_anomaly": raw_is_anomaly,
        "culprit_proc": culprit,
        "is_currently_running": currently_running,
        "threat_confidence": threat_confidence,
        "sample_state": latest_sample_state,
        "system_state": system_state
    }
