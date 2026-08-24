import numpy as np
import pandas as pd
from src.monitoring.process_monitor import is_process_currently_running
import warnings

warnings.filterwarnings("ignore")

def evaluate_latest_sample(df_engineered, model, scaler, features, threshold=None, whitelist=None):
    """
    Evaluates latest row from engineered telemetry DataFrame against IsolationForest model.
    Single Source of Truth: All classifications, confidence scores, and system states
    are derived 100% from the ML anomaly score relative to the threshold.
    No static resource thresholds (e.g. CPU >= 95%, RAM >= 95%) override ML predictions.
    
    Returns dict containing:
    - score (float)
    - threshold (float)
    - raw_is_anomaly (bool)
    - culprit_proc (str)
    - is_currently_running (bool)
    - threat_confidence (float)
    - sample_state (str)
    - system_state (str)
    - state_reason (str)
    """
    if threshold is None:
        threshold = float(getattr(model, "offset_", -0.600)) if model is not None else -0.600

    if df_engineered.empty or model is None or scaler is None:
        return {
            "score": 0.0,
            "threshold": threshold,
            "raw_is_anomaly": False,
            "culprit_proc": "Unknown",
            "is_currently_running": False,
            "threat_confidence": 0.0,
            "sample_state": "NORMAL",
            "system_state": "SECURE",
            "state_reason": "No telemetry data or model available."
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
    
    # Calculate threat confidence derived strictly from ML anomaly score depth
    effective_latest_score = (threshold + 1.0) if is_whitelisted else score
    if effective_latest_score < threshold:
        threat_confidence = max(0.0, min(100.0, (threshold - effective_latest_score) / (abs(threshold) + 1e-5) * 100.0))
    else:
        threat_confidence = 0.0

    # Determine states for recent samples to enforce temporal persistence
    last_n = min(3, len(df_engineered))
    recent_rows = df_engineered.tail(last_n)
    X_recent = recent_rows[features].values
    X_recent_scaled = scaler.transform(X_recent)
    recent_scores = model.score_samples(X_recent_scaled)
    
    recent_sample_states = []
    for i in range(last_n):
        r = recent_rows.iloc[i]
        s = float(recent_scores[i])
        p = str(r.get("top_process", "Unknown")).lower()
        
        is_proc_whitelisted = p in whitelist_set
        eff_s = (threshold + 1.0) if is_proc_whitelisted else s
        
        if eff_s < threshold:
            st = "CRITICAL"
        elif eff_s < (threshold + 0.05):
            st = "WARNING"
        else:
            st = "NORMAL"
        recent_sample_states.append(st)
        
    latest_sample_state = recent_sample_states[-1] if recent_sample_states else "NORMAL"
    
    # System state with 3-tick temporal persistence of ML score anomalies
    if len(recent_sample_states) > 0 and all(st == "CRITICAL" for st in recent_sample_states):
        if len(df_engineered) >= 3:
            system_state = "CRITICAL"
            state_reason = f"IsolationForest score ({score:.4f}) continuously below threshold ({threshold:.4f}) for 3+ ticks."
        else:
            system_state = "WARNING"
            state_reason = f"IsolationForest score ({score:.4f}) below threshold ({threshold:.4f}) — evaluating temporal persistence."
    elif any(st in ["CRITICAL", "WARNING"] for st in recent_sample_states):
        system_state = "WARNING"
        state_reason = f"Transient score fluctuation near threshold ({score:.4f} vs threshold {threshold:.4f})."
    else:
        system_state = "SECURE"
        state_reason = f"System behavior within learned baseline (score {score:.4f} >= threshold {threshold:.4f})."
        
    return {
        "score": score,
        "threshold": threshold,
        "raw_is_anomaly": raw_is_anomaly,
        "culprit_proc": culprit,
        "is_currently_running": currently_running,
        "threat_confidence": threat_confidence,
        "sample_state": latest_sample_state,
        "system_state": system_state,
        "state_reason": state_reason
    }
