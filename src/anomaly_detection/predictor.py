import numpy as np
import pandas as pd
from src.monitoring.process_monitor import is_process_currently_running, get_process_info
from src.monitoring.allowlist import check_process_allowlist
import warnings

warnings.filterwarnings("ignore")

def _clean_process_name(raw_name):
    if raw_name is None or pd.isna(raw_name):
        return "Unknown"
    s = str(raw_name).strip()
    return "Unknown" if s.lower() in ("", "nan", "none") else s

def evaluate_latest_sample(df_engineered, model, scaler, features, threshold=None, whitelist=None, proc_info=None):
    """
    Evaluates latest row from engineered telemetry DataFrame against IsolationForest model
    and the robust Windows System Process Allowlist.
    
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
    - allowlist_eval (dict)
    - is_whitelisted (bool)
    - is_suppressed (bool)
    - is_masquerading (bool)
    - is_resource_spike (bool)
    - threat_type (str)
    """
    if threshold is None:
        threshold = float(getattr(model, "offset_", -0.600)) if model is not None else -0.600

    empty_allowlist_eval = {
        "is_allowlisted": False,
        "is_system_proc": False,
        "is_masquerading": False,
        "is_suppressed": False,
        "is_resource_spike": False,
        "threat_type": "NONE",
        "reason": "No telemetry data or model available.",
        "verified_path": ""
    }

    if df_engineered is None or len(df_engineered) == 0 or model is None or scaler is None:
        return {
            "score": 0.0,
            "threshold": threshold,
            "raw_is_anomaly": False,
            "culprit_proc": "Unknown",
            "is_currently_running": False,
            "threat_confidence": 0.0,
            "sample_state": "NORMAL",
            "system_state": "SECURE",
            "state_reason": "No telemetry data or model available.",
            "allowlist_eval": empty_allowlist_eval,
            "is_whitelisted": False,
            "is_suppressed": False,
            "is_masquerading": False,
            "is_resource_spike": False,
            "threat_type": "NONE"
        }
        
    latest_row = df_engineered.iloc[-1]
    raw_vals = [pd.to_numeric(latest_row.get(f, 0.0), errors="coerce") for f in features]
    X_latest = np.asarray(raw_vals, dtype=float).reshape(1, -1)
    X_latest = np.nan_to_num(X_latest, nan=0.0, posinf=0.0, neginf=0.0)
    X_scaled = scaler.transform(X_latest)
    
    score = float(model.score_samples(X_scaled)[0])
    raw_is_anomaly = score < threshold
    
    culprit = _clean_process_name(latest_row.get("top_process", "Unknown"))
    currently_running = is_process_currently_running(culprit)

    if proc_info is None and culprit.lower() not in ("system", "system idle process", "registry", "unknown"):
        try:
            proc_info = get_process_info(culprit)
        except Exception:
            proc_info = None

    latest_cpu = float(pd.to_numeric(latest_row.get("cpu", 0.0), errors="coerce") or 0.0)
    latest_ram = float(pd.to_numeric(latest_row.get("ram", 0.0), errors="coerce") or 0.0)

    # Robust Windows Allowlist Validation
    allowlist_eval = check_process_allowlist(
        proc_name=culprit,
        proc_info=proc_info,
        cpu=latest_cpu,
        ram=latest_ram,
        score=score,
        threshold=threshold,
        custom_whitelist=whitelist
    )

    is_masquerading = allowlist_eval["is_masquerading"]
    is_resource_spike = allowlist_eval["is_resource_spike"]
    is_suppressed = allowlist_eval["is_suppressed"]
    is_whitelisted = allowlist_eval["is_allowlisted"]

    # Calculate effective latest score and threat confidence
    if is_masquerading:
        # Masquerading attack detected (MITRE ATT&CK T1036) — force critical threat
        effective_latest_score = min(score, threshold - 0.05)
        threat_confidence = max(95.0, min(100.0, (threshold - effective_latest_score) / (abs(threshold) + 1e-5) * 100.0))
    elif is_resource_spike:
        # Allowlisted system process with genuine abnormal CPU/RAM spike — alert without suppression!
        effective_latest_score = min(score, threshold - 0.01)
        threat_confidence = max(80.0, min(100.0, (threshold - effective_latest_score) / (abs(threshold) + 1e-5) * 100.0))
    elif is_suppressed:
        # Benign system process normal activity — suppress low-value alert
        effective_latest_score = threshold + 1.0
        threat_confidence = 0.0
    else:
        # Unknown / standard process evaluated strictly by IsolationForest anomaly score
        effective_latest_score = score
        if effective_latest_score < threshold:
            threat_confidence = max(0.0, min(100.0, (threshold - effective_latest_score) / (abs(threshold) + 1e-5) * 100.0))
        else:
            threat_confidence = 0.0

    # Determine states for recent samples to enforce temporal persistence
    last_n = min(3, len(df_engineered))
    recent_rows = df_engineered.tail(last_n)
    
    recent_matrix = []
    for i in range(last_n):
        row = recent_rows.iloc[i]
        vals = [pd.to_numeric(row.get(f, 0.0), errors="coerce") for f in features]
        recent_matrix.append(vals)
        
    X_recent = np.asarray(recent_matrix, dtype=float)
    X_recent = np.nan_to_num(X_recent, nan=0.0, posinf=0.0, neginf=0.0)
    X_recent_scaled = scaler.transform(X_recent)
    recent_scores = model.score_samples(X_recent_scaled)
    
    recent_sample_states = []
    for i in range(last_n):
        r = recent_rows.iloc[i]
        s = float(recent_scores[i])
        p = _clean_process_name(r.get("top_process", "Unknown"))
        r_cpu = float(pd.to_numeric(r.get("cpu", 0.0), errors="coerce") or 0.0)
        r_ram = float(pd.to_numeric(r.get("ram", 0.0), errors="coerce") or 0.0)

        r_eval = check_process_allowlist(
            proc_name=p,
            proc_info=proc_info if i == (last_n - 1) else None,
            cpu=r_cpu,
            ram=r_ram,
            score=s,
            threshold=threshold,
            custom_whitelist=whitelist
        )

        if r_eval["is_masquerading"]:
            eff_s = min(s, threshold - 0.05)
        elif r_eval["is_resource_spike"]:
            eff_s = min(s, threshold - 0.01)
        elif r_eval["is_suppressed"]:
            eff_s = threshold + 1.0
        else:
            eff_s = s
        
        if eff_s < threshold:
            st = "CRITICAL"
        elif eff_s < (threshold + 0.05):
            st = "WARNING"
        else:
            st = "NORMAL"
        recent_sample_states.append(st)
        
    latest_sample_state = recent_sample_states[-1] if recent_sample_states else "NORMAL"
    
    # System state with 3-tick temporal persistence of ML score anomalies
    if is_masquerading:
        system_state = "CRITICAL"
        state_reason = f"MASQUERADING ALERT: {allowlist_eval['reason']}"
    elif is_resource_spike:
        system_state = "CRITICAL" if latest_sample_state == "CRITICAL" else "WARNING"
        state_reason = f"RESOURCE ALERT: {allowlist_eval['reason']}"
    elif len(recent_sample_states) > 0 and all(st == "CRITICAL" for st in recent_sample_states):
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
        "state_reason": state_reason,
        "allowlist_eval": allowlist_eval,
        "is_whitelisted": is_whitelisted,
        "is_suppressed": is_suppressed,
        "is_masquerading": is_masquerading,
        "is_resource_spike": is_resource_spike,
        "threat_type": allowlist_eval["threat_type"]
    }
