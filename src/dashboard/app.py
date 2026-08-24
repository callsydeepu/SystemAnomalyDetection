import os
import sys
import warnings

os.environ["PYTHONWARNINGS"] = "ignore"
warnings.filterwarnings("ignore")

import streamlit as st
import pandas as pd
import numpy as np
import time
import psutil
import io
import subprocess
from pathlib import Path

# ─────────────────────────────────────────────
# PATHS & IMPORTS FROM SRC
# ─────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

DATA_FILE = PROJECT_ROOT / "data" / "system_data.csv"
MODELS_DIR = PROJECT_ROOT / "models"

from src.monitoring.process_monitor import is_process_currently_running
from src.features.feature_engineering import engineer_features, FEATURES
from src.anomaly_detection.model import load_trained_models, check_models_exist
from src.anomaly_detection.baseline import compute_xai_explanations
from src.anomaly_detection.predictor import evaluate_latest_sample

# ─────────────────────────────────────────────
# PAGE CONFIG & CSS
# ─────────────────────────────────────────────
st.set_page_config(page_title="AI Sentinel SOC", layout="wide", page_icon="🛡️")

def inject_custom_css():
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap');
    
    html, body, [class*="css"], .stText, .stMarkdown {
        font-family: 'Outfit', sans-serif;
    }
    
    .status-secure {
        background: linear-gradient(135deg, #052e16 0%, #064e3b 100%);
        border: 1px solid #10b981;
        box-shadow: 0 4px 20px rgba(16, 185, 129, 0.2);
        color: #34d399;
        padding: 24px;
        border-radius: 12px;
        text-align: center;
        font-size: 26px;
        font-weight: 700;
        margin-bottom: 25px;
    }

    .status-evaluating {
        background: linear-gradient(135deg, #451a03 0%, #78350f 100%);
        border: 1px solid #f59e0b;
        box-shadow: 0 4px 20px rgba(245, 158, 11, 0.3);
        color: #fbbf24;
        padding: 24px;
        border-radius: 12px;
        text-align: center;
        font-size: 26px;
        font-weight: 700;
        margin-bottom: 25px;
    }

    .status-threat {
        background: linear-gradient(135deg, #450a0a 0%, #7f1d1d 100%);
        border: 2px solid #ef4444;
        box-shadow: 0 4px 25px rgba(239, 68, 68, 0.4);
        color: #f87171;
        padding: 24px;
        border-radius: 12px;
        text-align: center;
        font-size: 26px;
        font-weight: 700;
        margin-bottom: 25px;
        animation: pulse 2s infinite;
    }

    .status-inactive {
        background: linear-gradient(135deg, #1e1b4b 0%, #312e81 100%);
        border: 1px solid #6366f1;
        box-shadow: 0 4px 20px rgba(99, 102, 241, 0.2);
        color: #a5b4fc;
        padding: 24px;
        border-radius: 12px;
        text-align: center;
        font-size: 26px;
        font-weight: 700;
        margin-bottom: 25px;
    }

    .status-paused {
        background: linear-gradient(135deg, #18181b 0%, #27272a 100%);
        border: 1px solid #71717a;
        color: #a1a1aa;
        padding: 24px;
        border-radius: 12px;
        text-align: center;
        font-size: 26px;
        font-weight: 700;
        margin-bottom: 25px;
    }

    @keyframes pulse {
        0% { transform: scale(1); }
        50% { transform: scale(1.01); }
        100% { transform: scale(1); }
    }

    .card {
        background-color: #0f172a;
        border: 1px solid #1e293b;
        border-radius: 10px;
        padding: 20px;
        margin-bottom: 15px;
    }

    .metric-value {
        font-size: 28px;
        font-weight: 700;
        color: #f8fafc;
    }

    .metric-label {
        font-size: 14px;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    .xai-badge-red {
        background-color: #7f1d1d;
        color: #fca5a5;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 600;
        display: inline-block;
        margin: 2px;
    }

    .xai-badge-amber {
        background-color: #78350f;
        color: #fde68a;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 600;
        display: inline-block;
        margin: 2px;
    }
    </style>
    """, unsafe_allow_html=True)

inject_custom_css()

# ─────────────────────────────────────────────
# TELEMETRY PROCESS HELPERS
# ─────────────────────────────────────────────
def is_collector_running():
    for p in psutil.process_iter(["pid", "cmdline"]):
        try:
            cmdline = " ".join(p.info.get("cmdline") or [])
            if "collect_data.py" in cmdline:
                return p
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return None

def start_collector():
    p = is_collector_running()
    if not p:
        cmd = [sys.executable, str(PROJECT_ROOT / "scripts" / "collect_data.py")]
        subprocess.Popen(cmd, cwd=str(PROJECT_ROOT))
        time.sleep(1)

def stop_collector():
    p = is_collector_running()
    if p:
        try:
            p.terminate()
            p.wait(timeout=2)
        except Exception:
            pass

def kill_top_cpu_process(proc_name):
    if not proc_name or proc_name.lower() in ["system", "unknown", "system idle process"]:
        return False, "Cannot terminate core OS / System Idle process."
    
    pname_clean = proc_name.strip().lower()
    base_name = pname_clean[:-4] if pname_clean.endswith(".exe") else pname_clean
    
    killed_any = False
    messages = []
    
    for p in psutil.process_iter(['pid', 'name']):
        try:
            name = (p.info.get('name') or "").strip().lower()
            if not name:
                continue
            proc_base = name[:-4] if name.endswith(".exe") else name
            
            if name == pname_clean or proc_base == base_name:
                pid = p.info['pid']
                if pid == os.getpid():
                    continue
                p_obj = psutil.Process(pid)
                p_obj.terminate()
                killed_any = True
                messages.append(f"Terminated {name} (PID: {pid})")
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            messages.append(f"Access Denied for PID {p.info.get('pid')}: {e}")
        except Exception as e:
            messages.append(str(e))
            
    if killed_any:
        return True, " | ".join(messages)
    return False, f"No active process matching '{proc_name}' could be terminated."

# ─────────────────────────────────────────────
# COLD-START CALIBRATION WIZARD
# ─────────────────────────────────────────────
def run_calibration_wizard():
    st.warning("**System Not Calibrated**: Training data not found. Please run the data collection process to create your system baseline.")
    st.markdown("""
    Welcome to **AI Sentinel SOC**. Before monitoring can start on your computer, the system must collect baseline telemetry from your own operating system to train your machine's Isolation Forest anomaly detector.
    """)
    
    col_c1, col_c2 = st.columns(2)
    with col_c1:
        if st.button("🚀 Start Background Data Collector", type="primary"):
            start_collector()
            st.rerun()
    with col_c2:
        if DATA_FILE.exists():
            df_existing = pd.read_csv(DATA_FILE)
            st.info(f"Currently Collected Baseline Rows: **{len(df_existing)}** / 100 required")
        else:
            st.info("Currently Collected Baseline Rows: **0** / 100 required")

    running_proc = is_collector_running()
    if running_proc:
        st.success(f"Telemetry Collector is RUNNING in background (PID: {running_proc.pid}).")
    else:
        st.error("elemetry Collector is currently STOPPED.")

    if DATA_FILE.exists():
        df_tmp = pd.read_csv(DATA_FILE)
        num_rows = len(df_tmp)
        progress = min(1.0, num_rows / 100.0)
        st.progress(progress)
        
        if num_rows >= 100:
            st.success("Sufficient baseline data collected! Click below to train the model.")
            if st.button("Train Anomaly Detection Model Now", type="primary"):
                with st.spinner("Training Isolation Forest Model..."):
                    train_script = PROJECT_ROOT / "scripts" / "train_model.py"
                    res = subprocess.run([sys.executable, str(train_script)], cwd=str(PROJECT_ROOT), capture_output=True, text=True)
                    if res.returncode == 0:
                        st.toast("Model trained successfully!")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error(f"Training failed: {res.stderr}")
        else:
            st.info(f"Gathering telemetry samples... ({num_rows}/100 rows). Page will auto-refresh.")
            time.sleep(3)
            st.rerun()
    st.stop()

# Load Trained Models or trigger wizard
model, scaler, features, stats = load_trained_models()
if model is None or scaler is None or features is None:
    run_calibration_wizard()

DEFAULT_WHITELIST = """System Idle Process
svchost.exe
lsass.exe"""

model_default_threshold = float(getattr(model, "offset_", -0.600))

defaults = {
    "alert_log":               [],
    "auto_kill_log":           [],
    "last_alert_time":         0,
    "last_alert_proc":         "",
    "last_autokill_time":      0,
    "whitelist_raw":           DEFAULT_WHITELIST,
    "refresh_rate":            2,
    "history_rows":            60,
    "score_threshold":         model_default_threshold,
    "user_overrode_threshold": False,
    "auto_kill":               False,
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

# If user has not explicitly overridden threshold, sync with model default
if not st.session_state.get("user_overrode_threshold", False):
    st.session_state.score_threshold = model_default_threshold

# ─────────────────────────────────────────────
# TABS
# ─────────────────────────────────────────────
tab_live, tab_memory, tab_history, tab_settings = st.tabs([
    "Live Monitor", "Memory Usage", "Security Audit Log", "Settings"
])

# ─────────────────────────────────────────────
# SETTINGS TAB
# ─────────────────────────────────────────────
with tab_settings:
    st.header("SOC Settings")
    col_a, col_b = st.columns(2)
    
    with col_a:
        st.subheader("Detection Sensitivity")
        st.session_state.refresh_rate = st.slider(
            "Refresh Rate (seconds)", 1, 5, st.session_state.refresh_rate)
        st.session_state.history_rows = st.slider(
            "History window (rows)", 30, 200, st.session_state.history_rows)
        
        current_threshold = st.session_state.score_threshold
        chosen_threshold = st.slider(
            "Anomaly score threshold", -0.900, -0.300,
            float(current_threshold), step=0.025,
            help=f"Trained IsolationForest model default boundary (offset_): {model_default_threshold:.4f}. Slide to override threshold.")
        if chosen_threshold != current_threshold:
            st.session_state.score_threshold = chosen_threshold
            st.session_state.user_overrode_threshold = True

        if st.session_state.get("user_overrode_threshold", False):
            if st.button("Reset Threshold to Model Default"):
                st.session_state.score_threshold = model_default_threshold
                st.session_state.user_overrode_threshold = False
                st.rerun()

        st.session_state.auto_kill = st.checkbox(
            "Enable Automated Threat Response (Auto-Kill Malicious Top Process)",
            st.session_state.auto_kill)

    with col_b:
        st.subheader("Process Whitelist")
        st.session_state.whitelist_raw = st.text_area(
            "Ignored process names (one per line)",
            st.session_state.whitelist_raw, height=180)
        
        st.subheader("Model Management")
        if st.button("Retrain Anomaly Detection Model"):
            with st.spinner("Retraining Isolation Forest model on latest CSV data..."):
                train_script = PROJECT_ROOT / "scripts" / "train_model.py"
                res = subprocess.run([sys.executable, str(train_script)], cwd=str(PROJECT_ROOT), capture_output=True, text=True)
                if res.returncode == 0:
                    st.toast("Model successfully retrained!")
                    st.session_state.user_overrode_threshold = False
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error(f"Retraining failed: {res.stderr}")

whitelist = [
    p.strip().lower()
    for p in st.session_state.whitelist_raw.splitlines()
    if p.strip()
]
refresh_rate    = st.session_state.refresh_rate
history_rows    = st.session_state.history_rows
score_threshold = st.session_state.score_threshold
auto_kill       = st.session_state.auto_kill

# ─────────────────────────────────────────────
# DATA LOADING & EVALUATION PIPELINE
# ─────────────────────────────────────────────
if not DATA_FILE.exists():
    st.warning("`data/system_data.csv` not found. Starting telemetry collector...")
    start_collector()
    st.rerun()

df_raw = pd.read_csv(DATA_FILE)
if len(df_raw) < 5:
    st.info("Collecting initial telemetry data... Please wait.")
    start_collector()
    time.sleep(2)
    st.rerun()

df = engineer_features(df_raw.tail(history_rows))
current = df.iloc[-1].to_dict()

# Telemetry Staleness Protection
data_age = 0
if "timestamp" in current:
    try:
        data_ts = time.mktime(time.strptime(str(current["timestamp"]), "%Y-%m-%d %H:%M:%S"))
        data_age = max(0, int(time.time() - data_ts))
    except Exception:
        data_age = 0

is_stale = data_age > 15

# Evaluation via predictor module
eval_res = evaluate_latest_sample(df, model, scaler, features, threshold=score_threshold, whitelist=whitelist)
score = eval_res["score"]
raw_is_anomaly = eval_res["raw_is_anomaly"]
culprit = eval_res["culprit_proc"]
is_currently_running = eval_res["is_currently_running"]
threat_confidence = eval_res["threat_confidence"]
sample_state = eval_res["sample_state"]
system_state = eval_res["system_state"]

is_whitelisted = culprit.lower() in whitelist
real_anomaly = (sample_state in ["WARNING", "CRITICAL"]) and not is_whitelisted and not is_stale
is_confirmed_threat = (system_state == "CRITICAL")

# Compute Session Anomaly Trend
df["is_anom"] = False
if len(df) > 0:
    X_hist = df[features].values
    X_hist_scaled = scaler.transform(X_hist)
    scores_hist = model.score_samples(X_hist_scaled)
    df["score"] = scores_hist
    df["is_anom"] = (df["score"] < score_threshold) | (df["cpu"] >= 95.0) | (df["ram"] >= 95.0)

if "timestamp" in df.columns:
    df["minute"] = df["timestamp"].astype(str).str.slice(0, 16)
else:
    df["minute"] = "recent"
anom_per_min = df.groupby("minute")["is_anom"].sum().reset_index()
anom_per_min.columns = ["minute", "anomalies"]

# Automated Mitigation
if is_confirmed_threat and is_currently_running and auto_kill and not is_whitelisted:
    now_t = time.time()
    if now_t - st.session_state.last_autokill_time > 10:
        success, msg = kill_top_cpu_process(culprit)
        st.session_state.last_autokill_time = now_t
        st.session_state.auto_kill_log.append({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "target": culprit,
            "score": round(score, 4),
            "success": success,
            "details": msg
        })
        if success:
            st.toast(f"Auto-Kill Triggered: {msg}")

# Alert Logging
if is_confirmed_threat and is_currently_running:
    now_t = time.time()
    if (now_t - st.session_state.last_alert_time > 10) or (culprit != st.session_state.last_alert_proc):
        st.session_state.last_alert_time = now_t
        st.session_state.last_alert_proc = culprit
        st.session_state.alert_log.append({
            "timestamp": current.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S")),
            "process":   culprit,
            "score":     round(score, 4),
            "cpu":       current["cpu"],
            "ram":       current["ram"],
            "disk":      current["disk"],
            "action":    "Auto-Killed" if (auto_kill and not is_whitelisted) else "Flagged"
        })

# ─────────────────────────────────────────────
# LIVE MONITOR TAB
# ─────────────────────────────────────────────
with tab_live:
    # Header Control Bar
    col_h1, col_h2 = st.columns([3, 1])
    with col_h1:
        st.title("AI Sentinel: Live Monitor Dashboard")
    with col_h2:
        collector_p = is_collector_running()
        if collector_p:
            st.success(f"Monitor Active (PID: {collector_p.pid})")
            if st.button("Stop Collector"):
                stop_collector()
                st.rerun()
        else:
            st.error("Monitor Stopped")
            if st.button("Start Collector"):
                start_collector()
                st.rerun()

    # Status Banner
    if is_stale:
        st.markdown(f"""
        <div class="status-paused">
            TELEMETRY PAUSED (Data is {data_age}s old — Collector is Offline)
        </div>
        """, unsafe_allow_html=True)
    elif system_state == "CRITICAL" and is_currently_running:
        st.markdown(f"""
        <div class="status-threat">
            CONFIRMED ANOMALY FLAGGED: {culprit.upper()}
        </div>
        """, unsafe_allow_html=True)
    elif system_state == "CRITICAL" and not is_currently_running:
        st.markdown(f"""
        <div class="status-inactive">
            HISTORICAL INACTIVE ANOMALY: {culprit.upper()} (Process Terminated on OS)
        </div>
        """, unsafe_allow_html=True)
    elif system_state == "WARNING":
        st.markdown(f"""
        <div class="status-evaluating">
            SYSTEM WARNING: HIGH RESOURCE UTILIZATION / TRANSIENT SPIKE ({culprit.upper()})
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="status-secure">
            SYSTEM STATE: SECURE
        </div>
        """, unsafe_allow_html=True)

    # Key Metrics Bar
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        if is_stale:
            st.metric("State Indicator", "PAUSED", help="Telemetry is stale")
        elif system_state == "CRITICAL" and is_currently_running:
            st.metric("State Indicator", "CRITICAL", delta="HIGH RISK", delta_color="inverse")
        elif system_state == "CRITICAL" and not is_currently_running:
            st.metric("State Indicator", "INACTIVE", delta="PROCESS TERMINATED")
        elif system_state == "WARNING":
            st.metric("State Indicator", "WARNING", delta="EVALUATING")
        else:
            st.metric("State Indicator", "SECURE", delta="NORMAL")

    with m2:
        st.metric("Threat Confidence", f"{threat_confidence:.1f}%", delta=f"score {score:.4f}")

    with m3:
        st.metric("CPU Usage", f"{current['cpu']:.1f}%", delta=f"Δ {current['cpu_delta']:.1f}%")

    with m4:
        total_ram_gb = current.get('ram_total_gb', 16.0)
        live_ram_gb = current.get('ram_used_gb', (current['ram'] / 100.0) * total_ram_gb)
        avail_ram_gb = total_ram_gb - live_ram_gb
        st.metric("Memory Usage", f"{current['ram']:.1f}%", delta=f"{live_ram_gb:.1f}/{total_ram_gb:.1f} GB")

    st.markdown("---")

    # Real-Time Charts
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("CPU & RAM % Utilization")
        st.line_chart(df[["cpu", "ram"]])

    with col2:
        st.subheader("Telemetry Anomaly Score (lower = suspicious)")
        chart_score = df[["score"]].copy()
        chart_score["threshold"] = score_threshold
        st.line_chart(chart_score)

    col3, col4 = st.columns(2)
    with col3:
        st.subheader("Network Activity (bytes)")
        st.line_chart(df[["net_total"]])
    with col4:
        st.subheader("Anomalies Per Minute (Session-wide)")
        st.bar_chart(anom_per_min.set_index("minute")["anomalies"])

    # Explainable AI (XAI) Section
    if real_anomaly:
        st.markdown("---")
        st.markdown("###Threat Diagnostic Breakdown (Explainable AI)")
        st.write("The features below triggered the anomaly classification based on deviation from baseline bounds:")
        
        explanations = compute_xai_explanations(current, stats, features)
        if explanations:
            for exp in explanations:
                f_name = exp["name"]
                val = exp["value"]
                mean = exp["mean"]
                z = exp["z"]
                direction = exp["direction"]
                
                badge_cls = "xai-badge-red" if abs(z) >= 2.5 else "xai-badge-amber"
                st.markdown(f"""
                <div style="background-color: #0f172a; padding: 12px; border-radius: 8px; margin-bottom: 8px; border-left: 4px solid #ef4444;">
                    <span class="{badge_cls}">Z = {z:+.2f}σ</span>
                    <strong>{f_name}</strong> {direction} to <code>{val:.2f}</code> (Baseline mean: <code>{mean:.2f}</code>)
                </div>
                """, unsafe_allow_html=True)

        # Threat Control Panel
        st.markdown("---")
        st.subheader(f"Active Threat Mitigation Options for `{culprit.upper()}`")
        col_kill, col_whitelist = st.columns(2)
        with col_kill:
            if st.button(f"Immediately Terminate Process ({culprit})", type="primary"):
                with st.spinner(f"Terminating {culprit}..."):
                    success, msg = kill_top_cpu_process(culprit)
                    if success:
                        if st.session_state.alert_log:
                            st.session_state.alert_log[-1]["action"] = "manually killed"
                        st.toast(f"{msg}")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.warning(msg)
        with col_whitelist:
            if st.button(f"Whitelist {culprit.upper()}"):
                st.session_state.whitelist_raw += f"\n{culprit}"
                st.toast(f"Added {culprit} to whitelist.")
                time.sleep(1)
                st.rerun()

# ─────────────────────────────────────────────
# MEMORY USAGE TAB
# ─────────────────────────────────────────────
with tab_memory:
    st.title("🧠 Advanced Memory Metrics")
    mc1, mc2, mc3, mc4 = st.columns(4)
    with mc1:
        st.metric("RAM Used", f"{live_ram_gb:.2f} GB", delta=f"{current['ram']:.1f}% of total")
    with mc2:
        st.metric("RAM Available", f"{avail_ram_gb:.2f} GB", delta=f"{100 - current['ram']:.1f}% free")
    with mc3:
        st.metric("Total RAM Capacity", f"{total_ram_gb:.2f} GB")
    with mc4:
        swap = psutil.swap_memory()
        st.metric("Swap Allocation Used", f"{swap.used / (1024**3):.2f} GB", delta=f"{swap.percent:.1f}%")
        
    st.markdown("---")
    st.subheader("Memory Utilization History")
    st.line_chart(df[["ram"]])
    
    col_m1, col_m2 = st.columns(2)
    with col_m1:
        st.subheader("Memory Used (GB)")
        if "ram_used_gb" in df.columns and df["ram_used_gb"].notna().any():
            mem_gb_chart = df[["ram_used_gb"]].copy()
            mem_gb_chart.columns = ["Used GB"]
            st.line_chart(mem_gb_chart)
        else:
            approx_gb = (df["ram"] / 100.0 * total_ram_gb).round(2)
            approx_df = pd.DataFrame({"Used GB (approx)": approx_gb})
            st.line_chart(approx_df)
    with col_m2:
        st.subheader("Memory Rate of Change (% per sample)")
        ram_delta_chart = df[["ram_delta"]].copy()
        ram_delta_chart.columns = ["RAM delta %"]
        st.line_chart(ram_delta_chart)

# ─────────────────────────────────────────────
# SECURITY AUDIT LOG TAB
# ─────────────────────────────────────────────
with tab_history:
    st.header("📋 Security Audit & Threat Log")
    if not st.session_state.alert_log:
        st.info("No security alerts logged during this SOC session.")
    else:
        log_df = pd.DataFrame(st.session_state.alert_log[::-1])
        st.dataframe(log_df)
        
        csv_buf = io.StringIO()
        log_df.to_csv(csv_buf, index=False)
        st.download_button(
            label="⬇️ Export Security Log as CSV",
            data=csv_buf.getvalue(),
            file_name=f"sentinel_alerts_{time.strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
        if st.button("🗑️ Clear SOC Alert Logs"):
            st.session_state.alert_log = []
            st.rerun()
            
    if st.session_state.auto_kill_log:
        st.markdown("---")
        st.subheader("🤖 Automated Response Mitigation Logs")
        st.dataframe(pd.DataFrame(st.session_state.auto_kill_log[::-1]))

# ─────────────────────────────────────────────
# REFRESH ENGINE
# ─────────────────────────────────────────────
time.sleep(refresh_rate)
st.rerun()
