import streamlit as st
import pandas as pd
import numpy as np
import joblib
import os
import time
import psutil
import io
import subprocess
import sys
import warnings

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────
# PAGE CONFIG & CSS
# ─────────────────────────────────────────────
st.set_page_config(page_title="AI Sentinel SOC", layout="wide", page_icon="🛡️")

def inject_custom_css():
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap');
    
    /* Global style resets and fonts */
    html, body, [class*="css"], .stText, .stMarkdown {
        font-family: 'Outfit', sans-serif;
    }
    
    /* Modern Glassmorphic Container */
    .metric-container {
        background: rgba(17, 22, 34, 0.7);
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        border: 1px solid rgba(255, 255, 255, 0.05);
        border-radius: 12px;
        padding: 20px;
        margin-bottom: 15px;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        transition: all 0.3s ease;
    }
    
    .metric-container:hover {
        border-color: rgba(0, 229, 255, 0.35);
        transform: translateY(-2px);
        box-shadow: 0 12px 40px 0 rgba(0, 229, 255, 0.1);
    }
    
    /* Pulse Glow Status Cards */
    .status-card {
        border-radius: 12px;
        padding: 20px;
        text-align: center;
        font-weight: 700;
        font-size: 1.4rem;
        letter-spacing: 1.5px;
        margin-bottom: 20px;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.4);
    }
    
    .status-secure {
        background: linear-gradient(135deg, rgba(0, 230, 118, 0.15) 0%, rgba(0, 230, 118, 0.02) 100%);
        border: 2px solid #00E676;
        color: #00E676;
        text-shadow: 0 0 10px rgba(0, 230, 118, 0.4);
        animation: pulse-green 2.5s infinite;
    }
    
    .status-anomaly {
        background: linear-gradient(135deg, rgba(255, 23, 68, 0.15) 0%, rgba(255, 23, 68, 0.02) 100%);
        border: 2px solid #FF1744;
        color: #FF1744;
        text-shadow: 0 0 10px rgba(255, 23, 68, 0.4);
        animation: pulse-red 2s infinite;
    }
    
    @keyframes pulse-green {
        0% { box-shadow: 0 0 5px rgba(0, 230, 118, 0.2); }
        50% { box-shadow: 0 0 25px rgba(0, 230, 118, 0.5); }
        100% { box-shadow: 0 0 5px rgba(0, 230, 118, 0.2); }
    }
    
    @keyframes pulse-red {
        0% { box-shadow: 0 0 5px rgba(255, 23, 68, 0.2); }
        50% { box-shadow: 0 0 25px rgba(255, 23, 68, 0.6); }
        100% { box-shadow: 0 0 5px rgba(255, 23, 68, 0.2); }
    }
    
    /* Explainable AI Cards */
    .xai-card {
        background: rgba(22, 28, 45, 0.85);
        border-radius: 8px;
        padding: 14px 18px;
        margin-bottom: 12px;
        border-left: 5px solid #00E5FF;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.15);
    }
    
    .xai-feature {
        font-weight: 700;
        font-size: 1rem;
        letter-spacing: 0.5px;
    }
    
    .xai-details {
        font-size: 0.88rem;
        color: #B0C4DE;
        margin-top: 4px;
        line-height: 1.4;
    }
    
    /* Hide default Streamlit padding */
    .block-container {
        padding-top: 2rem !important;
        padding-bottom: 2rem !important;
    }
    </style>
    """, unsafe_allow_html=True)

inject_custom_css()

# ─────────────────────────────────────────────
# DATA PROCESS MANAGEMENT & HELPERS
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
    try:
        subprocess.Popen([sys.executable, "collect_data.py"])
        return True, "Collector started."
    except Exception as e:
        return False, str(e)

def stop_collector():
    p = is_collector_running()
    if p:
        try:
            p.terminate()
            return True, "Collector stopped."
        except Exception as e:
            return False, str(e)
    return False, "Collector is not running."

def is_process_currently_running(process_name):
    if not process_name or process_name.lower() in ["system", "unknown", "system idle process"]:
        return True
    pname_clean = process_name.strip().lower()
    base_name = pname_clean[:-4] if pname_clean.endswith(".exe") else pname_clean
    for p in psutil.process_iter(['name', 'cmdline']):
        try:
            name = (p.info.get('name') or "").strip().lower()
            cmdline = " ".join(p.info.get('cmdline') or []).lower()
            if "controlled_workload" in pname_clean and "controlled_workload" in cmdline:
                return True
            if not name:
                continue
            proc_base = name[:-4] if name.endswith(".exe") else name
            if name == pname_clean or proc_base == base_name:
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return False

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

def score_to_confidence(score, threshold=-0.600):
    if score >= threshold:
        return 0.0
    max_score  = threshold
    min_score  = -0.80
    confidence = (max_score - score) / (max_score - min_score)
    return round(min(max(confidence, 0.0), 1.0) * 100, 1)

OWN_PID = os.getpid()

def get_protected_pids():
    protected = {OWN_PID}
    try:
        me = psutil.Process(OWN_PID)
        for parent in me.parents():
            protected.add(parent.pid)
        for child in me.children(recursive=True):
            protected.add(child.pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    for p in psutil.process_iter(["pid"]):
        try:
            for f in p.open_files():
                if "system_data" in f.path.lower():
                    protected.add(p.pid)
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError, OSError):
            pass
    for p in psutil.process_iter(["pid", "cmdline"]):
        try:
            cmdline = " ".join(p.info.get("cmdline") or [])
            if "collect_data" in cmdline.lower():
                protected.add(p.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return protected

def kill_top_cpu_process(culprit_name):
    protected = get_protected_pids()
    killed_any = False
    for p in psutil.process_iter(['name', 'pid']):
        try:
            pname = p.info['name'] or ""
            pid   = p.info['pid']
            if culprit_name.lower() in pname.lower() or (pname.lower() == "python.exe" and "inject" in culprit_name.lower()):
                if pid not in protected:
                    p.terminate()
                    killed_any = True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if killed_any:
        return True, f"Successfully stopped {culprit_name}."
    return False, "Process not found or Access Denied."

@st.cache_resource
def load_assets():
    try:
        model    = joblib.load("anomaly_model.pkl")
        scaler   = joblib.load("scaler.pkl")
        features = joblib.load("feature_list.pkl")
        stats    = joblib.load("baseline_stats.pkl") if os.path.exists("baseline_stats.pkl") else None
        return model, scaler, features, stats
    except Exception:
        return None, None, None, None

# Load assets
model, scaler, FEATURES, stats = load_assets()

# ─────────────────────────────────────────────
# INITIALIZATION WIZARD (COLD START)
# ─────────────────────────────────────────────
csv_exists = os.path.exists("system_data.csv")
num_rows = 0
if csv_exists:
    try:
        with open("system_data.csv", "r") as f:
            num_rows = sum(1 for _ in f) - 1
    except Exception:
        pass

has_model = model is not None and scaler is not None and FEATURES is not None
unlocked = st.session_state.get("unlocked_override", False) or (has_model and num_rows >= 100)

if not unlocked:
    st.title("🛡️ AI Sentinel — Autonomous Anomaly Detection SOC")
    st.markdown("### ⚙️ System Setup & Calibration Wizard")
    st.write(
        "To perform system-adaptive anomaly detection, we must calibrate the machine learning baseline "
        "on your system. This resolves the **cold start** issue."
    )
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("<div class='metric-container'>", unsafe_allow_html=True)
        st.markdown("#### 📡 1. Telemetry Calibration")
        st.write("Collect at least **100 baseline rows** (approx. 1.5 minutes) representing normal system idle/usage activity.")
        
        running_proc = is_collector_running()
        if running_proc:
            st.success(f"🟢 Active (PID: {running_proc.pid})")
            if st.button("⏹️ Stop Telemetry Collector", key="wiz_stop_coll"):
                stop_collector()
                st.rerun()
        else:
            st.error("🔴 Stopped")
            if st.button("▶️ Start Telemetry Collector", key="wiz_start_coll"):
                start_collector()
                st.rerun()
                
        prog = min(1.0, max(0.0, num_rows / 100.0))
        st.progress(prog)
        st.write(f"**Baseline Telemetry Progress:** {num_rows} / 100 rows")
        st.markdown("</div>", unsafe_allow_html=True)
        
    with col2:
        st.markdown("<div class='metric-container'>", unsafe_allow_html=True)
        st.markdown("#### 🧠 2. Machine Learning Training")
        st.write("Train the Isolation Forest model on the clean baseline. It learns normal ranges and distribution bounds.")
        
        if has_model:
            st.success("🟢 Calibration Model Ready")
        else:
            st.warning("🟡 No Model Found")
            
        train_disabled = num_rows < 100
        if st.button("⚙️ Train Baseline Model", disabled=train_disabled, key="wiz_train_model"):
            with st.spinner("Calibrating baseline..."):
                res = subprocess.run([sys.executable, "train_model.py"], capture_output=True, text=True)
                if res.returncode == 0:
                    st.success("Calibration complete!")
                    st.cache_resource.clear()
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error(f"Calibration failed: {res.stderr}")
        if train_disabled:
            st.caption("⚠️ Collect at least 100 telemetry rows in Step 1 to train.")
        st.markdown("</div>", unsafe_allow_html=True)
        
    with col3:
        st.markdown("<div class='metric-container'>", unsafe_allow_html=True)
        st.markdown("#### 🚀 3. SOC Control Center")
        st.write("Unlock the real-time adaptive metrics, telemetry dashboards, explainable diagnostics, and auto-response rules.")
        
        ready = has_model and num_rows >= 100
        if ready:
            st.success("🟢 Ready to unlock")
            if st.button("🚀 Access Monitoring Center", type="primary"):
                st.session_state["unlocked_override"] = True
                st.rerun()
        else:
            st.error("🔴 SOC Locked")
            st.caption("Complete Steps 1 & 2 to calibrate and unlock.")
        st.markdown("</div>", unsafe_allow_html=True)
        
    if csv_exists and num_rows > 0:
        st.markdown("---")
        st.markdown("#### 📊 Collected Calibration Samples (Last 5)")
        st.dataframe(pd.read_csv("system_data.csv").tail(5), use_container_width=True)
        
    if running_proc and num_rows < 100:
        time.sleep(3)
        st.rerun()
        
    st.stop()

# ─────────────────────────────────────────────
# MAIN DASHBOARD STATE & SESSION DEFAULTS
# ─────────────────────────────────────────────
DEFAULT_WHITELIST = """System Idle Process
svchost.exe
lsass.exe"""

defaults = {
    "alert_log":          [],
    "auto_kill_log":      [],
    "last_alert_time":    0,
    "last_alert_proc":    "",
    "last_autokill_time": 0,
    "whitelist_raw":      DEFAULT_WHITELIST,
    "refresh_rate":       2,
    "history_rows":       60,
    "score_threshold":    -0.600,
    "auto_kill":          False,
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ─────────────────────────────────────────────
# TABS
# ─────────────────────────────────────────────
tab_live, tab_memory, tab_history, tab_settings = st.tabs([
    "🖥️ Live Monitor", "🧠 Memory Usage", "📋 Security Audit Log", "⚙️ Settings"
])

# ─────────────────────────────────────────────
# SETTINGS TAB
# ─────────────────────────────────────────────
with tab_settings:
    st.header("⚙️ SOC Settings")
    col_a, col_b = st.columns(2)
    
    with col_a:
        st.subheader("🎛️ Detection Sensitivity")
        st.session_state.refresh_rate = st.slider(
            "Refresh Rate (seconds)", 1, 5, st.session_state.refresh_rate)
        st.session_state.history_rows = st.slider(
            "History window (rows)", 30, 200, st.session_state.history_rows)
        st.session_state.score_threshold = st.slider(
            "Anomaly score threshold",
            min_value=-1.0, max_value=-0.3,
            value=st.session_state.score_threshold,
            step=0.005,
            help="More negative = stricter. Normal ~-0.49, attacks ~-0.63+"
        )
        st.subheader("🤖 Auto Response Options")
        st.session_state.auto_kill = st.toggle(
            "Auto-kill anomalous process",
            value=st.session_state.auto_kill,
            help="Automatically terminates the culprit process when threat is flagged."
        )
        
        st.subheader("🔄 Retrain and Recalibrate")
        st.write("Recalibrate the Isolation Forest baseline model using current `system_data.csv` history.")
        if st.button("⚙️ Retrain Baseline Model Now"):
            with st.spinner("Retraining model..."):
                res = subprocess.run([sys.executable, "train_model.py"], capture_output=True, text=True)
                if res.returncode == 0:
                    st.success("✅ Model retrained and calibrated successfully!")
                    st.cache_resource.clear()
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error(f"Retraining failed: {res.stderr}")
                    
    with col_b:
        st.subheader("✅ Process Whitelist")
        st.caption("Whitelisted processes are ignored by the threat detector.")
        new_whitelist = st.text_area(
            "Whitelisted processes (one per line)",
            value=st.session_state.whitelist_raw,
            height=300
        )
        if st.button("💾 Save Whitelist"):
            st.session_state.whitelist_raw = new_whitelist
            st.success("✅ Whitelist updated successfully!")

# Apply configuration
refresh_rate    = st.session_state.refresh_rate
history_rows    = st.session_state.history_rows
score_threshold = st.session_state.score_threshold
auto_kill       = st.session_state.auto_kill

whitelist = {w.strip().lower() for w in st.session_state.whitelist_raw.splitlines() if w.strip()}
whitelist.update({"nan", "", "unknown", "system idle process"})

# Guard check for data existence
if not os.path.exists("system_data.csv"):
    with tab_live:
        st.warning("⏳ Waiting for telemetry — starting collector...")
        start_collector()
    time.sleep(2)
    st.rerun()

# Load telemetry
df_raw = pd.read_csv("system_data.csv").iloc[:-1] # skip last row to prevent partial reads
for col in ["cpu", "ram", "disk", "sent_delta", "recv_delta", "proc"]:
    if col in df_raw.columns:
        df_raw[col] = pd.to_numeric(df_raw[col], errors="coerce")
df_raw = df_raw.dropna(subset=["cpu", "ram", "disk", "sent_delta", "recv_delta", "proc"])

if len(df_raw) < 10:
    with tab_live:
        st.warning("⏳ Gathering live system telemetry. Please wait...")
    time.sleep(2)
    st.rerun()

# Score Telemetry
df_full_eng = engineer_features(df_raw)
X_full      = scaler.transform(df_full_eng[FEATURES].fillna(0))
scores_full = model.score_samples(X_full)
anom_flags  = scores_full < score_threshold

df_full_eng["score"]   = scores_full
df_full_eng["anomaly"] = np.where(anom_flags, -1, 1)
df_full_eng["minute"]  = (np.arange(len(df_full_eng)) // 60).astype(int)

anom_per_min = df_full_eng.groupby("minute")["anomaly"].apply(
    lambda x: (x == -1).sum()
).reset_index(name="anomalies")

# Filter window for live charts
df = df_full_eng.tail(history_rows).copy().reset_index(drop=True)
df["confidence"] = df["score"].apply(lambda s: score_to_confidence(s, score_threshold))

current        = df.iloc[-1]
culprit        = str(current.get("top_process", "unknown")).strip()
score_now      = current["score"]
conf_now       = current["confidence"]
is_whitelisted = culprit.lower() in whitelist

# PROCESS LIFECYCLE & STALENESS CHECK
is_active_on_os = is_process_currently_running(culprit)
csv_mtime = os.path.getmtime("system_data.csv") if os.path.exists("system_data.csv") else 0
telemetry_is_stale = (time.time() - csv_mtime) > 15.0

# TEMPORAL PERSISTENCE VALIDATION:
recent_anoms = df["anomaly"].tail(3).tolist()
recent_anom_count = sum(1 for a in recent_anoms if a == -1)

if not is_active_on_os:
    system_state = "TERMINATED / INACTIVE PROCESS"
    real_anomaly = False
    evaluating_spike = False
elif telemetry_is_stale:
    system_state = "STALE TELEMETRY"
    real_anomaly = False
    evaluating_spike = False
elif recent_anom_count >= 3 and not is_whitelisted:
    system_state = "CONFIRMED THREAT"
    real_anomaly = True
    evaluating_spike = False
elif recent_anom_count > 0 and not is_whitelisted:
    system_state = "EVALUATING (SPIKE DETECTED)"
    real_anomaly = False
    evaluating_spike = True
else:
    system_state = "SECURE"
    real_anomaly = False
    evaluating_spike = False

# Get statistics from psutil
vm           = psutil.virtual_memory()
live_ram_gb  = round(vm.used      / (1024**3), 2)
total_ram_gb = round(vm.total     / (1024**3), 2)
avail_ram_gb = round(vm.available / (1024**3), 2)
swap         = psutil.swap_memory()
has_mem_cols = "ram_used_gb" in df.columns

# ─────────────────────────────────────────────
# LIVE MONITOR TAB
# ─────────────────────────────────────────────
with tab_live:
    # Header Collector Alert
    coll_p = is_collector_running()
    if not coll_p:
        st.warning("⚠️ Telemetry Collector is offline. Click button below to start live telemetry.")
        if st.button("▶️ Launch Telemetry Collector", key="live_start_coll"):
            start_collector()
            st.rerun()
    elif telemetry_is_stale:
        st.warning("⚠️ Telemetry Stream Paused: No new data received in > 15s.")
        
    st.markdown("### 🖥️ AI Sentinel: Live Monitor Dashboard")
    
    # Pulse Status Alert Card
    if real_anomaly:
        st.markdown(f"<div class='status-card status-anomaly'>🚨 CONFIRMED ANOMALY FLAGGED: {culprit.upper()}</div>", unsafe_allow_html=True)
    elif evaluating_spike:
        st.markdown(f"<div class='status-card' style='background: rgba(255, 193, 7, 0.15); border: 2px solid #FFC107; color: #FFC107; text-align: center; font-weight: 700; font-size: 1.4rem; padding: 20px; border-radius: 12px; margin-bottom: 20px;'>⚡ TRANSIENT SPIKE DETECTED ({recent_anom_count}/3): EVALUATING PERSISTENCE</div>", unsafe_allow_html=True)
    elif not is_active_on_os and culprit.lower() not in ["system", "unknown", "system idle process"]:
        st.markdown(f"<div class='status-card' style='background: rgba(41, 121, 255, 0.15); border: 2px solid #2979FF; color: #2979FF; text-align: center; font-weight: 700; font-size: 1.2rem; padding: 16px; border-radius: 12px; margin-bottom: 20px;'>ℹ️ HISTORICAL PROCESS INACTIVE: {culprit.upper()} (No Active Threat)</div>", unsafe_allow_html=True)
    else:
        st.markdown("<div class='status-card status-secure'>🛡️ SYSTEM STATE: SECURE</div>", unsafe_allow_html=True)
        
    # Standard metrics
    col_status, col_conf, col_cpu, col_ram = st.columns(4)
    with col_status:
        st.metric("State Indicator", "🚨 THREAT" if real_anomaly else ("⚡ SPIKE" if evaluating_spike else ("ℹ️ INACTIVE" if not is_active_on_os else "✅ SECURE")))
    with col_conf:
        st.metric("Threat Confidence", f"{conf_now}%" if (real_anomaly or evaluating_spike) else "0%", delta=f"score {score_now:.4f}")
    with col_cpu:
        st.metric("CPU Usage", f"{current['cpu']:.1f}%", delta=f"Δ {current['cpu_delta']:.1f}%")
    with col_ram:
        st.metric("Memory Usage", f"{current['ram']:.1f}%", delta=f"{live_ram_gb:.1f}/{total_ram_gb:.1f} GB")
        
    # Charts
    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("CPU & RAM % Utilization")
        st.line_chart(df[["cpu", "ram"]], use_container_width=True)
    with col2:
        st.subheader("Telemetry Anomaly Score (lower = suspicious)")
        chart_score = df[["score"]].copy()
        chart_score["threshold"] = score_threshold
        st.line_chart(chart_score, use_container_width=True)
        
    col3, col4 = st.columns(2)
    with col3:
        st.subheader("Network Activity (bytes)")
        st.line_chart(df[["net_total"]], use_container_width=True)
    with col4:
        st.subheader("Anomalies Per Minute (Session-wide)")
        st.bar_chart(anom_per_min.set_index("minute")["anomalies"], use_container_width=True)
        
    # Diagnostic / Explainable AI (XAI) Section
    if real_anomaly:
        st.markdown("---")
        st.markdown("### 🛡️ Threat Diagnostic Breakdown (Explainable AI)")
        st.write("The features below triggered the anomaly classification based on deviation from baseline bounds:")
        
        if stats:
            explanations = []
            for f in FEATURES:
                val = current.get(f, 0)
                mean = stats["mean"].get(f, 0)
                std = stats["std"].get(f, 1)
                z = (val - mean) / (std + 1e-5)
                
                names = {
                    "cpu": "CPU Usage (%)",
                    "ram": "RAM Usage (%)",
                    "disk": "Disk Space (%)",
                    "proc": "Process Count",
                    "cpu_delta": "CPU Spike Rate",
                    "cpu_z": "CPU rolling anomaly factor",
                    "net_total": "Network Throughput",
                    "net_roll": "Rolling Network Throughput"
                }
                name = names.get(f, f)
                
                if abs(z) >= 1.5:
                    direction = "spiked" if z > 0 else "dropped"
                    explanations.append({
                        "name": name,
                        "value": val,
                        "mean": mean,
                        "std": std,
                        "z": z,
                        "direction": direction
                    })
            
            explanations.sort(key=lambda x: abs(x["z"]), reverse=True)
            
            if explanations:
                for exp in explanations:
                    sign = "🔺" if exp["z"] > 0 else "🔻"
                    color = "#FF1744" if exp["z"] > 0 else "#2979FF"
                    st.markdown(f"""
                    <div class='xai-card' style='border-left-color: {color}'>
                        <span class='xai-feature' style='color: {color}'>{sign} {exp['name'].upper()} {exp['direction'].upper()}</span><br/>
                        <span class='xai-details'>
                            Current measurement: <b>{exp['value']:.2f}</b> vs. Baseline average: <b>{exp['mean']:.2f}</b> 
                            (Deviation: <b style='color: {color}'>{exp['z']:+.2f}</b> standard deviations)
                        </span>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.info("The anomaly represents a complex correlation. No individual metric is out of bounds on its own.")
        else:
            st.warning("⚠️ No baseline stats available. Re-run training in Settings to build XAI breakdown data.")

    # Flagged rows
    st.markdown("---")
    st.subheader("🔴 Flagged Telemetry Logs")
    flagged = df[df["anomaly"] == -1][["cpu", "ram", "net_total", "proc", "confidence", "score", "top_process"]].tail(10)
    
    if flagged.empty:
        st.info("No anomalies detected in current history window.")
    else:
        flagged = flagged.rename(columns={
            "cpu": "CPU %", "ram": "RAM %", "net_total": "Net Bytes",
            "proc": "Processes", "confidence": "Confidence %",
            "score": "Score", "top_process": "Culprit"
        })
        st.dataframe(flagged, use_container_width=True)

    # Remediation
    if real_anomaly:
        st.markdown("---")
        st.subheader("⚡ Threat Mitigation Center")
        st.error(f"Target Process: **{culprit}** | Threat Confidence: **{conf_now}%**")
        
        now = time.time()
        if st.session_state.last_alert_proc != culprit or now - st.session_state.last_alert_time > 30:
            st.session_state.alert_log.append({
                "time":       time.strftime("%H:%M:%S"),
                "process":    culprit,
                "cpu":        f"{current['cpu']:.1f}%",
                "confidence": f"{conf_now}%",
                "score":      f"{score_now:.4f}",
                "action":     "detected"
            })
            st.session_state.last_alert_time = now
            st.session_state.last_alert_proc = culprit
            
        if auto_kill:
            time_since = now - st.session_state.last_autokill_time
            if time_since > 30:
                success, msg = kill_top_cpu_process(culprit)
                if success:
                    st.session_state.last_autokill_time = now
                    st.session_state.auto_kill_log.append({
                        "time":    time.strftime("%H:%M:%S"),
                        "process": culprit,
                        "cpu":     f"{current['cpu']:.1f}%",
                    })
                    if st.session_state.alert_log:
                        st.session_state.alert_log[-1]["action"] = "auto-killed"
                    st.toast(f"🤖 Auto-response: Terminated {culprit}")
                    time.sleep(1)
                    st.rerun()
            else:
                st.warning(f"🤖 Auto-response cooldown: {int(30 - time_since)}s remaining.")
                
        col_kill, col_whitelist = st.columns([1, 4])
        with col_kill:
            if st.button(f"🔴 Terminate {culprit.upper()}"):
                with st.spinner(f"Terminating {culprit}..."):
                    success, msg = kill_top_cpu_process(culprit)
                    if success:
                        if st.session_state.alert_log:
                            st.session_state.alert_log[-1]["action"] = "manually killed"
                        st.toast(f"✅ {msg}")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.warning(msg)
        with col_whitelist:
            if st.button(f"✅ Whitelist {culprit.upper()}"):
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
        st.metric("Swap Allocation Used", f"{swap.used / (1024**3):.2f} GB", delta=f"{swap.percent:.1f}%")
        
    st.markdown("---")
    st.subheader("Memory Utilization History")
    st.line_chart(df[["ram"]], use_container_width=True)
    
    col_m1, col_m2 = st.columns(2)
    with col_m1:
        st.subheader("Memory Used (GB)")
        if has_mem_cols and df["ram_used_gb"].notna().any():
            mem_gb_chart = df[["ram_used_gb"]].copy()
            mem_gb_chart.columns = ["Used GB"]
            st.line_chart(mem_gb_chart, use_container_width=True)
        else:
            approx_gb = (df["ram"] / 100.0 * total_ram_gb).round(2)
            approx_df = pd.DataFrame({"Used GB (approx)": approx_gb})
            st.line_chart(approx_df, use_container_width=True)
    with col_m2:
        st.subheader("Memory Rate of Change (% per sample)")
        ram_delta_chart = df[["ram_delta"]].copy()
        ram_delta_chart.columns = ["RAM delta %"]
        st.line_chart(ram_delta_chart, use_container_width=True)

# ─────────────────────────────────────────────
# SECURITY AUDIT LOG TAB
# ─────────────────────────────────────────────
with tab_history:
    st.header("📋 Security Audit & Threat Log")
    if not st.session_state.alert_log:
        st.info("No security alerts logged during this SOC session.")
    else:
        log_df = pd.DataFrame(st.session_state.alert_log[::-1])
        st.dataframe(log_df, use_container_width=True)
        
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
        st.dataframe(pd.DataFrame(st.session_state.auto_kill_log[::-1]), use_container_width=True)

# ─────────────────────────────────────────────
# REFRESH ENGINE
# ─────────────────────────────────────────────
time.sleep(refresh_rate)
st.rerun()
