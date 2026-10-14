import os
import sys
import warnings

os.environ["PYTHONWARNINGS"] = "ignore"
warnings.filterwarnings("ignore")

import streamlit as st
import streamlit.components.v1 as components
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

import html
from src.monitoring.process_monitor import (
    is_process_currently_running,
    get_process_info,
    kill_top_cpu_process,
    PROTECTED_PROCESSES
)

from src.features.feature_engineering import engineer_features, FEATURES
from src.anomaly_detection.model import load_trained_models, check_models_exist, load_model_metadata, get_model_file_paths
from src.anomaly_detection.baseline import compute_xai_explanations
from src.anomaly_detection.predictor import evaluate_latest_sample
from src.monitoring.allowlist import (
    SYSTEM_ALLOWLIST,
    check_process_allowlist,
    get_all_allowlisted_process_names
)
from src.audit.audit_db import (
    log_security_alert,
    get_security_alerts,
    clear_security_alerts,
    log_autokill_event,
    get_autokill_events,
    clear_autokill_events,
    log_model_event,
    get_model_events
)
try:
    from src.audit.audit_db import log_suppressed_alert
except ImportError:
    import importlib
    import src.audit.audit_db as _adb
    importlib.reload(_adb)
    try:
        from src.audit.audit_db import log_suppressed_alert
    except ImportError:
        def log_suppressed_alert(timestamp, process, score, cpu, ram, disk, reason="", db_path=None):
            act = f"Suppressed (Allowlist: {reason[:40]})" if reason else "Suppressed (Allowlisted System Process)"
            log_security_alert(timestamp, process, score, cpu, ram, disk, action=act, db_path=db_path)
from src.monitoring.realtime_events import start_realtime_server, get_realtime_broker
from src.dashboard.toast_ui import get_toast_html

REALTIME_PORT = start_realtime_server()
event_broker = get_realtime_broker()

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

def _get_python_executable():
    if getattr(sys, "frozen", False):
        import shutil
        return shutil.which("python") or shutil.which("python3") or sys.executable
    return sys.executable

def start_collector():
    p = is_collector_running()
    if not p:
        py_exe = _get_python_executable()
        cmd = [py_exe, str(PROJECT_ROOT / "scripts" / "collect_data.py")]
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

# ─────────────────────────────────────────────
# FIRST-TIME SETUP & PERSONAL BASELINE WIZARD
# ─────────────────────────────────────────────
def run_calibration_wizard():
    st.title("🛡️ Welcome to AI Sentinel")
    st.subheader("Personal Anomaly Model Setup")
    st.info("AI Sentinel needs to learn your PC's normal behavior before monitoring can begin.")
    
    st.markdown("""
    Every computer has a unique baseline of background tasks, memory footprints, and network traffic.
    AI Sentinel collects baseline telemetry directly from **this PC** to train your personal IsolationForest anomaly detector.
    
    *You can continue using your computer normally while baseline telemetry is being collected.*
    """)
    
    running_proc = is_collector_running()
    
    col_c1, col_c2 = st.columns(2)
    with col_c1:
        if not running_proc:
            if st.button("🚀 Learn My PC", type="primary", use_container_width=True):
                start_collector()
                st.rerun()
        else:
            st.success(f"🟢 Telemetry Collector Active (PID: {running_proc.pid})")
            
    num_rows = 0
    if DATA_FILE.exists():
        try:
            df_tmp = pd.read_csv(DATA_FILE)
            num_rows = len(df_tmp)
        except Exception:
            num_rows = 0

    with col_c2:
        st.metric("Baseline Samples Collected", f"{num_rows} / 100 required")

    if running_proc or num_rows > 0:
        progress = min(1.0, num_rows / 100.0)
        st.progress(progress, text=f"Learning your PC... ({num_rows}/100 samples)")
        
        st.markdown("### Real-Time Baseline Subsystem Status")
        b1, b2, b3, b4 = st.columns(4)
        with b1:
            st.markdown("🖥️ **CPU Behavior**")
            st.caption("Learning..." if num_rows < 100 else "Ready ✓")
        with b2:
            st.markdown("🧠 **Memory Behavior**")
            st.caption("Learning..." if num_rows < 100 else "Ready ✓")
        with b3:
            st.markdown("⚡ **Process Behavior**")
            st.caption("Learning..." if num_rows < 100 else "Ready ✓")
        with b4:
            st.markdown("🌐 **Network Behavior**")
            st.caption("Learning..." if num_rows < 100 else "Ready ✓")

        st.markdown("---")

        if num_rows >= 100:
            st.success("Sufficient baseline data collected! Click below to train your personal model.")
            if st.button("🧠 Train Personal Anomaly Model Now", type="primary", use_container_width=True):
                with st.spinner("Training Personal Isolation Forest Model on THIS PC's Telemetry..."):
                    train_script = PROJECT_ROOT / "scripts" / "train_model.py"
                    py_exe = _get_python_executable()
                    res = subprocess.run([py_exe, str(train_script)], cwd=str(PROJECT_ROOT), capture_output=True, text=True)
                    if res.returncode == 0:
                        meta_init = load_model_metadata()
                        log_model_event(
                            time.strftime("%Y-%m-%d %H:%M:%S"),
                            "MODEL_INIT_COMPLETED",
                            meta_init.get("model_version", "V1"),
                            meta_init.get("training_samples", 100),
                            "Initial personal anomaly model trained successfully."
                        )
                        st.toast("Personal model (V1) trained successfully!")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error(f"Training failed: {res.stderr}")
        else:
            st.info(f"Gathering telemetry samples... ({num_rows}/100 rows). Page will auto-refresh.")
            time.sleep(3)
            st.rerun()

    st.stop()

# Load Trained Personal Model or trigger setup wizard
model, scaler, features, stats = load_trained_models()
if model is None or scaler is None or features is None:
    run_calibration_wizard()



DEFAULT_WHITELIST = """System Idle Process
svchost.exe
lsass.exe
explorer.exe
dwm.exe
MsMpEng.exe"""

model_default_threshold = float(getattr(model, "offset_", -0.600))

defaults = {
    "alert_log":                  [],
    "auto_kill_log":              [],
    "last_alert_time":            0,
    "last_alert_proc":            "",
    "last_autokill_time":         0,
    "last_suppressed_log_time":   0,
    "last_suppressed_log_proc":   "",
    "whitelist_raw":              DEFAULT_WHITELIST,
    "refresh_rate":               2,
    "history_rows":               60,
    "score_threshold":            model_default_threshold,
    "user_overrode_threshold":    False,
    "auto_kill":                  False,
    "enable_notifications":       True,
    "enable_sound":               True,
    "enable_browser_push":        True,
    "snoozed_alerts":             {},
    "active_dialog_open":         False,
    "current_alert_culprit":      "",
    "last_notified_culprit":      "",
    "last_notified_time":         0,
    "manual_open_anomaly":        False,
    "manual_test_anomaly":        False,
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

# If user has not explicitly overridden threshold, sync with model default
if not st.session_state.get("user_overrode_threshold", False):
    st.session_state.score_threshold = model_default_threshold

def dismiss_dialog_callback():
    st.session_state.active_dialog_open = False
    st.session_state.manual_open_anomaly = False
    st.session_state.manual_test_anomaly = False
    curr = st.session_state.get("current_alert_culprit", "")
    if curr:
        st.session_state.snoozed_alerts[curr.lower()] = time.time() + 30

@st.dialog("🚨 SECURITY ALERT: ANOMALY DETECTED", width="large", on_dismiss=dismiss_dialog_callback)
def show_anomaly_notification_dialog(anomaly_info):
    culprit_name = anomaly_info["culprit"]
    alert_score = anomaly_info["score"]
    alert_threshold = anomaly_info["threshold"]
    alert_confidence = anomaly_info["confidence"]
    current_metrics = anomaly_info["current"]
    xai_factors = anomaly_info.get("xai", [])
    proc_info = anomaly_info.get("proc_info", {})
    is_test = anomaly_info.get("is_test", False)
    is_masquerading = anomaly_info.get("is_masquerading", False)
    is_resource_spike = anomaly_info.get("is_resource_spike", False)
    allowlist_eval = anomaly_info.get("allowlist_eval", {})

    culprit_esc = html.escape(str(culprit_name))
    cmdline_raw = proc_info.get("cmdline") or f"{culprit_name}"
    cmdline_esc = html.escape(str(cmdline_raw))

    st.markdown(f"""
    <div style="background: linear-gradient(135deg, #450a0a 0%, #7f1d1d 100%); border: 2px solid #ef4444; border-radius: 12px; padding: 18px 22px; margin-bottom: 20px; box-shadow: 0 4px 20px rgba(239, 68, 68, 0.35);">
        <div style="display:flex; justify-content:space-between; align-items:center;">
            <span style="font-size:22px; font-weight:700; color:#fca5a5;">
                🚨 ANOMALY DETECTED ON HOST
            </span>
            <span style="background-color:#991b1b; color:#fee2e2; padding:4px 12px; border-radius:15px; font-weight:700; font-size:13px; letter-spacing:0.5px;">
                CONFIDENCE: {alert_confidence:.1f}%
            </span>
        </div>
        <p style="color:#fecaca; margin:8px 0 0 0; font-size:15px; line-height:1.5;">
            Anomalous system telemetry detected. Top CPU contributor: <code style="color:#ffffff; background:#991b1b; padding:2px 8px; border-radius:4px; font-size:15px; font-weight:700;">{culprit_esc.upper()}</code>.
            Review anomaly diagnostics below to determine action: <strong>Ignore if Known</strong> or <strong>Kill if Unknown</strong>.
        </p>
    </div>
    """, unsafe_allow_html=True)

    if is_masquerading:
        st.error(f"🚨 CRITICAL SECURITY THREAT: Executable '{culprit_esc}' is running from an untrusted location ({proc_info.get('exe', 'unknown folder')}) impersonating a Windows system component (MITRE ATT&CK T1036 Masquerading). This binary cannot be whitelisted.")
    elif is_resource_spike:
        st.warning(f"⚠️ RESOURCE ANOMALY: Process '{culprit_esc}' is a recognized system component, but has triggered an alert due to abnormal resource utilization ({current_metrics.get('cpu', 0.0):.1f}% CPU, {current_metrics.get('ram', 0.0):.1f}% RAM).")

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric("Suspect Process", culprit_name, delta="FLAGGED")
    with m2:
        st.metric("ML Anomaly Score", f"{alert_score:.4f}", delta=f"Threshold: {alert_threshold:.4f}", delta_color="inverse")
    with m3:
        st.metric("CPU Load", f"{current_metrics.get('cpu', 0.0):.1f}%", delta=f"Δ {current_metrics.get('cpu_delta', 0.0):.1f}%")
    with m4:
        st.metric("Memory Usage", f"{current_metrics.get('ram', 0.0):.1f}%", delta=f"{current_metrics.get('ram_used_gb', 0.0):.1f} GB")

    pids = proc_info.get("pids", [])
    pids_display = ", ".join(str(p) for p in pids[:8]) if pids else "Active OS Instance"
    if len(pids) > 8:
        pids_display += f" ... (+{len(pids)-8} more)"
    pids_display_esc = html.escape(pids_display)

    st.markdown(f"""
    <div style="background-color: #0f172a; padding: 14px 18px; border-radius: 8px; border: 1px solid #1e293b; margin-bottom: 16px;">
        <span style="font-weight:700; color:#38bdf8; font-size:14px; text-transform:uppercase; letter-spacing:0.5px;">🔍 Process Telemetry Details</span>
        <div style="margin-top:8px; font-size:14px; color:#cbd5e1; line-height:1.7;">
            <strong>Target:</strong> <code>{culprit_esc}</code> &nbsp;|&nbsp; 
            <strong>Active PIDs:</strong> <code>{pids_display_esc}</code> &nbsp;|&nbsp; 
            <strong>Resident Memory:</strong> <code>{proc_info.get('memory_mb', 0.0)} MB</code><br>
            <strong>Command:</strong> <code style="word-break:break-all;">{cmdline_esc}</code>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("#### 🧠 Explainable AI Root Cause Factors")
    if xai_factors:
        st.caption("Telemetry attributes deviating significantly (|Z| ≥ 1.5σ) from your learned baseline:")
        for factor in xai_factors:
            f_name = factor.get("name", factor.get("feature", "Metric"))
            val = factor.get("value", 0.0)
            mean = factor.get("mean", 0.0)
            z = factor.get("z", 0.0)
            direction = factor.get("direction", "deviated")
            badge_color = "#991b1b" if abs(z) >= 2.5 else "#854d0e"
            badge_text = "#fca5a5" if abs(z) >= 2.5 else "#fde68a"
            st.markdown(f"""
            <div style="background-color: #111827; padding: 10px 14px; border-radius: 6px; margin-bottom: 6px; border-left: 4px solid #ef4444; display:flex; justify-content:space-between; align-items:center;">
                <div>
                    <strong>{f_name}</strong> {direction} to <code>{val:.2f}</code> (Baseline mean: <code>{mean:.2f}</code>)
                </div>
                <span style="background:{badge_color}; color:{badge_text}; padding:3px 8px; border-radius:4px; font-size:12px; font-weight:700;">
                    Z = {z:+.2f}σ
                </span>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("Anomaly triggered by multi-variate deviation crossing the Isolation Forest hypersphere boundary.")

    st.markdown("---")
    st.subheader("🛡️ Threat Mitigation Decision")
    col_known, col_unknown = st.columns(2)

    with col_known:
        st.markdown("""
        <div style="background: rgba(16, 185, 129, 0.08); border: 1px solid #10b981; border-radius: 10px; padding: 16px; min-height: 140px;">
            <h4 style="color:#34d399; margin:0 0 6px 0;">🟢 Known Anomaly — Ignore</h4>
            <p style="color:#a7f3d0; font-size:13px; margin:0; line-height:1.4;">
                If this process is recognized software, a scheduled job, or legitimate user work, mark it as known to ignore and whitelist it.
            </p>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
        if is_masquerading:
            st.warning("⚠️ Masquerading lookalike binaries cannot be added to allowlist.")
            st.button("🚫 Whitelisting Blocked", disabled=True, use_container_width=True)
        else:
            if st.button("✅ IGNORE (Mark as Known)", key="btn_ignore_known", use_container_width=True, type="secondary"):
                if not is_test:
                    existing = st.session_state.whitelist_raw.splitlines()
                    if culprit_name.lower() not in [p.strip().lower() for p in existing]:
                        st.session_state.whitelist_raw = (st.session_state.whitelist_raw.strip() + f"\n{culprit_name}").strip()
                    log_security_alert(
                        time.strftime("%Y-%m-%d %H:%M:%S"),
                        culprit_name,
                        round(alert_score, 4),
                        current_metrics.get("cpu", 0.0),
                        current_metrics.get("ram", 0.0),
                        current_metrics.get("disk", 0.0),
                        "Ignored by User (Known)"
                    )
                st.session_state.active_dialog_open = False
                st.session_state.manual_open_anomaly = False
                st.session_state.manual_test_anomaly = False
                st.toast(f"✅ Marked '{culprit_name}' as known. Whitelisted & ignored.", icon="🛡️")
                time.sleep(0.3)
                st.rerun()

    with col_unknown:
        st.markdown("""
        <div style="background: rgba(239, 68, 68, 0.08); border: 1px solid #ef4444; border-radius: 10px; padding: 16px; min-height: 140px;">
            <h4 style="color:#f87171; margin:0 0 6px 0;">🔴 Unknown Anomaly — Kill Process</h4>
            <p style="color:#fca5a5; font-size:13px; margin:0; line-height:1.4;">
                If this process is unknown, unrecognized, or a rogue workload, immediately terminate the offending process.
            </p>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
        if st.button("🛑 KILL PROCESS (Terminate Unknown)", key="btn_kill_unknown", use_container_width=True, type="primary"):
            if is_test:
                success, msg = True, f"Simulated termination of test process {culprit_name}."
            else:
                success, msg = kill_top_cpu_process(culprit_name)
            
            ts_now = time.strftime("%Y-%m-%d %H:%M:%S")
            if success:
                if not is_test:
                    log_autokill_event(ts_now, culprit_name, alert_score, True, f"Terminated by user (Unknown Threat): {msg}")
                    log_security_alert(
                        ts_now,
                        culprit_name,
                        round(alert_score, 4),
                        current_metrics.get("cpu", 0.0),
                        current_metrics.get("ram", 0.0),
                        current_metrics.get("disk", 0.0),
                        "Killed by User (Unknown)"
                    )
                st.session_state.active_dialog_open = False
                st.session_state.manual_open_anomaly = False
                st.session_state.manual_test_anomaly = False
                st.toast(f"🛑 Terminated '{culprit_name}': {msg}", icon="💥")
                time.sleep(0.5)
                st.rerun()
            else:
                st.error(f"Cannot terminate '{culprit_name}': {msg}")

    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
    c_snz, c_ins = st.columns(2)
    with c_snz:
        if st.button("⏱️ Snooze Alert (60 Seconds)", key="btn_snooze_alert", use_container_width=True):
            st.session_state.snoozed_alerts[culprit_name.lower()] = time.time() + 60
            st.session_state.active_dialog_open = False
            st.session_state.manual_open_anomaly = False
            st.session_state.manual_test_anomaly = False
            st.toast(f"⏱️ Alert snoozed for 60s for '{culprit_name}'.")
            time.sleep(0.2)
            st.rerun()
    with c_ins:
        if st.button("📊 Close & Inspect Live Charts", key="btn_inspect_charts", use_container_width=True):
            st.session_state.snoozed_alerts[culprit_name.lower()] = time.time() + 20
            st.session_state.active_dialog_open = False
            st.session_state.manual_open_anomaly = False
            st.session_state.manual_test_anomaly = False
            time.sleep(0.2)
            st.rerun()

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

        st.markdown("---")
        st.subheader("🔔 Real-Time Anomaly Toast Notifications")
        st.session_state.enable_notifications = st.checkbox(
            "Enable Real-Time Bottom-Right Toast Notifications",
            value=st.session_state.get("enable_notifications", True),
            help="Display a non-blocking floating toast notification at the bottom-right corner when an anomaly is detected.")
        st.session_state.enable_sound = st.checkbox(
            "Enable Audio Alert Chime",
            value=st.session_state.get("enable_sound", True),
            help="Play an audible chime when an anomaly is detected.")
        st.session_state.enable_browser_push = st.checkbox(
            "Enable Browser Desktop Notifications",
            value=st.session_state.get("enable_browser_push", True),
            help="Show system notifications via the browser Web Notification API.")
        
        if st.button("🚨 Test Real-Time Toast Notification", use_container_width=True):
            st.session_state.manual_test_anomaly = True
            st.rerun()

    with col_b:
        st.subheader("Process Whitelist")
        st.session_state.whitelist_raw = st.text_area(
            "Ignored process names (one per line)",
            st.session_state.whitelist_raw, height=120)

        with st.expander("🛡️ View 35+ Built-in Windows System Process Allowlist Rules"):
            st.caption(
                "These core Windows processes are validated by path integrity and signature certification. "
                "Normal activity is automatically suppressed, but resource anomalies (CPU > 85%, RAM > 85%) "
                "and masquerading lookalikes remain strictly monitored."
            )
            allowlist_summary = []
            for name, meta_p in SYSTEM_ALLOWLIST.items():
                dirs = ", ".join(meta_p.get("expected_dirs", [])) or "Kernel Subsystem (PID 0/4)"
                allowlist_summary.append({
                    "Process": name,
                    "Component": meta_p.get("display_name", name),
                    "Expected Location": dirs
                })
            st.dataframe(pd.DataFrame(allowlist_summary), height=200, use_container_width=True)
        
        st.subheader("Personal Model Management")
        meta = load_model_metadata()
        model_ver = meta.get('model_version', 'V1')
        
        total_accumulated_samples = 0
        if DATA_FILE.exists():
            try:
                total_accumulated_samples = len(pd.read_csv(DATA_FILE))
            except Exception:
                total_accumulated_samples = meta.get('training_samples', 0)
        else:
            total_accumulated_samples = meta.get('training_samples', 0)

        st.markdown(f"""
        <div style="background-color: #0f172a; padding: 16px; border-radius: 8px; border: 1px solid #1e293b; margin-bottom: 15px;">
            <p style="margin:0; font-weight:700; color:#34d399; font-size:16px;">MODEL STATUS: Active 🟢</p>
            <p style="margin:8px 0 0 0; font-size:14px; color:#cbd5e1; line-height: 1.6;">
                <strong>Model Version:</strong> {model_ver}<br>
                <strong>Training Samples:</strong> {meta.get('training_samples', total_accumulated_samples):,}<br>
                <strong>Accumulated Dataset:</strong> {total_accumulated_samples:,} rows<br>
                <strong>Last Trained:</strong> {meta.get('training_timestamp', 'N/A')}<br>
                <strong>Algorithm:</strong> {meta.get('model_type', 'Isolation Forest')}<br>
                <strong>PC Name:</strong> {meta.get('pc_name', 'This PC')}
            </p>
        </div>
        """, unsafe_allow_html=True)

        if st.button("🧠 RETRAIN MODEL", type="primary", use_container_width=True):
            now_str = time.strftime("%Y-%m-%d %H:%M:%S")
            log_model_event(now_str, "MODEL_RETRAIN_STARTED", model_ver, total_accumulated_samples, "User initiated model retraining on accumulated telemetry dataset.")
            with st.spinner(f"Retraining Isolation Forest on ALL accumulated telemetry ({total_accumulated_samples:,} rows)..."):
                train_script = PROJECT_ROOT / "scripts" / "train_model.py"
                py_exe = _get_python_executable()
                res = subprocess.run([py_exe, str(train_script)], cwd=str(PROJECT_ROOT), capture_output=True, text=True)
                if res.returncode == 0:
                    new_meta = load_model_metadata()
                    new_ver = new_meta.get("model_version", "V2")
                    new_samples = new_meta.get("training_samples", total_accumulated_samples)
                    log_model_event(
                        time.strftime("%Y-%m-%d %H:%M:%S"),
                        "MODEL_RETRAIN_COMPLETED",
                        new_ver,
                        new_samples,
                        f"Retraining complete. Activated Model {new_ver}."
                    )
                    st.toast(f"Retrained successfully! Model {new_ver} is now ACTIVE ({new_samples:,} samples).")
                    time.sleep(1)
                    st.rerun()
                else:
                    log_model_event(
                        time.strftime("%Y-%m-%d %H:%M:%S"),
                        "MODEL_RETRAIN_FAILED",
                        model_ver,
                        total_accumulated_samples,
                        f"Retraining failed. Retained active Model {model_ver}. Error: {res.stderr[:200]}"
                    )
                    st.error(f"Retraining failed. Working model {model_ver} remains active safely.\nError details:\n{res.stderr}")



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

df_raw = None
for _ in range(3):
    try:
        df_raw = pd.read_csv(DATA_FILE, on_bad_lines='skip')
        break
    except (pd.errors.ParserError, pd.errors.EmptyDataError, PermissionError):
        time.sleep(0.1)

if df_raw is None or len(df_raw) < 5:
    st.info("Collecting initial telemetry data... Please wait.")
    start_collector()
    time.sleep(2)
    st.rerun()

df = engineer_features(df_raw.tail(history_rows))
current = df.iloc[-1].to_dict()

total_ram_gb = current.get('ram_total_gb', 16.0)
live_ram_gb = current.get('ram_used_gb', (current.get('ram', 0.0) / 100.0) * total_ram_gb)
avail_ram_gb = max(0.0, total_ram_gb - live_ram_gb)

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

is_whitelisted = eval_res.get("is_whitelisted", False)
is_suppressed = eval_res.get("is_suppressed", False)
is_masquerading = eval_res.get("is_masquerading", False)
is_resource_spike = eval_res.get("is_resource_spike", False)
allowlist_eval = eval_res.get("allowlist_eval", {})

# Genuine anomaly: active alert unless legitimately suppressed as normal system process
real_anomaly = (is_masquerading or is_resource_spike or (sample_state in ["WARNING", "CRITICAL"] and not is_suppressed)) and not is_stale
is_confirmed_threat = (system_state == "CRITICAL" or is_masquerading)

# ─────────────────────────────────────────────
# AUDIT LOGGING FOR SUPPRESSED SYSTEM PROCESS ALERTS
# ─────────────────────────────────────────────
if is_suppressed and raw_is_anomaly and is_currently_running:
    now_t = time.time()
    if (now_t - st.session_state.get("last_suppressed_log_time", 0) > 15) or (culprit != st.session_state.get("last_suppressed_log_proc", "")):
        st.session_state.last_suppressed_log_time = now_t
        st.session_state.last_suppressed_log_proc = culprit
        ts_suppressed = current.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S"))
        log_suppressed_alert(
            ts_suppressed,
            culprit,
            round(score, 4),
            current.get("cpu", 0.0),
            current.get("ram", 0.0),
            current.get("disk", 0.0),
            reason=allowlist_eval.get("reason", "Recognized Windows System Process")
        )

# ─────────────────────────────────────────────
# REAL-TIME ANOMALY NOTIFICATION ENGINE (SSE & BOTTOM-RIGHT TOAST)
# ─────────────────────────────────────────────
now_time = time.time()
is_snoozed = (st.session_state.snoozed_alerts.get(culprit.lower(), 0) > now_time)
is_anomaly_active = real_anomaly and is_currently_running and not is_snoozed

direct_toast_event = None

# Manual Test Trigger from Settings tab
if st.session_state.get("manual_test_anomaly", False):
    st.session_state.manual_test_anomaly = False
    test_proc = "suspicious_workload.exe"
    direct_toast_event = event_broker.publish_anomaly(
        culprit=test_proc,
        severity="CRITICAL",
        score=-0.7420,
        threshold=score_threshold,
        confidence=94.5,
        cpu=95.8,
        ram=82.4,
        description=f"Unusual activity identified: process '{test_proc}' consuming 95.8% CPU (ML Score: -0.7420 vs {score_threshold:.4f})."
    )
    if direct_toast_event is None:
        direct_toast_event = {
            "id": f"anom_test_{int(time.time()*1000)}",
            "type": "Severe CPU & Process Spike",
            "severity": "CRITICAL",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "process": test_proc,
            "score": -0.7420,
            "threshold": round(score_threshold, 4),
            "confidence": 94.5,
            "cpu": 95.8,
            "ram": 82.4,
            "message": "⚠️ Anomaly Detected! Unusual activity has been identified.",
            "description": f"Unusual activity identified: process '{test_proc}' consuming 95.8% CPU (ML Score: -0.7420 vs {score_threshold:.4f})."
        }
elif is_anomaly_active and not is_snoozed and st.session_state.get("enable_notifications", True):
    # Live Real Anomaly Detected!
    # Publish to the real-time event broker (which pushes via SSE to connected clients)
    xai = compute_xai_explanations(current, stats, features)
    sev = system_state if system_state in ["CRITICAL", "WARNING"] else sample_state
    
    anom_type = None
    if is_masquerading:
        anom_type = "Process Masquerading Attack (MITRE T1036)"
        sev = "CRITICAL"
    elif is_resource_spike:
        anom_type = "Allowlisted Process Resource Anomaly"

    direct_toast_event = event_broker.publish_anomaly(
        culprit=culprit,
        severity=sev,
        score=score,
        threshold=score_threshold,
        confidence=threat_confidence,
        cpu=current.get("cpu", 0.0),
        ram=current.get("ram", 0.0),
        timestamp=current.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S")),
        xai=xai,
        anomaly_type=anom_type,
        description=eval_res.get("state_reason")
    )

# Inject real-time bottom-right floating toast notification client
toast_html = get_toast_html(
    REALTIME_PORT,
    direct_toast_event,
    enable_sound=st.session_state.get("enable_sound", True),
    enable_browser_push=st.session_state.get("enable_browser_push", True)
)
st.html(toast_html, unsafe_allow_javascript=True)

# Detailed inspection modal only when user explicitly requests it (e.g. clicking Check Anomaly on top banner)
if st.session_state.get("manual_open_anomaly", False):
    proc_info = get_process_info(culprit)
    xai = compute_xai_explanations(current, stats, features)
    inspect_modal_data = {
        "culprit": culprit,
        "score": score,
        "threshold": score_threshold,
        "confidence": threat_confidence,
        "current": current,
        "xai": xai,
        "proc_info": proc_info,
        "is_test": False,
        "is_masquerading": is_masquerading,
        "is_resource_spike": is_resource_spike,
        "allowlist_eval": allowlist_eval
    }
    show_anomaly_notification_dialog(inspect_modal_data)

# Compute Session Anomaly Trend
df["is_anom"] = False
if len(df) > 0 and len(features) > 0:
    try:
        X_hist = np.asarray(df[features].values, dtype=float)
        X_hist = np.nan_to_num(X_hist, nan=0.0, posinf=0.0, neginf=0.0)
        X_hist_scaled = scaler.transform(X_hist)
        scores_hist = model.score_samples(X_hist_scaled)
        df["score"] = scores_hist
        df["is_anom"] = (df["score"] < score_threshold)
    except Exception:
        df["score"] = 0.0
        df["is_anom"] = False

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
        ts_ak = time.strftime("%Y-%m-%d %H:%M:%S")
        log_autokill_event(ts_ak, culprit, score, success, msg)
        if success:
            st.toast(f"Auto-Kill Triggered: {msg}")

# Alert Logging
if is_confirmed_threat and is_currently_running and not is_suppressed:
    now_t = time.time()
    if (now_t - st.session_state.last_alert_time > 10) or (culprit != st.session_state.last_alert_proc):
        st.session_state.last_alert_time = now_t
        st.session_state.last_alert_proc = culprit
        ts_alert = current.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S"))
        if is_masquerading:
            act_alert = "Flagged: Masquerading Threat"
        elif is_resource_spike:
            act_alert = "Flagged: Resource Anomaly"
        else:
            act_alert = "Auto-Killed" if (auto_kill and not is_whitelisted) else "Flagged"
        log_security_alert(
            ts_alert, culprit, round(score, 4),
            current.get("cpu", 0.0), current.get("ram", 0.0), current.get("disk", 0.0), act_alert
        )

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

    # Anomaly Notification Banner & Quick Actions
    culprit_esc = html.escape(str(culprit))
    if is_anomaly_active:
        col_tb1, col_tb2, col_tb3, col_tb4 = st.columns([4, 1.4, 1.4, 1.4])
        with col_tb1:
            if is_masquerading:
                st.markdown(f"""
                <div style="background: linear-gradient(90deg, #7f1d1d 0%, #991b1b 100%); border-left: 6px solid #ef4444; padding: 10px 16px; border-radius: 8px;">
                    <span style="font-weight:700; color:#fca5a5; font-size:16px;">🚨 MASQUERADING ATTACK DETECTED — <code>{culprit_esc.upper()}</code></span><br>
                    <span style="color:#fee2e2; font-size:13px;">Process masquerading from untrusted path: {html.escape(str(allowlist_eval.get('verified_path', 'untrusted folder')))}</span>
                </div>
                """, unsafe_allow_html=True)
            elif is_resource_spike:
                st.markdown(f"""
                <div style="background: linear-gradient(90deg, #78350f 0%, #92400e 100%); border-left: 6px solid #f59e0b; padding: 10px 16px; border-radius: 8px;">
                    <span style="font-weight:700; color:#fde68a; font-size:16px;">⚠️ RESOURCE ANOMALY: System Process — <code>{culprit_esc.upper()}</code></span><br>
                    <span style="color:#fef3c7; font-size:13px;">High resource consumption ({current.get('cpu', 0.0):.1f}% CPU, {current.get('ram', 0.0):.1f}% RAM) | ML Score: {score:.4f}</span>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div style="background: linear-gradient(90deg, #450a0a 0%, #7f1d1d 100%); border-left: 6px solid #ef4444; padding: 10px 16px; border-radius: 8px;">
                    <span style="font-weight:700; color:#fca5a5; font-size:16px;">🚨 THREAT ALERT: Anomaly Detected — <code>{culprit_esc.upper()}</code></span><br>
                    <span style="color:#fee2e2; font-size:13px;">ML Score: {score:.4f} &lt; {score_threshold:.4f} | Confidence: {threat_confidence:.1f}%</span>
                </div>
                """, unsafe_allow_html=True)
        with col_tb2:
            if st.button("🔍 Check Anomaly", key="banner_chk_btn", use_container_width=True):
                st.session_state.manual_open_anomaly = True
                st.session_state.active_dialog_open = True
                st.rerun()
        with col_tb3:
            if is_masquerading:
                st.button("⚠️ Untrusted Binary", disabled=True, use_container_width=True, help="Masquerading lookalike binaries cannot be added to allowlist.")
            else:
                if st.button("✅ Ignore (Known)", key="banner_ign_btn", use_container_width=True):
                    if culprit.lower() not in whitelist:
                        st.session_state.whitelist_raw = (st.session_state.whitelist_raw.strip() + f"\n{culprit}").strip()
                    log_security_alert(
                        time.strftime("%Y-%m-%d %H:%M:%S"),
                        culprit,
                        round(score, 4),
                        current.get("cpu", 0.0),
                        current.get("ram", 0.0),
                        current.get("disk", 0.0),
                        "Ignored by User (Known)"
                    )
                    st.toast(f"✅ Marked '{culprit}' as known and whitelisted.", icon="🛡️")
                    st.rerun()
        with col_tb4:
            if st.button("🛑 Kill (Unknown)", key="banner_kil_btn", use_container_width=True, type="primary"):
                success, msg = kill_top_cpu_process(culprit)
                ts_now = time.strftime("%Y-%m-%d %H:%M:%S")
                if success:
                    log_autokill_event(ts_now, culprit, score, True, f"Manual termination by user: {msg}")
                    log_security_alert(
                        ts_now,
                        culprit,
                        round(score, 4),
                        current.get("cpu", 0.0),
                        current.get("ram", 0.0),
                        current.get("disk", 0.0),
                        "Killed by User (Unknown)"
                    )
                    st.toast(f"🛑 Terminated rogue process '{culprit}': {msg}", icon="💥")
                    st.rerun()
                else:
                    st.error(f"Cannot terminate: {msg}")
        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

    # Status Banner
    state_reason = eval_res.get("state_reason", "")
    print(f"[SOC DIAGNOSTIC] {current.get('timestamp')} | SysCPU: {current.get('cpu', 0):.1f}% | SysRAM: {current.get('ram', 0):.1f}% | TopProc: {culprit} | ML Score: {score:.4f} | Threshold: {score_threshold:.4f} | State: {system_state} | Reason: {state_reason}")

    if is_stale:
        st.markdown(f"""
        <div class="status-paused">
            TELEMETRY PAUSED (Data is {data_age}s old — Collector is Offline)
        </div>
        """, unsafe_allow_html=True)
    elif system_state == "CRITICAL" and is_currently_running:
        st.markdown(f"""
        <div class="status-threat">
            🚨 SYSTEM ANOMALY DETECTED (Score: {score:.4f} &lt; Threshold: {score_threshold:.4f})<br>
            <span style="font-size:16px; font-weight:400; color:#fca5a5;">Top CPU process at tick: <code>{culprit_esc.upper()}</code> ({current.get('cpu', 0):.1f}% CPU)</span>
        </div>
        """, unsafe_allow_html=True)
    elif system_state == "CRITICAL" and not is_currently_running:
        st.markdown(f"""
        <div class="status-inactive">
            HISTORICAL INACTIVE ANOMALY (Top process <code>{culprit_esc.upper()}</code> terminated on OS)
        </div>
        """, unsafe_allow_html=True)
    elif system_state == "WARNING":
        st.markdown(f"""
        <div class="status-evaluating">
            ⚠️ SYSTEM WARNING: ELEVATED ANOMALY RISK / TRANSIENT SPIKE<br>
            <span style="font-size:16px; font-weight:400; color:#fde68a;">Top CPU process at tick: <code>{culprit_esc.upper()}</code> ({current.get('cpu', 0):.1f}% CPU)</span>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="status-secure">
            🛡️ SYSTEM STATE: SECURE
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
        st.metric("Memory Usage", f"{current['ram']:.1f}%", delta=f"{live_ram_gb:.1f}/{total_ram_gb:.1f} GB")

    st.markdown("---")

    # Real-Time Charts
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("CPU & RAM % Utilization")
        st.line_chart(df[["cpu", "ram"]])

    with col2:
        st.subheader("Telemetry Anomaly Score (lower = suspicious)")
        if "score" in df.columns:
            chart_score = df[["score"]].copy()
            chart_score["threshold"] = score_threshold
            st.line_chart(chart_score)
        else:
            st.info("Calculating anomaly scores...")

    col3, col4 = st.columns(2)
    with col3:
        st.subheader("Network Activity (bytes)")
        st.line_chart(df[["net_total"]])
    with col4:
        st.subheader("Anomalies Per Minute (Session-wide)")
        if not anom_per_min.empty and "minute" in anom_per_min.columns:
            st.bar_chart(anom_per_min.set_index("minute")["anomalies"])

    # Explainable AI (XAI) Section
    if real_anomaly:
        st.markdown("---")
        st.markdown("### Threat Diagnostic Breakdown (Explainable AI)")
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
        st.subheader(f"Process Mitigation Options for Top CPU Contributor `{culprit.upper()}`")
        col_known_p, col_kill_p = st.columns(2)
        with col_known_p:
            if st.button(f"✅ Mark as Known & Ignore ({culprit.upper()})", key="panel_whitelist_btn", use_container_width=True):
                if culprit.lower() not in whitelist:
                    st.session_state.whitelist_raw = (st.session_state.whitelist_raw.strip() + f"\n{culprit}").strip()
                log_security_alert(
                    time.strftime("%Y-%m-%d %H:%M:%S"),
                    culprit,
                    round(score, 4),
                    current.get("cpu", 0.0),
                    current.get("ram", 0.0),
                    current.get("disk", 0.0),
                    "Ignored by User (Known)"
                )
                st.toast(f"✅ Added {culprit} to whitelist & marked as known.", icon="🛡️")
                time.sleep(0.5)
                st.rerun()
        with col_kill_p:
            if st.button(f"🛑 Kill Rogue Process ({culprit})", key="panel_kill_btn", type="primary", use_container_width=True):
                with st.spinner(f"Terminating rogue process {culprit}..."):
                    success, msg = kill_top_cpu_process(culprit)
                    ts_kill = time.strftime("%Y-%m-%d %H:%M:%S")
                    if success:
                        log_autokill_event(ts_kill, culprit, score, True, f"Manual termination by SOC analyst (Unknown Threat): {msg}")
                        log_security_alert(
                            ts_kill,
                            culprit,
                            round(score, 4),
                            current.get("cpu", 0.0),
                            current.get("ram", 0.0),
                            current.get("disk", 0.0),
                            "Killed by User (Unknown)"
                        )
                        st.toast(f"🛑 {msg}", icon="💥")
                        time.sleep(0.5)
                        st.rerun()
                    else:
                        st.error(f"Termination failed: {msg}")

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
    log_filter = st.radio(
        "Filter Audit Records:",
        ["All Records", "Active Anomalies Only", "Suppressed Allowlist Events"],
        horizontal=True
    )

    if log_filter == "Active Anomalies Only":
        all_raw = get_security_alerts()
        saved_alerts = [a for a in all_raw if not str(a.get("action", "")).startswith("Suppressed")]
    elif log_filter == "Suppressed Allowlist Events":
        saved_alerts = get_security_alerts(action_filter="Suppressed")
    else:
        saved_alerts = get_security_alerts()

    if not saved_alerts:
        st.info("No security alerts matching this filter logged during this SOC session.")
    else:
        log_df = pd.DataFrame(saved_alerts)
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
            clear_security_alerts()
            clear_autokill_events()
            st.toast("Security Audit Logs cleared.")
            st.rerun()
            
    saved_autokill = get_autokill_events()
    if saved_autokill:
        st.markdown("---")
        st.subheader("🤖 Automated Response Mitigation Logs")
        st.dataframe(pd.DataFrame(saved_autokill))

    saved_model_events = get_model_events()
    if saved_model_events:
        st.markdown("---")
        st.subheader("🧠 Model Retraining & Version History")
        st.dataframe(pd.DataFrame(saved_model_events))

# ─────────────────────────────────────────────
# REFRESH ENGINE
# ─────────────────────────────────────────────
if st.session_state.get("active_dialog_open", False):
    st.info("⏸️ Telemetry auto-refresh paused while threat mitigation dialog is open.")
    st.stop()

time.sleep(refresh_rate)
st.rerun()

