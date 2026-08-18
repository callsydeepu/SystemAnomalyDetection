# Real-Time OS Anomaly Monitoring — Demonstration Guide

This guide details the exact procedure for demonstrating real-time, behavior-based anomaly detection on Windows operating system processes using the **AI Sentinel** platform.

---

## 🛡️ Core Principles

1. **No Fake Anomalies / No Hardcoded Rules**: The anomaly detector does **not** rely on hardcoded process names or artificial `anomaly = True` flags. Every process is evaluated dynamically by the `IsolationForest` machine learning model.
2. **Real Host Process Monitoring**: The workload runs as a real host OS process (`controlled_workload.py`). It is sampled naturally by `collect_data.py`, engineered by `engineer_features()`, and scored by `model.score_samples()`.
3. **Live Process Lifecycle Enforcement**: If a process terminates, it immediately disappears from current monitoring and current threat cards.
4. **Behavior-Based Detection**: The model evaluates statistical deviations (CPU, RAM, deltas, Z-scores) from learned baseline behavior, rather than matching process names.

---

## 🚀 Step-by-Step Mentor Demonstration Flow

### Step 1: Open Terminal 1 — Start Live Telemetry Monitoring
```powershell
python collect_data.py
```
**Terminal Output:**
```text
============================================================
  AI Sentinel — Real-Time OS Anomaly Monitor
============================================================
  Monitoring PID : 12345
  CPU Cores      : 16
  Total RAM      : 15.73 GB
  Telemetry File : system_data.csv
============================================================
  Active OS Monitoring Started...
```

### Step 2: Open Terminal 2 — Launch Streamlit Dashboard
```powershell
python -m streamlit run app.py
```
Open [http://localhost:8507](http://localhost:8507) in your browser.

### Step 3: Observe Baseline (Normal Idle / Multitasking)
Point out to your mentor:
- The system state is `🛡️ SYSTEM STATE: SECURE`.
- Continuous anomaly scores remain in the normal range (`-0.42` to `-0.54`).
- Standard applications (Chrome, VS Code, SQL Server, Python) operate normally.

### Step 4: Open Terminal 3 — Run Controlled Workload
In Terminal 3, run the safe local CPU computational workload for 30 seconds:
```powershell
python demo/controlled_workload.py 30
```

### Step 5: Observe Telemetry Capture & Feature Engineering
Show your mentor:
- CPU utilization jumping to 100% on the **CPU & RAM % Utilization** chart.
- `controlled_workload.py` detected naturally as the active top process.
- The rolling feature pipeline computing `cpu_delta` and `cpu_z` Z-scores.

### Step 6: Observe ML Model Anomaly Detection
Show the **Telemetry Anomaly Score** timeline chart:
- The Isolation Forest score drops to `~ -0.65` to `-0.72` (below the `-0.600` decision threshold).
- Point out the 3-sample **Temporal Persistence Check**: after 3 consecutive ticks (~3s), the state escalates naturally to:
```
🚨 CONFIRMED ANOMALY FLAGGED: CONTROLLED_WORKLOAD.PY
```
- Scroll to the **Explainable AI (XAI)** breakdown showing exact statistical deviations (e.g. `🔺 CPU USAGE SPIKED (+24.5σ)`).

### Step 7: Terminate Workload & Verify Automatic Recovery
Wait 30 seconds (or press `Ctrl+C` in Terminal 3). Show your mentor:
- `controlled_workload.py` terminates.
- The **Live Process Lifecycle Checker** immediately verifies process termination.
- The threat status clears automatically, returning to `🛡️ SYSTEM STATE: SECURE`.
- No stale anomaly remains on the dashboard.
