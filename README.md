# Adaptive Anomaly Detection in Operating Systems Using Machine Learning (AI Sentinel SOC)

AI Sentinel is a real-time, machine-learning-powered Operating System Anomaly Detection platform. It continuously monitors live host telemetry, extracts statistical behavioral features, and leverages an Isolation Forest model to detect unusual process behavior and system anomalies without relying on hardcoded rules, fake anomaly flags, or pre-labeled attack data.

---

## 🛡️ Key Features

- **Behavior-Based Anomaly Detection**: Evaluates processes dynamically using statistical ML features (`cpu`, `ram`, `disk`, `proc`, `cpu_delta`, `cpu_z`, `net_total`, `net_roll`) rather than process names or hardcoded lists.
- **Real-Time OS Telemetry Collection**: Continuously samples CPU%, RAM%, Swap%, Disk%, Network throughput deltas (bytes sent/received), total process count, and active top processes via `psutil`.
- **Isolation Forest ML Model**: Uses an unsupervised `IsolationForest` (200 trees, `StandardScaler`) trained on clean host baseline activity.
- **Temporal Persistence Validation**: Requires 3 consecutive suspicious observations before escalating a threat, preventing false alarms from brief 1-second workload spikes.
- **Live Process Lifecycle Enforcement**: Verifies host OS process state in real time (`psutil.process_iter()`). When a process terminates, it is immediately cleared from current threat cards.
- **Explainable AI (XAI)**: Identifies and displays exact metric Z-score deviations relative to learned baseline statistics whenever an anomaly is flagged.
- **Safe Demonstration Mechanism**: Includes a safe local test script (`demo/controlled_workload.py`) for live mentor/examiner demonstrations.
- **Interactive SOC Dashboard**: 4-tab Streamlit interface featuring Live Monitoring, Memory Metrics, Security Audit Logs, and SOC Settings.

---

## 📁 Repository Structure

```
SystemAnomalyDetection/
├── collect_data.py       # Real-time telemetry collector script
├── train_model.py         # Isolation Forest model training pipeline
├── app.py                 # Streamlit Security Operations Center (SOC) dashboard
├── run_app.py             # Entry-point runner script
├── build_exe.bat          # PyInstaller build script for standalone EXE creation
├── demo/                  # Demonstration suite for mentors/examiners
│   ├── controlled_workload.py  # Safe local CPU math workload script
│   └── README_DEMO.md          # 10-step mentor presentation guide
├── system_data.csv        # Baseline telemetry dataset (11-column format)
├── anomaly_model.pkl      # Trained Isolation Forest model artifact
├── scaler.pkl             # Trained StandardScaler artifact
├── feature_list.pkl       # ML feature definition list
├── baseline_stats.pkl     # Learned feature baseline statistics (means & stds)
├── requirements.txt       # Essential Python dependencies
└── .gitignore             # Ignored directories (.venv, __pycache__, logs)
```

---

## 🚀 Quick Start Guide

### 1. Installation
Clone the repository and install dependencies:
```powershell
git clone https://github.com/callsydeepu/SystemAnomalyDetection.git
cd SystemAnomalyDetection
pip install -r requirements.txt
```

### 2. Start Live Telemetry Collector
In Terminal 1:
```powershell
python collect_data.py
```

### 3. Launch Streamlit SOC Dashboard
In Terminal 2:
```powershell
python -m streamlit run app.py
```
Or run using the wrapper:
```powershell
python run_app.py
```
Open [http://localhost:8501](http://localhost:8501) in your browser.

### 4. Run Safe Demonstration Workload
In Terminal 3 (Optional for Live Demonstration):
```powershell
python demo/controlled_workload.py 30
```
See [demo/README_DEMO.md](demo/README_DEMO.md) for the complete 10-step mentor presentation flow.

### 5. Retrain Baseline Model (Optional)
To recalibrate the Isolation Forest model on your machine's current workload:
```powershell
python train_model.py
```

---

## 📊 Technical Architecture

```
┌───────────────────────────────┐
│     Windows Host Operating    │
│            System             │
└───────────────┬───────────────┘
                │ psutil telemetry @ 1s
                ▼
┌───────────────────────────────┐
│       collect_data.py         │  ← Background Telemetry Monitor
│   (10 metrics + timestamp)    │
└───────────────┬───────────────┘
                │ CSV append
                ▼
┌───────────────────────────────┐
│       system_data.csv         │  ← Data Repository
└───────┬───────────────┬───────┘
        │               │
        │ fit           │ predict / score
        ▼               ▼
┌───────────────┐ ┌───────────────┐
│train_model.py │ │    app.py     │  ← Streamlit SOC Dashboard
│ (Standard     │ │ (Streamlit)   │     - Live Monitor
│  Scaler +     │ └───────────────┘     - Memory Usage
│  Isolation    │                       - Security Audit Log
│  Forest)      │                       - Settings
└───────────────┘
```
