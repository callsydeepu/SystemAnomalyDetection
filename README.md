# Adaptive Anomaly Detection in Operating Systems Using Machine Learning (AI Sentinel SOC)

AI Sentinel is a real-time, machine-learning-powered Operating System Anomaly Detection platform. It continuously monitors live host telemetry, extracts statistical behavioral features, and leverages an Isolation Forest model to detect unusual process behavior and system anomalies without relying on hardcoded rules, fake anomaly flags, or pre-labeled attack data.

---

## 📁 Project Directory Structure

```text
adaptive-os-anomaly-detection/
│
├── README.md                          # Project documentation & execution guide
├── requirements.txt                   # Essential Python dependencies
├── .gitignore                         # Git ignore definitions (.venv, __pycache__, logs)
├── run.py                             # Root application entry point
│
├── src/                               # Core application modules
│   ├── __init__.py
│   ├── monitoring/
│   │   ├── __init__.py
│   │   ├── process_monitor.py         # Process enumeration & live lifecycle check
│   │   └── system_monitor.py          # Real-time psutil telemetry collector
│   ├── features/
│   │   ├── __init__.py
│   │   └── feature_engineering.py     # 8-feature calculation & rolling Z-scores
│   ├── anomaly_detection/
│   │   ├── __init__.py
│   │   ├── model.py                   # Model loader & IsolationForest wrapper
│   │   ├── baseline.py                # Baseline stats & Explainable AI (XAI) breakdown
│   │   └── predictor.py               # Real-time predictor & persistence check
│   └── dashboard/
│       ├── __init__.py
│       └── app.py                     # Streamlit SOC Dashboard
│
├── models/                            # Trained ML artifacts
│   ├── anomaly_model.pkl
│   ├── baseline_stats.pkl
│   ├── scaler.pkl
│   └── feature_list.pkl
│
├── data/                              # Data storage
│   └── system_data.csv                # 11-column telemetry dataset
│
├── demo/                              # Safe demonstration suite
│   ├── controlled_workload.py         # Local CPU computational math workload
│   └── README_DEMO.md                 # 10-step mentor presentation guide
│
├── scripts/                           # Utility & management scripts
│   ├── collect_data.py                # Standalone telemetry collector runner
│   ├── train_model.py                 # Isolation Forest model training pipeline
│   └── build_exe.bat                  # PyInstaller standalone build script
│
└── tests/                             # Unit & integration test suite
    ├── test_monitoring.py             # Process monitoring unit tests
    ├── test_features.py               # Feature engineering unit tests
    └── test_anomaly_detection.py      # ML anomaly detection unit tests
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

### 2. Launch Streamlit SOC Dashboard (Root Entry Point)
```powershell
python run.py
```
Open [http://localhost:8501](http://localhost:8501) in your browser.

### 3. Start Telemetry Collector (Standalone Terminal)
```powershell
python scripts/collect_data.py
```

### 4. Retrain Baseline Model (Optional)
To recalibrate the Isolation Forest model on your machine's current workload:
```powershell
python scripts/train_model.py
```

### 5. Run Controlled Demonstration Workload
For live mentor/examiner demonstrations:
```powershell
python demo/controlled_workload.py 30
```
See [demo/README_DEMO.md](demo/README_DEMO.md) for the complete 10-step presentation procedure.

### 6. Run Unit Tests
```powershell
python -c "import tests.test_monitoring as tm, tests.test_features as tf, tests.test_anomaly_detection as ta; tm.test_get_proc_count(); tm.test_get_top_process(); tm.test_is_process_currently_running(); tf.test_engineer_features_structure(); tf.test_cpu_delta_calculation(); ta.test_model_loading(); ta.test_predictor_evaluation(); print('All unit tests passed cleanly!')"
```

### 7. Build Standalone Executable
```cmd
scripts\build_exe.bat
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
│     src/monitoring/           │  ← Background Telemetry Monitor
│  (system_monitor.py)          │
└───────────────┬───────────────┘
                │ CSV append
                ▼
┌───────────────────────────────┐
│     data/system_data.csv      │  ← Data Repository
└───────┬───────────────┬───────┘
        │               │
        │ fit           │ predict / score
        ▼               ▼
┌───────────────┐ ┌───────────────┐
│scripts/       │ │src/dashboard/ │  ← Streamlit SOC Dashboard
│train_model.py │ │ (app.py)      │     - Live Monitor
│ (Isolation    │ └───────────────┘     - Memory Usage
│  Forest)      │                       - Security Audit Log
└───────┬───────┘                       - Settings
        │ saves
        ▼
┌───────────────┐
│   models/*.pkl│
└───────────────┘
```
