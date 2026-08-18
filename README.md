# Adaptive Anomaly Detection in Operating Systems Using Machine Learning (AI Sentinel SOC)

AI Sentinel is a real-time, machine-learning-powered Operating System Anomaly Detection platform. It continuously monitors live host telemetry, extracts statistical behavioral features, and leverages an Isolation Forest model to detect unusual process behavior and system anomalies without relying on hardcoded rules, fake anomaly flags, or pre-labeled attack data.

> 🔒 **Privacy & Portability Guarantee**: This repository ships **zero personal telemetry data or pre-trained machine weights**. Every user who clones this project collects their own system telemetry and trains an adaptive baseline tailored specifically to their own computer.

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
│       └── app.py                     # Streamlit SOC Dashboard & Calibration Wizard
│
├── models/                            # User's trained ML artifacts (Created on setup)
│   └── .gitkeep
│
├── data/                              # User's telemetry storage (Created on setup)
│   └── .gitkeep
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

## 🚀 First-Time User Setup Guide

Follow these 5 steps when setting up the project on a new computer:

### Step 1: Clone Repository & Install Dependencies
```powershell
git clone https://github.com/callsydeepu/SystemAnomalyDetection.git
cd SystemAnomalyDetection
pip install -r requirements.txt
```

### Step 2: Collect Personal System Baseline Data
Run the background telemetry collector to observe your computer's normal operating workload:
```powershell
python scripts/collect_data.py
```
*(Let it run for 1–2 minutes to record ~100 baseline observations in `data/system_data.csv`)*.

### Step 3: Train Your Machine's Anomaly Detection Model
Train the Isolation Forest model on your machine's recorded baseline:
```powershell
python scripts/train_model.py
```
*(Generates your machine's trained artifacts in `models/`)*.

### Step 4: Start the Live SOC Dashboard
Launch the dashboard from the project root:
```powershell
python run.py
```
*(Or simply run `python run.py` first, and the interactive **Cold-Start Calibration Wizard** will guide you through steps 2 and 3 automatically!)*

Open [http://localhost:8501](http://localhost:8501) in your browser.

### Step 5: Run Safe Controlled Demonstration (Optional)
In a separate terminal, test the real-time detection pipeline:
```powershell
python demo/controlled_workload.py 30
```
See [demo/README_DEMO.md](demo/README_DEMO.md) for the complete 10-step mentor presentation procedure.

---

## 🧪 Running Unit Tests
```powershell
python -c "import tests.test_monitoring as tm, tests.test_features as tf, tests.test_anomaly_detection as ta; tm.test_get_proc_count(); tm.test_get_top_process(); tm.test_is_process_currently_running(); tf.test_engineer_features_structure(); tf.test_cpu_delta_calculation(); ta.test_model_loading(); ta.test_predictor_evaluation(); print('All unit tests passed cleanly!')"
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
│     data/system_data.csv      │  ← User Data Repository
└───────┬───────────────┬───────┘
        │               │
        │ fit           │ predict / score
        ▼               ▼
┌───────────────┐ ┌───────────────┐
│scripts/       │ │src/dashboard/ │  ← Streamlit SOC Dashboard
│train_model.py │ │ (app.py)      │     - Live Monitor
│ (Isolation    │ └───────────────┘     - Cold-Start Wizard
│  Forest)      │                       - Memory Usage
└───────┬───────┘                       - Security Log
        │ saves
        ▼
┌───────────────┐
│   models/*.pkl│
└───────────────┘
```
