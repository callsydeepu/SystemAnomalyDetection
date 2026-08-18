# Adaptive Anomaly Detection in Operating Systems Using Machine Learning (AI Sentinel SOC)

AI Sentinel is a real-time, machine-learning-powered Operating System Anomaly Detection platform. It monitors live host telemetry, extracts statistical behavioral features, and leverages an Isolation Forest model to detect unusual process behavior and system anomalies without relying on pre-labeled attack data.

---

## 🛡️ Key Features

- **Real-Time OS Telemetry Collection**: Monitors CPU%, RAM%, Swap%, Disk%, Network throughput deltas (bytes sent/received), total process count, and top CPU process names via `psutil`.
- **Machine Learning Engine**: Uses an unsupervised `IsolationForest` model trained on host-calibrated baseline data with `StandardScaler` feature normalization.
- **Engineered Features**: Calculates instantaneous deltas (`cpu_delta`), 30-sample rolling Z-scores (`cpu_z`), and rolling network throughput (`net_roll`).
- **Temporal Persistence Check**: Requires consecutive suspicious observations before escalating a threat, preventing false alarms from brief 1-second workload spikes (e.g., opening browser tabs).
- **Explainable AI (XAI)**: Identifies and displays exact metric deviations (Z-scores) relative to learned baseline statistics whenever an anomaly is flagged.
- **Process Lifecycle Verification**: Ensures terminated/inactive processes are cleared from active threat alerts.
- **Interactive SOC Dashboard**: 4-tab Streamlit interface featuring Live Monitoring, Memory Metrics, Security Audit Logs, and SOC Settings.

---

## 📁 Repository Structure

```
SystemAnomalyDetection/
├── collect_data.py       # Live telemetry collector script
├── train_model.py         # Isolation Forest model training pipeline
├── app.py                 # Streamlit Security Operations Center (SOC) dashboard
├── run_app.py             # Entry-point runner script
├── build_exe.bat          # PyInstaller build script for standalone EXE creation
├── system_data.csv        # Baseline telemetry dataset
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
Clone the repository and install the dependencies:
```powershell
git clone https://github.com/callsydeepu/SystemAnomalyDetection.git
cd SystemAnomalyDetection
pip install -r requirements.txt
```

### 2. Start Live Telemetry Collector
In a terminal, start the background telemetry collector:
```powershell
python collect_data.py
```

### 3. Launch Streamlit SOC Dashboard
In a separate terminal, start the dashboard:
```powershell
python -m streamlit run app.py
```
Or run using the wrapper script:
```powershell
python run_app.py
```
Open [http://localhost:8501](http://localhost:8501) in your browser.

### 4. Retrain Baseline Model (Optional)
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
│       collect_data.py         │  ← Background Collector
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
