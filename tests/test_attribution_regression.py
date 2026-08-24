import pandas as pd
from unittest.mock import MagicMock
from src.anomaly_detection.predictor import evaluate_latest_sample

def test_high_ram_normal_ml_score_no_false_critical():
    """
    Regression Test:
    Proves that high system RAM (96.4%) with normal ML anomaly score (-0.5464)
    does NOT trigger a CRITICAL system state or label processes like SQLSERVR.EXE
    or NOTION.EXE as anomalous processes.
    """
    dummy_model = MagicMock()
    dummy_scaler = MagicMock()
    
    # Scaler returns input unchanged
    dummy_scaler.transform = lambda x: x
    
    # Model returns normal score (-0.5464), which is ABOVE threshold (-0.600)
    dummy_model.score_samples = lambda x: [-0.5464] * len(x)
    
    raw_data = {
        "timestamp": ["2026-08-24 18:00:00", "2026-08-24 18:00:01", "2026-08-24 18:00:02"],
        "cpu": [19.8, 12.1, 15.0],
        "ram": [96.4, 96.3, 96.5],  # High RAM load
        "disk": [40.0, 40.0, 40.0],
        "proc": [200, 200, 200],
        "cpu_delta": [0.5, 0.2, 0.3],
        "cpu_z": [0.1, 0.1, 0.1],
        "net_total": [500, 500, 500],
        "net_roll": [500, 500, 500],
        "top_process": ["SQLSERVR.EXE", "NOTION.EXE", "SQLSERVR.EXE"]
    }
    df = pd.DataFrame(raw_data)
    features = ["cpu", "ram", "disk", "proc", "cpu_delta", "cpu_z", "net_total", "net_roll"]
    
    threshold = -0.600
    res = evaluate_latest_sample(df, dummy_model, dummy_scaler, features, threshold=threshold)
    
    # Single Source of Truth Assertions
    assert res["score"] == -0.5464
    assert res["threshold"] == threshold
    assert res["raw_is_anomaly"] == False
    assert res["threat_confidence"] == 0.0
    assert res["system_state"] == "SECURE"
    assert "System behavior within learned baseline" in res["state_reason"]

def test_high_cpu_normal_ml_score_no_false_critical():
    """
    Regression Test:
    Proves that high CPU usage (92.0%) with normal ML anomaly score (-0.500)
    does NOT trigger a CRITICAL system state.
    """
    dummy_model = MagicMock()
    dummy_scaler = MagicMock()
    dummy_scaler.transform = lambda x: x
    dummy_model.score_samples = lambda x: [-0.500] * len(x)
    
    raw_data = {
        "timestamp": ["2026-08-24 18:00:00", "2026-08-24 18:00:01", "2026-08-24 18:00:02"],
        "cpu": [92.0, 92.0, 92.0],
        "ram": [60.0, 60.0, 60.0],
        "disk": [40.0, 40.0, 40.0],
        "proc": [200, 200, 200],
        "cpu_delta": [1.0, 1.0, 1.0],
        "cpu_z": [0.5, 0.5, 0.5],
        "net_total": [500, 500, 500],
        "net_roll": [500, 500, 500],
        "top_process": ["chrome.exe", "chrome.exe", "chrome.exe"]
    }
    df = pd.DataFrame(raw_data)
    features = ["cpu", "ram", "disk", "proc", "cpu_delta", "cpu_z", "net_total", "net_roll"]
    
    res = evaluate_latest_sample(df, dummy_model, dummy_scaler, features, threshold=-0.600)
    
    assert res["raw_is_anomaly"] == False
    assert res["threat_confidence"] == 0.0
    assert res["system_state"] == "SECURE"

def test_genuine_ml_score_anomaly_triggers_critical():
    """
    Regression Test:
    Proves that genuine ML score anomaly (-0.7500 < threshold -0.6000)
    for 3 consecutive samples correctly triggers CRITICAL system state.
    """
    dummy_model = MagicMock()
    dummy_scaler = MagicMock()
    dummy_scaler.transform = lambda x: x
    dummy_model.score_samples = lambda x: [-0.7500] * len(x)
    
    raw_data = {
        "timestamp": ["2026-08-24 18:00:00", "2026-08-24 18:00:01", "2026-08-24 18:00:02"],
        "cpu": [50.0, 50.0, 50.0],
        "ram": [60.0, 60.0, 60.0],
        "disk": [40.0, 40.0, 40.0],
        "proc": [200, 200, 200],
        "cpu_delta": [20.0, 20.0, 20.0],
        "cpu_z": [3.5, 3.5, 3.5],
        "net_total": [50000, 50000, 50000],
        "net_roll": [50000, 50000, 50000],
        "top_process": ["controlled_workload.py", "controlled_workload.py", "controlled_workload.py"]
    }
    df = pd.DataFrame(raw_data)
    features = ["cpu", "ram", "disk", "proc", "cpu_delta", "cpu_z", "net_total", "net_roll"]
    
    res = evaluate_latest_sample(df, dummy_model, dummy_scaler, features, threshold=-0.600)
    
    assert res["raw_is_anomaly"] == True
    assert res["threat_confidence"] > 0.0
    assert res["system_state"] == "CRITICAL"
    assert "continuously below threshold" in res["state_reason"]
