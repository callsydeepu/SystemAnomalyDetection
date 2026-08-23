import pandas as pd
from src.anomaly_detection.model import load_trained_models, check_models_exist
from src.anomaly_detection.baseline import load_baseline_stats, compute_xai_explanations
from src.anomaly_detection.predictor import evaluate_latest_sample
from src.features.feature_engineering import engineer_features

def test_model_loading():
    assert check_models_exist() == True
    model, scaler, features, stats = load_trained_models()
    assert model is not None
    assert scaler is not None
    assert isinstance(features, list)
    assert isinstance(stats, dict)

def test_predictor_evaluation():
    model, scaler, features, stats = load_trained_models()
    raw_data = {
        "timestamp": ["2026-08-18 10:00:00"],
        "cpu": [15.0],
        "ram": [85.0],
        "disk": [40.0],
        "sent_delta": [100],
        "recv_delta": [200],
        "proc": [200],
        "top_process": ["chrome.exe"]
    }
    df = pd.DataFrame(raw_data)
    df_feat = engineer_features(df)
    
    eval_res = evaluate_latest_sample(df_feat, model, scaler, features, threshold=-0.600)
    assert "score" in eval_res
    assert isinstance(eval_res["score"], float)
    assert "raw_is_anomaly" in eval_res
    assert isinstance(eval_res["raw_is_anomaly"], bool)

def test_resource_based_state_classification():
    from unittest.mock import MagicMock
    
    # Create dummy model, scaler, and features list
    dummy_model = MagicMock()
    dummy_scaler = MagicMock()
    
    dummy_scaler.transform = lambda x: x
    
    def evaluate_scenario(cpu_history, ram_history, score_history, threshold=-0.600, whitelist=None):
        raw_data = {
            "timestamp": ["2026-08-18 10:00:00", "2026-08-18 10:00:01", "2026-08-18 10:00:02"],
            "cpu": cpu_history,
            "ram": ram_history,
            "disk": [40.0, 40.0, 40.0],
            "sent_delta": [100, 100, 100],
            "recv_delta": [200, 200, 200],
            "proc": [200, 200, 200],
            "top_process": ["chrome.exe", "chrome.exe", "chrome.exe"]
        }
        df = pd.DataFrame(raw_data)
        
        # Mock score_samples to return the score_history
        dummy_model.score_samples = lambda x: score_history[-len(x):]
        
        features = ["cpu", "ram", "disk", "proc"]
        
        res = evaluate_latest_sample(df, dummy_model, dummy_scaler, features, threshold=threshold, whitelist=whitelist)
        return res

    # 1. CPU 30%, Memory 40% -> SECURE
    res = evaluate_scenario([30.0, 30.0, 30.0], [40.0, 40.0, 40.0], [0.0, 0.0, 0.0])
    assert res["system_state"] == "SECURE"
    assert res["threat_confidence"] == 0.0

    # 2. CPU 70%, Memory 60% -> SECURE
    res = evaluate_scenario([70.0, 70.0, 70.0], [60.0, 60.0, 60.0], [0.0, 0.0, 0.0])
    assert res["system_state"] == "SECURE"
    assert res["threat_confidence"] == 20.0

    # 3. CPU 85%, Memory 70% -> WARNING
    res = evaluate_scenario([70.0, 70.0, 85.0], [60.0, 60.0, 70.0], [0.0, 0.0, 0.0])
    assert res["system_state"] == "WARNING"
    assert res["threat_confidence"] > 0.0

    # 4. CPU 95%, Memory 70% -> CRITICAL
    res = evaluate_scenario([95.0, 95.0, 95.0], [70.0, 70.0, 70.0], [0.0, 0.0, 0.0])
    assert res["system_state"] == "CRITICAL"
    assert res["threat_confidence"] >= 80.0

    # 5. CPU 100%, Memory 88% -> CRITICAL
    res = evaluate_scenario([100.0, 100.0, 100.0], [88.0, 88.0, 88.0], [0.0, 0.0, 0.0])
    assert res["system_state"] == "CRITICAL"
    assert res["threat_confidence"] == 100.0

    # 6. CPU 60%, Memory 97% -> CRITICAL
    res = evaluate_scenario([60.0, 60.0, 60.0], [97.0, 97.0, 97.0], [0.0, 0.0, 0.0])
    assert res["system_state"] == "CRITICAL"
    assert res["threat_confidence"] >= 80.0

    # 7. CPU 100%, Memory 90%, normal ML score -> CRITICAL
    res = evaluate_scenario([100.0, 100.0, 100.0], [90.0, 90.0, 90.0], [0.5, 0.5, 0.5])
    assert res["system_state"] == "CRITICAL"
    assert res["threat_confidence"] == 100.0
