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
