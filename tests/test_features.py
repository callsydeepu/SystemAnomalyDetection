import pandas as pd
import numpy as np
from src.features.feature_engineering import engineer_features, FEATURES

def test_engineer_features_structure():
    raw_data = {
        "timestamp": ["2026-08-18 10:00:00", "2026-08-18 10:00:01"],
        "cpu": [10.5, 50.0],
        "ram": [80.0, 81.0],
        "disk": [40.0, 40.0],
        "sent_delta": [100, 500],
        "recv_delta": [200, 1000],
        "proc": [200, 201],
        "top_process": ["chrome.exe", "python.exe"]
    }
    df = pd.DataFrame(raw_data)
    df_feat = engineer_features(df)
    
    assert len(FEATURES) == 8
    for f in FEATURES:
        assert f in df_feat.columns
    assert not df_feat[FEATURES].isna().any().any()
    assert not np.isinf(df_feat[FEATURES].values).any()

def test_cpu_delta_calculation():
    raw_data = {
        "cpu": [10.0, 60.0],
        "ram": [50.0, 50.0],
        "disk": [10.0, 10.0],
        "sent_delta": [0, 0],
        "recv_delta": [0, 0],
        "proc": [100, 100]
    }
    df = pd.DataFrame(raw_data)
    df_feat = engineer_features(df)
    assert df_feat["cpu_delta"].iloc[1] == 50.0

def test_engineer_features_empty_and_missing_columns():
    # Empty DataFrame resilience
    empty_df = pd.DataFrame()
    res_empty = engineer_features(empty_df)
    assert len(res_empty) == 0
    for f in FEATURES:
        assert f in res_empty.columns

    # Missing columns resilience
    partial_df = pd.DataFrame({"cpu": [20.0, 40.0]})
    res_partial = engineer_features(partial_df)
    assert len(res_partial) == 2
    for f in FEATURES:
        assert f in res_partial.columns
        assert not res_partial[f].isna().any()
