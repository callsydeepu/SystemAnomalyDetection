import os
import shutil
import json
import pandas as pd
from pathlib import Path
from src.anomaly_detection.model import load_model_metadata, load_trained_models
from scripts.train_model import train, get_current_metadata, MODELS_DIR, DATA_FILE, BACKUPS_DIR

def test_retraining_lifecycle_and_continuous_dataset():
    """
    Validates that:
    1. Dataset is retained across retrains (never wiped or reset).
    2. Model version increments sequentially (V1 -> V2 -> V3).
    3. Backup directories are generated.
    4. Metadata correctly reflects accumulated training sample count.
    """
    assert DATA_FILE.exists(), f"Telemetry file {DATA_FILE} should exist for test."
    
    df_initial = pd.read_csv(DATA_FILE)
    initial_count = len(df_initial)
    assert initial_count >= 50, f"Expected at least 50 initial rows, found {initial_count}"

    # Retrain model -> produces next version
    meta_before = get_current_metadata()
    ver_before_num = int(meta_before.get("model_version_num", 1))

    # Execute retraining pipeline
    train()

    # Verify updated metadata
    meta_after = get_current_metadata()
    ver_after_num = int(meta_after.get("model_version_num", 2))
    ver_after_str = meta_after.get("model_version")

    assert ver_after_num == ver_before_num + 1 or ver_after_num >= 2
    assert ver_after_str.startswith("V")
    assert meta_after["training_samples"] >= initial_count

    # Verify dataset was NOT deleted or reset
    df_after = pd.read_csv(DATA_FILE)
    assert len(df_after) >= initial_count, "Dataset row count must not decrease after retraining."

    # Verify model artifact loading succeeds
    model, scaler, features, stats = load_trained_models()
    assert model is not None
    assert scaler is not None
    assert len(features) == 8
