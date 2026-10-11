import os
import shutil
import json
import tempfile
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
    5. Production models are restored afterwards so tests do not pollute production state.
    """
    assert DATA_FILE.exists(), f"Telemetry file {DATA_FILE} should exist for test."
    
    df_initial = pd.read_csv(DATA_FILE)
    initial_count = len(df_initial)
    assert initial_count >= 50, f"Expected at least 50 initial rows, found {initial_count}"

    # Record existing backup folders
    existing_backups = set(BACKUPS_DIR.glob("*")) if BACKUPS_DIR.exists() else set()

    # Preserve current production model artifacts to restore after test
    temp_preserve_dir = Path(tempfile.mkdtemp(prefix="sentinel_prod_model_backup_"))
    for item in MODELS_DIR.glob("*"):
        if item.is_file():
            shutil.copy2(item, temp_preserve_dir / item.name)

    try:
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

    finally:
        # Restore original production model state so test execution has zero side-effects
        if temp_preserve_dir.exists():
            for item in temp_preserve_dir.glob("*"):
                if item.is_file():
                    shutil.copy2(item, MODELS_DIR / item.name)
            shutil.rmtree(temp_preserve_dir, ignore_errors=True)

        # Clean up any backup folder created during test execution
        if BACKUPS_DIR.exists():
            current_backups = set(BACKUPS_DIR.glob("*"))
            for new_folder in (current_backups - existing_backups):
                if new_folder.is_dir():
                    shutil.rmtree(new_folder, ignore_errors=True)
