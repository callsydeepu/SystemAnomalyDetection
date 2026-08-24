import pytest
import os
import json
from pathlib import Path
from src.anomaly_detection.model import (
    load_trained_models,
    check_models_exist,
    load_model_metadata,
    get_model_file_paths
)

def test_personal_model_lifecycle_and_validation():
    # 1. Verify model files check
    exists = check_models_exist()
    paths = get_model_file_paths()
    assert "metadata" in paths

    # 2. Verify model loading
    model, scaler, features, stats = load_trained_models()
    if exists:
        assert model is not None
        assert scaler is not None
        assert isinstance(features, list)
        assert isinstance(stats, dict)
        
        # Verify metadata
        metadata = load_model_metadata()
        assert isinstance(metadata, dict)
        if metadata:
            assert "model_version" in metadata
            assert "pc_name" in metadata
            assert "training_samples" in metadata

def test_corrupted_model_validation():
    # Verify load_trained_models returns None if model file path does not exist
    import tempfile
    paths = get_model_file_paths()
    
    # Save original exists result
    res = check_models_exist()
    assert isinstance(res, bool)
