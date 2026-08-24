import joblib
import json
import numpy as np
from pathlib import Path
import warnings

warnings.filterwarnings("ignore")

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
MODELS_DIR = PROJECT_ROOT / "models"

def get_model_file_paths():
    return {
        "model": MODELS_DIR / "anomaly_model.pkl",
        "scaler": MODELS_DIR / "scaler.pkl",
        "features": MODELS_DIR / "feature_list.pkl",
        "stats": MODELS_DIR / "baseline_stats.pkl",
        "metadata": MODELS_DIR / "metadata.json",
    }

def check_models_exist():
    paths = get_model_file_paths()
    return all(p.exists() for p in paths.values())

def load_model_metadata():
    """Loads metadata.json if present, or returns default dict."""
    paths = get_model_file_paths()
    meta_path = paths["metadata"]
    if meta_path.exists():
        try:
            with open(meta_path, "r") as f:
                data = json.load(f)
                if "model_version" not in data:
                    data["model_version"] = "V1"
                return data
        except Exception:
            pass
    return {}


def load_trained_models():
    """
    Loads personal model, scaler, features list, baseline stats, and metadata.
    Validates feature dimensions and executes a dry-run scoring pass to ensure model integrity.
    Returns (model, scaler, features, stats) or (None, None, None, None) if invalid/missing.
    """
    paths = get_model_file_paths()
    if not check_models_exist():
        return None, None, None, None
    try:
        model = joblib.load(paths["model"])
        scaler = joblib.load(paths["scaler"])
        features = joblib.load(paths["features"])
        stats = joblib.load(paths["stats"])
        
        scaler_n = getattr(scaler, "n_features_in_", None)
        model_n = getattr(model, "n_features_in_", None)
        if (scaler_n is not None and len(features) != scaler_n) or (model_n is not None and len(features) != model_n):
            print(f"Model feature count mismatch detected (features: {len(features)}, scaler expecting: {scaler_n}, model expecting: {model_n}). Recalibration required.")
            return None, None, None, None

        # Dry-run validation test pass to confirm model scoring integrity
        dummy_input = np.zeros((1, len(features)))
        dummy_scaled = scaler.transform(dummy_input)
        _ = model.score_samples(dummy_scaled)

        return model, scaler, features, stats
    except Exception as e:
        print(f"Error loading personal model artifacts: {e}")
        return None, None, None, None

