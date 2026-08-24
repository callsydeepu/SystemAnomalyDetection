import joblib
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
    }

def check_models_exist():
    paths = get_model_file_paths()
    return all(p.exists() for p in paths.values())

def load_trained_models():
    """
    Loads model, scaler, features list, and baseline stats from models/ directory.
    Returns (model, scaler, features, stats) or (None, None, None, None) if not trained.
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
            print(f"Model feature count mismatch detected (features: {len(features)}, scaler expecting: {scaler_n}, model expecting: {model_n}). Retraining required.")
            return None, None, None, None

        return model, scaler, features, stats
    except Exception as e:
        print(f"Error loading model artifacts: {e}")
        return None, None, None, None
