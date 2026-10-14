import joblib
from pathlib import Path
import warnings
import numpy as np

warnings.filterwarnings("ignore")

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
STATS_FILE = PROJECT_ROOT / "models" / "baseline_stats.pkl"

FEATURE_NAMES = {
    "cpu": "CPU Usage (%)",
    "ram": "RAM Usage (%)",
    "disk": "Disk Space (%)",
    "proc": "Process Count",
    "cpu_delta": "CPU Spike Rate",
    "cpu_z": "CPU rolling anomaly factor",
    "net_total": "Network Throughput",
    "net_roll": "Rolling Network Throughput"
}

def load_baseline_stats(stats_path=None):
    target_path = Path(stats_path) if stats_path else STATS_FILE
    if target_path.exists():
        try:
            return joblib.load(target_path)
        except Exception:
            return None
    return None

def _safe_float(v, default=0.0):
    if v is None:
        return default
    try:
        f = float(v)
        return default if np.isnan(f) or np.isinf(f) else f
    except (ValueError, TypeError):
        return default

def compute_xai_explanations(current_row, stats, features):
    """
    Computes Explainable AI (XAI) Z-score attributions relative to baseline means and stds.
    Returns list of explanation dicts for features with |z| >= 1.5.
    """
    if not current_row or not hasattr(current_row, "get"):
        return []
    if not stats or not isinstance(stats, dict) or "mean" not in stats or "std" not in stats:
        return []
        
    explanations = []
    means = stats.get("mean") or {}
    stds = stats.get("std") or {}
    
    for f in features:
        val = _safe_float(current_row.get(f, 0.0), default=0.0)
        mean = _safe_float(means.get(f, 0.0), default=0.0)
        std_raw = _safe_float(stds.get(f, 1.0), default=1.0)
        std = std_raw if std_raw > 0 else 1.0
        
        z = (val - mean) / (std + 1e-5)
        
        name = FEATURE_NAMES.get(f, f)
        if abs(z) >= 1.5:
            direction = "spiked" if z > 0 else "dropped"
            explanations.append({
                "feature": f,
                "name": name,
                "value": val,
                "mean": mean,
                "std": std,
                "z": z,
                "direction": direction
            })
    return explanations
