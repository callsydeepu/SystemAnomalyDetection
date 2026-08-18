import joblib
from pathlib import Path
import warnings

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

def load_baseline_stats():
    if STATS_FILE.exists():
        try:
            return joblib.load(STATS_FILE)
        except Exception:
            return None
    return None

def compute_xai_explanations(current_row, stats, features):
    """
    Computes Explainable AI (XAI) Z-score attributions relative to baseline means and stds.
    Returns list of explanation dicts for features with |z| >= 1.5.
    """
    if not stats or "mean" not in stats or "std" not in stats:
        return []
        
    explanations = []
    for f in features:
        val = current_row.get(f, 0)
        mean = stats["mean"].get(f, 0)
        std = stats["std"].get(f, 1)
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
