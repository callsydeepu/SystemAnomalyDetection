import sqlite3
from pathlib import Path
import warnings
import math

warnings.filterwarnings("ignore")

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DB_PATH = PROJECT_ROOT / "data" / "security_audit.db"

def _resolve_db_path(db_path=None):
    return Path(db_path) if db_path is not None else DB_PATH

def _safe_float(val, default=0.0):
    if val is None:
        return default
    try:
        f = float(val)
        return default if math.isnan(f) or math.isinf(f) else f
    except (ValueError, TypeError):
        return default

def _safe_int(val, default=0):
    if val is None:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default

def init_audit_db(db_path=None):
    """Initializes SQLite database and tables for persistent security audit logs."""
    target_path = _resolve_db_path(db_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(target_path, timeout=15.0) as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA busy_timeout=15000;")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                process TEXT NOT NULL,
                score REAL,
                cpu REAL,
                ram REAL,
                disk REAL,
                action TEXT,
                dedup_key TEXT UNIQUE
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS autokill_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                target TEXT NOT NULL,
                score REAL,
                success INTEGER,
                details TEXT,
                dedup_key TEXT UNIQUE
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS model_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                model_version TEXT NOT NULL,
                training_samples INTEGER,
                details TEXT,
                dedup_key TEXT UNIQUE
            )
        """)
        conn.commit()

def log_security_alert(timestamp, process, score, cpu, ram, disk, action, db_path=None):
    """
    Inserts a security alert into the persistent SQLite database.
    Uses dedup_key to prevent duplicate entries on Streamlit reruns.
    """
    target_path = _resolve_db_path(db_path)
    init_audit_db(target_path)
    dedup_key = f"{timestamp}_{process}_{action}"
    with sqlite3.connect(target_path, timeout=15.0) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR IGNORE INTO security_alerts (timestamp, process, score, cpu, ram, disk, action, dedup_key)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            str(timestamp),
            str(process),
            _safe_float(score),
            _safe_float(cpu),
            _safe_float(ram),
            _safe_float(disk),
            str(action),
            dedup_key
        ))
        conn.commit()

def get_security_alerts(db_path=None):
    """Returns all security alerts as a list of dicts (newest first)."""
    target_path = _resolve_db_path(db_path)
    init_audit_db(target_path)
    with sqlite3.connect(target_path, timeout=15.0) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, process, score, cpu, ram, disk, action FROM security_alerts ORDER BY id DESC")
        rows = cursor.fetchall()
        return [dict(row) for row in rows]

def clear_security_alerts(db_path=None):
    """Clears all security alerts from persistent SQLite storage."""
    target_path = _resolve_db_path(db_path)
    init_audit_db(target_path)
    with sqlite3.connect(target_path, timeout=15.0) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM security_alerts")
        conn.commit()

def log_autokill_event(timestamp, target, score, success, details, db_path=None):
    """Inserts an automated response mitigation log into the persistent SQLite database."""
    target_path = _resolve_db_path(db_path)
    init_audit_db(target_path)
    dedup_key = f"{timestamp}_{target}_{details}"
    with sqlite3.connect(target_path, timeout=15.0) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR IGNORE INTO autokill_logs (timestamp, target, score, success, details, dedup_key)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            str(timestamp),
            str(target),
            _safe_float(score),
            1 if success else 0,
            str(details),
            dedup_key
        ))
        conn.commit()

def get_autokill_events(db_path=None):
    """Returns all autokill logs as a list of dicts (newest first)."""
    target_path = _resolve_db_path(db_path)
    init_audit_db(target_path)
    with sqlite3.connect(target_path, timeout=15.0) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, target, score, success, details FROM autokill_logs ORDER BY id DESC")
        rows = cursor.fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["success"] = bool(d["success"])
            result.append(d)
        return result

def clear_autokill_events(db_path=None):
    """Clears all autokill logs from persistent SQLite storage."""
    target_path = _resolve_db_path(db_path)
    init_audit_db(target_path)
    with sqlite3.connect(target_path, timeout=15.0) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM autokill_logs")
        conn.commit()

def log_model_event(timestamp, event_type, model_version, training_samples, details, db_path=None):
    """Inserts a model retraining lifecycle event into persistent SQLite DB."""
    target_path = _resolve_db_path(db_path)
    init_audit_db(target_path)
    dedup_key = f"{timestamp}_{event_type}_{model_version}_{training_samples}"
    with sqlite3.connect(target_path, timeout=15.0) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR IGNORE INTO model_events (timestamp, event_type, model_version, training_samples, details, dedup_key)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            str(timestamp),
            str(event_type),
            str(model_version),
            _safe_int(training_samples),
            str(details),
            dedup_key
        ))
        conn.commit()

def get_model_events(db_path=None):
    """Returns all model retraining events as a list of dicts (newest first)."""
    target_path = _resolve_db_path(db_path)
    init_audit_db(target_path)
    with sqlite3.connect(target_path, timeout=15.0) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, event_type, model_version, training_samples, details FROM model_events ORDER BY id DESC")
        rows = cursor.fetchall()
        return [dict(row) for row in rows]

def clear_model_events(db_path=None):
    """Clears all model events from persistent SQLite storage."""
    target_path = _resolve_db_path(db_path)
    init_audit_db(target_path)
    with sqlite3.connect(target_path, timeout=15.0) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM model_events")
        conn.commit()
