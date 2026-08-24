import sqlite3
from pathlib import Path
import warnings

warnings.filterwarnings("ignore")

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DB_PATH = PROJECT_ROOT / "data" / "security_audit.db"

def init_audit_db():
    """Initializes SQLite database and tables for persistent security audit logs."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
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
        conn.commit()

def log_security_alert(timestamp, process, score, cpu, ram, disk, action):
    """
    Inserts a security alert into the persistent SQLite database.
    Uses dedup_key to prevent duplicate entries on Streamlit reruns.
    """
    init_audit_db()
    dedup_key = f"{timestamp}_{process}_{action}"
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR IGNORE INTO security_alerts (timestamp, process, score, cpu, ram, disk, action, dedup_key)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (str(timestamp), str(process), float(score), float(cpu), float(ram), float(disk), str(action), dedup_key))
        conn.commit()

def get_security_alerts():
    """Returns all security alerts as a list of dicts (newest first)."""
    init_audit_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, process, score, cpu, ram, disk, action FROM security_alerts ORDER BY id DESC")
        rows = cursor.fetchall()
        return [dict(row) for row in rows]

def clear_security_alerts():
    """Clears all security alerts from persistent SQLite storage."""
    init_audit_db()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM security_alerts")
        conn.commit()

def log_autokill_event(timestamp, target, score, success, details):
    """Inserts an automated response mitigation log into the persistent SQLite database."""
    init_audit_db()
    dedup_key = f"{timestamp}_{target}_{details}"
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR IGNORE INTO autokill_logs (timestamp, target, score, success, details, dedup_key)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (str(timestamp), str(target), float(score), 1 if success else 0, str(details), dedup_key))
        conn.commit()

def get_autokill_events():
    """Returns all autokill logs as a list of dicts (newest first)."""
    init_audit_db()
    with sqlite3.connect(DB_PATH) as conn:
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

def clear_autokill_events():
    """Clears all autokill logs from persistent SQLite storage."""
    init_audit_db()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM autokill_logs")
        conn.commit()
