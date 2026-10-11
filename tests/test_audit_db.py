import os
import tempfile
from pathlib import Path
from src.audit.audit_db import (
    log_security_alert,
    get_security_alerts,
    clear_security_alerts,
    log_autokill_event,
    get_autokill_events,
    clear_autokill_events,
    log_model_event,
    get_model_events
)

TEST_DB_PATH = Path(tempfile.gettempdir()) / "sentinel_test_security_audit.db"

def setup_function():
    if TEST_DB_PATH.exists():
        try:
            TEST_DB_PATH.unlink()
        except Exception:
            pass

def teardown_function():
    if TEST_DB_PATH.exists():
        try:
            TEST_DB_PATH.unlink()
        except Exception:
            pass

def test_audit_db_persistence_and_deduplication():
    # Ensure test operates on isolated test database
    if TEST_DB_PATH.exists():
        TEST_DB_PATH.unlink()

    initial_alerts = get_security_alerts(db_path=TEST_DB_PATH)
    assert len(initial_alerts) == 0

    # 1. Insert alert
    log_security_alert("2026-08-24 14:00:00", "test_proc.exe", -0.75, 50.0, 60.0, 30.0, "Flagged", db_path=TEST_DB_PATH)
    
    alerts = get_security_alerts(db_path=TEST_DB_PATH)
    assert len(alerts) == 1
    assert alerts[0]["process"] == "test_proc.exe"
    assert alerts[0]["score"] == -0.75

    # 2. Duplicate insertion attempt (same timestamp + process + action)
    log_security_alert("2026-08-24 14:00:00", "test_proc.exe", -0.75, 50.0, 60.0, 30.0, "Flagged", db_path=TEST_DB_PATH)
    alerts_after_dup = get_security_alerts(db_path=TEST_DB_PATH)
    assert len(alerts_after_dup) == 1  # Must not duplicate!

    # 3. Append second unique alert with potential None/float edge case
    log_security_alert("2026-08-24 14:00:05", "another_proc.exe", None, 80.0, None, 40.0, "Auto-Killed", db_path=TEST_DB_PATH)
    alerts_after_second = get_security_alerts(db_path=TEST_DB_PATH)
    assert len(alerts_after_second) == 2
    assert alerts_after_second[0]["process"] == "another_proc.exe" # Newest first
    assert alerts_after_second[0]["score"] == 0.0  # None safely defaulted to 0.0

    # 4. Clear alerts
    clear_security_alerts(db_path=TEST_DB_PATH)
    assert len(get_security_alerts(db_path=TEST_DB_PATH)) == 0

def test_model_event_logging():
    log_model_event("2026-08-24 15:00:00", "MODEL_RETRAIN_COMPLETED", "V_TEST", 15284, "Retrained successfully.", db_path=TEST_DB_PATH)
    events = get_model_events(db_path=TEST_DB_PATH)
    assert len(events) >= 1
    found = any(e["model_version"] == "V_TEST" and e["training_samples"] == 15284 for e in events)
    assert found
