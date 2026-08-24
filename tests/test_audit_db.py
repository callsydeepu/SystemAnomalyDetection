import pytest
import os
from pathlib import Path
from src.audit.audit_db import (
    log_security_alert,
    get_security_alerts,
    clear_security_alerts,
    log_autokill_event,
    get_autokill_events,
    clear_autokill_events,
    DB_PATH
)

def test_audit_db_persistence_and_deduplication():
    # Clear existing alerts
    clear_security_alerts()
    clear_autokill_events()
    
    initial_alerts = get_security_alerts()
    assert len(initial_alerts) == 0

    # 1. Insert alert
    log_security_alert("2026-08-24 14:00:00", "test_proc.exe", -0.75, 50.0, 60.0, 30.0, "Flagged")
    
    alerts = get_security_alerts()
    assert len(alerts) == 1
    assert alerts[0]["process"] == "test_proc.exe"
    assert alerts[0]["score"] == -0.75

    # 2. Duplicate insertion attempt (same timestamp + process + action)
    log_security_alert("2026-08-24 14:00:00", "test_proc.exe", -0.75, 50.0, 60.0, 30.0, "Flagged")
    alerts_after_dup = get_security_alerts()
    assert len(alerts_after_dup) == 1  # Must not duplicate!

    # 3. Append second unique alert
    log_security_alert("2026-08-24 14:00:05", "another_proc.exe", -0.80, 80.0, 90.0, 40.0, "Auto-Killed")
    alerts_after_second = get_security_alerts()
    assert len(alerts_after_second) == 2
    assert alerts_after_second[0]["process"] == "another_proc.exe" # Newest first

    # 4. Clear alerts
    clear_security_alerts()
    assert len(get_security_alerts()) == 0
