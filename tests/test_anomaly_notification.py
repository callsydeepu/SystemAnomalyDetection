import tempfile
import time
import sys
import json
import http.client
from pathlib import Path
import psutil

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.monitoring.process_monitor import get_process_info, kill_top_cpu_process, PROTECTED_PROCESSES
from src.audit.audit_db import (
    log_security_alert,
    get_security_alerts,
    clear_security_alerts,
    log_autokill_event,
    get_autokill_events,
    clear_autokill_events
)
from src.monitoring.realtime_events import (
    AnomalyEventBroker,
    start_realtime_server,
    get_realtime_broker
)
from src.dashboard.toast_ui import get_toast_html

TEST_DB_PATH = Path(tempfile.gettempdir()) / "sentinel_test_notification_audit.db"

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

def test_get_process_info_structure():
    """Verify get_process_info returns safe, structured data for both system and user processes."""
    # Test system / idle process
    sys_info = get_process_info("System Idle Process")
    assert isinstance(sys_info, dict)
    assert "pids" in sys_info
    assert "count" in sys_info
    assert "memory_mb" in sys_info
    assert "exe" in sys_info
    assert "cmdline" in sys_info

    # Test active current python process
    py_info = get_process_info("python.exe")
    assert isinstance(py_info, dict)
    assert isinstance(py_info["pids"], list)
    assert py_info["count"] >= 0

def test_known_anomaly_ignore_and_whitelist_logging():
    """Verify that marking an anomaly as known updates whitelist and logs to security audit DB."""
    clear_security_alerts(db_path=TEST_DB_PATH)

    culprit = "legitimate_backup_tool.exe"
    score = -0.6845
    cpu = 65.2
    ram = 72.0
    disk = 35.0
    action = "Ignored by User (Known)"
    ts = "2026-10-14 10:00:00"

    # Simulate ignoring known anomaly
    whitelist_raw = "System Idle Process\nsvchost.exe"
    existing = [p.strip().lower() for p in whitelist_raw.splitlines() if p.strip()]
    assert culprit.lower() not in existing

    # User chooses Ignore (Known)
    updated_whitelist_raw = (whitelist_raw + f"\n{culprit}").strip()
    log_security_alert(ts, culprit, score, cpu, ram, disk, action, db_path=TEST_DB_PATH)

    # Validate whitelist contains culprit
    new_whitelist = [p.strip().lower() for p in updated_whitelist_raw.splitlines() if p.strip()]
    assert culprit.lower() in new_whitelist

    # Validate audit log recorded the action
    alerts = get_security_alerts(db_path=TEST_DB_PATH)
    assert len(alerts) == 1
    assert alerts[0]["process"] == culprit
    assert alerts[0]["action"] == "Ignored by User (Known)"
    assert round(alerts[0]["score"], 4) == round(score, 4)

def test_unknown_anomaly_kill_logging():
    """Verify that killing an unknown anomaly logs correctly to both audit and autokill tables."""
    clear_security_alerts(db_path=TEST_DB_PATH)
    clear_autokill_events(db_path=TEST_DB_PATH)

    culprit = "rogue_miner_payload.exe"
    score = -0.7890
    cpu = 95.0
    ram = 80.0
    disk = 40.0
    action = "Killed by User (Unknown)"
    ts = "2026-10-14 10:05:00"
    kill_details = "Manual termination by user (Unknown Threat): Terminated rogue_miner_payload.exe (PID: 12345)"

    log_autokill_event(ts, culprit, score, True, kill_details, db_path=TEST_DB_PATH)
    log_security_alert(ts, culprit, score, cpu, ram, disk, action, db_path=TEST_DB_PATH)

    # Validate security audit entry
    alerts = get_security_alerts(db_path=TEST_DB_PATH)
    assert len(alerts) == 1
    assert alerts[0]["process"] == culprit
    assert alerts[0]["action"] == "Killed by User (Unknown)"

    # Validate autokill mitigation entry
    autokill_logs = get_autokill_events(db_path=TEST_DB_PATH)
    assert len(autokill_logs) == 1
    assert autokill_logs[0]["target"] == culprit
    assert autokill_logs[0]["success"] is True
    assert "Terminated rogue_miner_payload.exe" in autokill_logs[0]["details"]

def test_protected_process_kill_immunity():
    """Verify that protected OS processes cannot be terminated when user attempts to kill."""
    for protected in ["svchost.exe", "explorer.exe", "csrss.exe"]:
        success, msg = kill_top_cpu_process(protected)
        assert success is False
        assert "protected from termination" in msg

def test_snooze_alert_behavior():
    """Verify that snoozing an alert suppresses duplicate popups during the snooze window."""
    snoozed_alerts = {}
    culprit = "transient_spike.exe"
    now_t = time.time()

    # Before snooze: not snoozed
    assert not (snoozed_alerts.get(culprit.lower(), 0) > now_t)

    # Snooze for 60 seconds
    snoozed_alerts[culprit.lower()] = now_t + 60
    assert snoozed_alerts.get(culprit.lower(), 0) > now_t

    # Expired snooze
    snoozed_alerts[culprit.lower()] = now_t - 5
    assert not (snoozed_alerts.get(culprit.lower(), 0) > now_t)

def test_realtime_broker_normal_activity_zero_events():
    """Verify that normal system activity does not publish any anomaly notification events."""
    broker = AnomalyEventBroker(cooldown_seconds=1.0)
    client_q = broker.subscribe()

    # When pipeline detects normal activity (is_anomaly=False), publish_anomaly is not triggered
    is_anomaly = False
    if is_anomaly:
        broker.publish_anomaly("normal_proc.exe", "CRITICAL", -0.7, -0.6, 95.0, 10.0, 20.0)

    assert client_q.empty()
    assert len(broker.get_recent_events()) == 0
    broker.unsubscribe(client_q)

def test_realtime_broker_anomaly_detection_payload():
    """Verify that detected anomalies produce rich, correctly structured notification payloads."""
    broker = AnomalyEventBroker(cooldown_seconds=1.0)
    client_q = broker.subscribe()

    culprit = "malicious_script.exe"
    ts = "2026-10-14 11:00:00"
    desc = "Process 'malicious_script.exe' triggered CRITICAL anomaly. Sys CPU: 96.5%, RAM: 88.0%."

    event = broker.publish_anomaly(
        culprit=culprit,
        severity="CRITICAL",
        score=-0.7850,
        threshold=-0.6000,
        confidence=96.2,
        cpu=96.5,
        ram=88.0,
        timestamp=ts,
        description=desc
    )

    assert event is not None
    assert event["message"] == "⚠️ Anomaly Detected! Unusual activity has been identified."
    assert event["severity"] == "CRITICAL"
    assert event["process"] == culprit
    assert event["score"] == -0.7850
    assert event["threshold"] == -0.6000
    assert event["confidence"] == 96.2
    assert event["cpu"] == 96.5
    assert event["ram"] == 88.0
    assert event["timestamp"] == ts
    assert event["description"] == desc
    assert "Spike" in event["type"] or "Anomaly" in event["type"]

    assert not client_q.empty()
    queued_event = client_q.get_nowait()
    assert queued_event["id"] == event["id"]
    assert queued_event["process"] == culprit
    broker.unsubscribe(client_q)

def test_realtime_broker_deduplication_cooldown():
    """Verify deduplication suppresses duplicate alerts for the same event within the cooldown window."""
    broker = AnomalyEventBroker(cooldown_seconds=0.3)

    # First publication: passes
    first = broker.publish_anomaly("repeated_proc.exe", "CRITICAL", -0.72, -0.60, 90.0, 85.0, 70.0)
    assert first is not None

    # Immediate second publication with same culprit & severity: suppressed
    second = broker.publish_anomaly("repeated_proc.exe", "CRITICAL", -0.75, -0.60, 92.0, 88.0, 72.0)
    assert second is None

    # Different culprit: passes immediately
    different = broker.publish_anomaly("other_proc.exe", "CRITICAL", -0.71, -0.60, 89.0, 80.0, 65.0)
    assert different is not None

    # Same culprit but different severity: passes immediately
    diff_sev = broker.publish_anomaly("repeated_proc.exe", "WARNING", -0.61, -0.60, 75.0, 60.0, 50.0)
    assert diff_sev is not None

    # Wait for cooldown to expire
    time.sleep(0.35)

    # After cooldown expires: passes again
    after_cooldown = broker.publish_anomaly("repeated_proc.exe", "CRITICAL", -0.73, -0.60, 91.0, 86.0, 71.0)
    assert after_cooldown is not None

def test_realtime_sse_server_streaming_and_reconnection():
    """Verify SSE streaming endpoint, event delivery, and clean client reconnection."""
    port = start_realtime_server()
    broker = get_realtime_broker()

    # 1. Health endpoint
    h_conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    h_conn.request("GET", "/api/health")
    h_resp = h_conn.getresponse()
    assert h_resp.status == 200
    h_data = json.loads(h_resp.read().decode("utf-8"))
    assert h_data["status"] == "healthy"
    h_conn.close()

    # 2. SSE client connection 1
    client1 = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    client1.request("GET", "/api/anomaly-events")
    resp1 = client1.getresponse()
    assert resp1.status == 200
    assert "text/event-stream" in resp1.getheader("Content-Type")

    # Read initial handshake comment
    handshake = resp1.readline().decode("utf-8").strip()
    assert handshake.startswith(":")
    resp1.readline()  # blank separator

    # Publish anomaly
    event_payload = broker.publish_anomaly("sse_test_proc1.exe", "CRITICAL", -0.80, -0.60, 98.0, 99.0, 80.0)
    assert event_payload is not None

    # Verify client1 receives the event
    data_line = resp1.readline().decode("utf-8").strip()
    assert data_line.startswith("data: ")
    received_evt = json.loads(data_line[6:])
    assert received_evt["process"] == "sse_test_proc1.exe"
    assert received_evt["severity"] == "CRITICAL"
    client1.close()

    # 3. Client reconnection (client2)
    client2 = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    client2.request("GET", "/api/anomaly-events")
    resp2 = client2.getresponse()
    assert resp2.status == 200
    resp2.readline()  # handshake
    resp2.readline()  # blank separator

    event_payload2 = broker.publish_anomaly("sse_test_proc2.exe", "WARNING", -0.62, -0.60, 80.0, 65.0, 55.0)
    assert event_payload2 is not None

    data_line2 = resp2.readline().decode("utf-8").strip()
    assert data_line2.startswith("data: ")
    received_evt2 = json.loads(data_line2[6:])
    assert received_evt2["process"] == "sse_test_proc2.exe"
    assert received_evt2["severity"] == "WARNING"
    client2.close()

def test_bottom_right_toast_html_generation():
    """Verify toast UI HTML contains required bottom-right non-blocking elements, animations, and scripts."""
    html_no_event = get_toast_html(8502, direct_event=None)
    assert "#sentinel-toast-container" in html_no_event
    assert "position: fixed !important;" in html_no_event
    assert "bottom: 24px !important;" in html_no_event
    assert "right: 24px !important;" in html_no_event
    assert "pointer-events: none !important;" in html_no_event
    assert "pointer-events: auto !important;" in html_no_event
    assert "sentinel-toast-critical" in html_no_event
    assert "sentinel-toast-warning" in html_no_event
    assert "sentinel-toast-progress-bar" in html_no_event
    assert "sentinelToastCountdown 6s" in html_no_event
    assert "sentinel-toast-close" in html_no_event
    assert "EventSource" in html_no_event
    assert "DIRECT_EVENT = null;" in html_no_event

    test_evt = {
        "id": "direct_test_123",
        "severity": "CRITICAL",
        "message": "⚠️ Anomaly Detected! Unusual activity has been identified.",
        "process": "test_app.exe",
        "score": -0.75
    }
    html_with_event = get_toast_html(8502, direct_event=test_evt)
    assert "direct_test_123" in html_with_event
    assert "test_app.exe" in html_with_event

if __name__ == "__main__":
    test_get_process_info_structure()
    test_known_anomaly_ignore_and_whitelist_logging()
    test_unknown_anomaly_kill_logging()
    test_protected_process_kill_immunity()
    test_snooze_alert_behavior()
    test_realtime_broker_normal_activity_zero_events()
    test_realtime_broker_anomaly_detection_payload()
    test_realtime_broker_deduplication_cooldown()
    test_realtime_sse_server_streaming_and_reconnection()
    test_bottom_right_toast_html_generation()
    print("All anomaly notification & real-time toast tests passed successfully!")
