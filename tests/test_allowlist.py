import os
import sys
import tempfile
import sqlite3
import pandas as pd
import numpy as np
from unittest.mock import MagicMock
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.monitoring.allowlist import (
    SYSTEM_ALLOWLIST,
    check_process_allowlist,
    get_all_allowlisted_process_names,
    verify_digital_signature,
    RESOURCE_CPU_SPIKE_THRESHOLD,
    RESOURCE_RAM_SPIKE_THRESHOLD
)
from src.anomaly_detection.predictor import evaluate_latest_sample
from src.audit.audit_db import log_suppressed_alert, get_security_alerts, init_audit_db
from src.monitoring.process_monitor import kill_top_cpu_process, PROTECTED_PROCESSES
from src.monitoring.realtime_events import AnomalyEventBroker


def test_canonical_system_processes_defined():
    """Verify all 30+ requested Windows system processes are cataloged with metadata."""
    canonical_procs = get_all_allowlisted_process_names()
    
    # User requested explicit list
    required_procs = [
        "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
        "services.exe", "lsass.exe", "svchost.exe", "winlogon.exe",
        "explorer.exe", "dwm.exe", "fontdrvhost.exe", "sihost.exe",
        "taskhostw.exe", "runtimebroker.exe", "searchhost.exe",
        "startmenuexperiencehost.exe", "shellexperiencehost.exe",
        "audiodg.exe", "conhost.exe", "dllhost.exe", "spoolsv.exe",
        "wmiprvse.exe", "msmpeng.exe", "securityhealthservice.exe",
        "securityhealthsystray.exe", "ctfmon.exe", "wudfhost.exe",
        "dashost.exe", "lsm.exe"
    ]
    for p in required_procs:
        p_clean = p.lower()
        assert any(p_clean == name.lower() for name in canonical_procs), f"Missing requested process: {p}"

    # Also verify additional legitimate OS processes
    additional_os_procs = [
        "system idle process", "searchindexer.exe", "smartscreen.exe",
        "sppsvc.exe", "tiworker.exe", "trustedinstaller.exe",
        "backgroundtaskhost.exe", "compattelrunner.exe"
    ]
    for p in additional_os_procs:
        assert any(p == name.lower() for name in canonical_procs), f"Missing additional OS process: {p}"


def test_normal_activity_system_process_suppressed():
    """Test 1: Normal activity from recognized system processes does not create unnecessary alerts."""
    # Test svchost.exe in System32 with normal CPU (12%) and normal RAM (45%)
    proc_info = {
        "exe": r"C:\Windows\System32\svchost.exe",
        "pids": [1234, 5678],
        "cmdline": r"C:\Windows\system32\svchost.exe -k netsvcs",
        "memory_mb": 42.0
    }
    res = check_process_allowlist(
        proc_name="svchost.exe",
        proc_info=proc_info,
        cpu=12.0,
        ram=45.0,
        score=-0.620,
        threshold=-0.600
    )
    assert res["is_allowlisted"] == True
    assert res["is_system_proc"] == True
    assert res["is_suppressed"] == True
    assert res["is_masquerading"] == False
    assert res["is_resource_spike"] == False
    assert res["threat_type"] == "NONE"


def test_high_cpu_resource_anomaly_triggers_alert():
    """Test 2: High CPU or memory usage can still trigger resource anomaly alerts on allowlisted process."""
    # svchost.exe in legitimate path, but consuming 92.5% CPU
    proc_info = {
        "exe": r"C:\Windows\System32\svchost.exe",
        "pids": [1004],
        "cmdline": r"C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted",
        "memory_mb": 128.0
    }
    res = check_process_allowlist(
        proc_name="svchost.exe",
        proc_info=proc_info,
        cpu=92.5,
        ram=50.0,
        score=-0.710,
        threshold=-0.600
    )
    # The allowlist must NOT suppress this spike!
    assert res["is_allowlisted"] == True
    assert res["is_suppressed"] == False
    assert res["is_resource_spike"] == True
    assert res["threat_type"] == "RESOURCE_ANOMALY"
    assert "CPU load at 92.5%" in res["reason"]

    # Test high RAM spike (88.0% RAM)
    res_ram = check_process_allowlist(
        proc_name="explorer.exe",
        proc_info={"exe": r"C:\Windows\explorer.exe"},
        cpu=10.0,
        ram=88.0,
        score=-0.650,
        threshold=-0.600
    )
    assert res_ram["is_suppressed"] == False
    assert res_ram["is_resource_spike"] == True
    assert "Memory load at 88.0%" in res_ram["reason"]


def test_masquerading_untrusted_path_not_trusted():
    """Test 3: A suspicious executable impersonating a system process is not automatically trusted."""
    # Impersonator named 'svchost.exe' running from User Temp or AppData folder
    malicious_paths = [
        r"C:\Users\JohnDoe\AppData\Local\Temp\svchost.exe",
        r"C:\Users\Public\Downloads\lsass.exe",
        r"C:\Windows\Temp\explorer.exe",
        r"C:\PerfLogs\csrss.exe"
    ]
    for mpath in malicious_paths:
        pname = os.path.basename(mpath)
        proc_info = {
            "exe": mpath,
            "pids": [9999],
            "cmdline": f"{mpath} --stealth",
            "memory_mb": 15.0
        }
        res = check_process_allowlist(
            proc_name=pname,
            proc_info=proc_info,
            cpu=5.0,
            ram=10.0,
            score=-0.500,
            threshold=-0.600
        )
        assert res["is_allowlisted"] == False, f"Process at {mpath} should NOT be allowlisted"
        assert res["is_masquerading"] == True, f"Process at {mpath} should be flagged as masquerading"
        assert res["is_suppressed"] == False, f"Process at {mpath} must NEVER be suppressed"
        assert res["threat_type"] == "MASQUERADING_ATTACK"


def test_unknown_process_eligible_for_detection():
    """Test 4: Unknown processes remain eligible for standard anomaly detection."""
    proc_info = {
        "exe": r"C:\Program Files\SomeRandomTool\cryptominer.exe",
        "pids": [4444],
        "cmdline": "cryptominer.exe -o pool.mine.org",
        "memory_mb": 80.0
    }
    res = check_process_allowlist(
        proc_name="cryptominer.exe",
        proc_info=proc_info,
        cpu=20.0,
        ram=30.0,
        score=-0.750,
        threshold=-0.600
    )
    assert res["is_allowlisted"] == False
    assert res["is_system_proc"] == False
    assert res["is_masquerading"] == False
    assert res["is_suppressed"] == False
    assert res["threat_type"] == "UNKNOWN_PROCESS"


def test_predictor_integration_with_allowlist():
    """Test predictor integration under normal system load, resource spike, and masquerading."""
    dummy_model = MagicMock()
    dummy_scaler = MagicMock()
    dummy_scaler.transform = lambda x: x
    features = ["cpu", "ram", "disk", "proc"]

    # Scenario A: Legitimate svchost.exe normal activity -> Suppressed alert, SECURE state
    df_normal = pd.DataFrame([{
        "timestamp": "2026-08-18 10:00:00",
        "cpu": 15.0,
        "ram": 50.0,
        "disk": 20.0,
        "proc": 150,
        "top_process": "svchost.exe"
    }])
    dummy_model.score_samples = lambda x: np.array([-0.630])  # slightly below threshold, but legitimate
    eval_normal = evaluate_latest_sample(
        df_normal, dummy_model, dummy_scaler, features,
        threshold=-0.600,
        proc_info={"exe": r"C:\Windows\System32\svchost.exe"}
    )
    assert eval_normal["is_suppressed"] == True
    assert eval_normal["threat_confidence"] == 0.0
    assert eval_normal["system_state"] == "SECURE"

    # Scenario B: Legitimate svchost.exe with 94.0% CPU spike -> NOT suppressed, triggers alert
    df_spike = pd.DataFrame([{
        "timestamp": "2026-08-18 10:00:00",
        "cpu": 94.0,
        "ram": 50.0,
        "disk": 20.0,
        "proc": 150,
        "top_process": "svchost.exe"
    }])
    dummy_model.score_samples = lambda x: np.array([-0.680])
    eval_spike = evaluate_latest_sample(
        df_spike, dummy_model, dummy_scaler, features,
        threshold=-0.600,
        proc_info={"exe": r"C:\Windows\System32\svchost.exe"}
    )
    assert eval_spike["is_suppressed"] == False
    assert eval_spike["is_resource_spike"] == True
    assert eval_spike["threat_confidence"] >= 80.0
    assert eval_spike["sample_state"] in ("WARNING", "CRITICAL")

    # Scenario C: Masquerading svchost.exe in Temp directory -> CRITICAL threat
    df_masq = pd.DataFrame([{
        "timestamp": "2026-08-18 10:00:00",
        "cpu": 15.0,
        "ram": 50.0,
        "disk": 20.0,
        "proc": 150,
        "top_process": "svchost.exe"
    }])
    dummy_model.score_samples = lambda x: np.array([-0.500])
    eval_masq = evaluate_latest_sample(
        df_masq, dummy_model, dummy_scaler, features,
        threshold=-0.600,
        proc_info={"exe": r"C:\Users\Attacker\AppData\Local\Temp\svchost.exe"}
    )
    assert eval_masq["is_masquerading"] == True
    assert eval_masq["is_suppressed"] == False
    assert eval_masq["system_state"] == "CRITICAL"
    assert eval_masq["threat_confidence"] >= 95.0


def test_suppressed_alerts_logged_in_audit_db():
    """Test 5: Log suppressed alerts for auditing and debugging."""
    test_db = Path(tempfile.gettempdir()) / "sentinel_test_allowlist_audit.db"
    if test_db.exists():
        try:
            test_db.unlink()
        except Exception:
            pass

    try:
        init_audit_db(test_db, force=True)

        log_suppressed_alert(
            timestamp="2026-10-14 11:00:00",
            process="svchost.exe",
            score=-0.6150,
            cpu=14.2,
            ram=48.5,
            disk=22.0,
            reason="Recognized Windows System Process",
            db_path=test_db
        )

        alerts = get_security_alerts(db_path=test_db)
        assert len(alerts) == 1
        assert alerts[0]["process"] == "svchost.exe"
        assert "Suppressed" in alerts[0]["action"]
    finally:
        if test_db.exists():
            try:
                test_db.unlink()
            except Exception:
                pass


def test_realtime_broker_publishes_genuine_and_resource_anomalies():
    """Test 6: Real-time toast notifications continue working for genuine and resource anomalies."""
    broker = AnomalyEventBroker(cooldown_seconds=1.0)
    
    # 1. Genuine unknown anomaly
    evt1 = broker.publish_anomaly(
        culprit="unknown_trojan.exe",
        severity="CRITICAL",
        score=-0.750,
        threshold=-0.600,
        confidence=95.0,
        cpu=96.0,
        ram=40.0
    )
    assert evt1 is not None
    assert evt1["process"] == "unknown_trojan.exe"
    assert evt1["severity"] == "CRITICAL"

    # 2. Resource anomaly on allowlisted process
    evt2 = broker.publish_anomaly(
        culprit="svchost.exe",
        severity="CRITICAL",
        score=-0.710,
        threshold=-0.600,
        confidence=88.0,
        cpu=93.0,
        ram=55.0,
        anomaly_type="Allowlisted Process Resource Anomaly"
    )
    assert evt2 is not None
    assert evt2["process"] == "svchost.exe"
    assert evt2["type"] == "Allowlisted Process Resource Anomaly"


def test_protected_processes_termination_immunity():
    """Test 7: Critical Windows system processes cannot be terminated by mistake."""
    for proc_name in ["svchost.exe", "lsass.exe", "smss.exe", "csrss.exe", "services.exe", "dwm.exe"]:
        assert proc_name in PROTECTED_PROCESSES or proc_name.lower() in PROTECTED_PROCESSES
        success, msg = kill_top_cpu_process(proc_name)
        assert success == False
        assert "protected from termination" in msg.lower()
