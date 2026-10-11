from src.monitoring.process_monitor import (
    is_process_currently_running,
    get_proc_count,
    get_top_process,
    kill_top_cpu_process,
    PROTECTED_PROCESSES
)
from src.monitoring.system_monitor import get_system_disk_anchor

def test_get_proc_count():
    count = get_proc_count()
    assert isinstance(count, int)
    assert count > 0

def test_get_top_process():
    top = get_top_process()
    assert isinstance(top, str)
    assert len(top) > 0

def test_is_process_currently_running():
    # System Idle Process should always be running
    assert is_process_currently_running("System Idle Process") == True
    # Non-existent process name
    assert is_process_currently_running("NonExistentFakeProcess_12345.exe") == False

def test_disk_anchor_and_os_process_immunity():
    anchor = get_system_disk_anchor()
    assert isinstance(anchor, str)
    assert len(anchor) > 0

    # Ensure critical OS processes are never terminable by automated response
    for proc in ["explorer.exe", "svchost.exe", "System Idle Process", "dwm.exe"]:
        success, msg = kill_top_cpu_process(proc)
        assert success == False
        assert "protected" in msg.lower() or "cannot" in msg.lower() or "critical" in msg.lower()
