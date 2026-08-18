from src.monitoring.process_monitor import is_process_currently_running, get_proc_count, get_top_process

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
