import psutil
import time
import os
import warnings

warnings.filterwarnings("ignore")

_last_proc_cpu_state = {}
_last_sample_time = time.time()
NUM_CPUS = psutil.cpu_count() or 1
OWN_PID = os.getpid()

def is_process_currently_running(process_name):
    """
    Checks whether a process is actively running on the host OS.
    Prevents terminated/historical processes from staying flagged as active anomalies.
    """
    if not process_name or process_name.lower() in ["system", "unknown", "system idle process"]:
        return True
    pname_clean = process_name.strip().lower()
    base_name = pname_clean[:-4] if pname_clean.endswith(".exe") else pname_clean
    for p in psutil.process_iter(['name', 'cmdline']):
        try:
            name = (p.info.get('name') or "").strip().lower()
            cmdline = " ".join(p.info.get('cmdline') or []).lower()
            if "controlled_workload" in pname_clean and "controlled_workload" in cmdline:
                return True
            if not name:
                continue
            proc_base = name[:-4] if name.endswith(".exe") else name
            if name == pname_clean or proc_base == base_name:
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return False

def get_proc_count():
    """Returns the current number of running processes."""
    try:
        return len(list(psutil.process_iter(['pid'])))
    except Exception:
        return 0

def get_top_process():
    """
    Calculates CPU time delta per process over the sampling interval
    to accurately identify the process using the most CPU.
    """
    global _last_proc_cpu_state, _last_sample_time
    now = time.time()
    elapsed = max(0.1, now - _last_sample_time)
    _last_sample_time = now
    
    current_state = {}
    results = []
    
    for p in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            pid = p.info['pid']
            name = p.info.get('name')
            if pid == OWN_PID or not name:
                continue
            
            cmdline = " ".join(p.info.get('cmdline') or [])
            if "controlled_workload" in cmdline.lower():
                name = "controlled_workload.py"
            
            cpu_t = p.cpu_times()
            total_time = cpu_t.user + cpu_t.system
            current_state[pid] = (name, total_time)
            
            if pid in _last_proc_cpu_state:
                prev_name, prev_time = _last_proc_cpu_state[pid]
                if prev_name == name:
                    delta_time = max(0.0, total_time - prev_time)
                    proc_cpu = round((delta_time / elapsed / NUM_CPUS) * 100.0, 1)
                    if name != "System Idle Process":
                        results.append((proc_cpu, name))
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
            pass
            
    _last_proc_cpu_state = current_state
    
    if not results:
        return "System"
        
    results.sort(key=lambda x: x[0], reverse=True)
    top_cpu, top_name = results[0]
    
    if top_cpu > 0.5:
        return top_name
    return "System"
