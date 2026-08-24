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

def get_top_process_details():
    """
    Calculates CPU time delta per process over the sampling interval,
    aggregates CPU usage across all process instances sharing the same process name
    (e.g., summing multi-threaded or multi-process PowerShell background jobs),
    and returns a tuple: (top_process_name, aggregated_proc_cpu_percent, process_cpu_map, ps_debug_info).
    """
    global _last_proc_cpu_state, _last_sample_time
    now = time.time()
    elapsed = max(0.1, now - _last_sample_time)
    _last_sample_time = now
    
    current_state = {}
    name_cpu_map = {}
    ps_procs = []
    
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
                    # System-scaled CPU percentage (100% = ALL logical cores fully loaded)
                    proc_cpu_system_scaled = (delta_time / elapsed / NUM_CPUS) * 100.0
                    
                    if name != "System Idle Process":
                        name_cpu_map[name] = name_cpu_map.get(name, 0.0) + proc_cpu_system_scaled
                        if "powershell" in name.lower() or "pwsh" in name.lower():
                            ps_procs.append({
                                "pid": pid,
                                "name": name,
                                "cpu_system_scaled": proc_cpu_system_scaled
                            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
            pass
            
    _last_proc_cpu_state = current_state
    
    if not name_cpu_map:
        return "System", 0.0, {}, {"ps_count": len(ps_procs), "ps_procs": ps_procs}
        
    sorted_procs = sorted(name_cpu_map.items(), key=lambda x: x[1], reverse=True)
    top_name, top_cpu = sorted_procs[0]
    
    if top_cpu > 0.1:
        return top_name, round(top_cpu, 1), name_cpu_map, {"ps_count": len(ps_procs), "ps_procs": ps_procs}
    return "System", 0.0, name_cpu_map, {"ps_count": len(ps_procs), "ps_procs": ps_procs}

def get_top_process():
    """Returns top process name (backwards compatible helper)."""
    top_name, _, _, _ = get_top_process_details()
    return top_name
