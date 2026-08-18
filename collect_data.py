import psutil
import time
import csv
import os
import pandas as pd

filename = "system_data.csv"
COLUMNS  = ["timestamp", "cpu", "ram", "disk", "ram_used_gb", "ram_total_gb",
            "swap_percent", "sent_delta", "recv_delta", "proc", "top_process"]
OWN_PID  = os.getpid()

_last_proc_cpu_state = {}
_last_sample_time = time.time()
NUM_CPUS = psutil.cpu_count() or 1

# ─────────────────────────────────────────────
# Top process — calculates CPU delta per process
# ─────────────────────────────────────────────
def get_top_process():
    global _last_proc_cpu_state, _last_sample_time
    now = time.time()
    elapsed = max(0.1, now - _last_sample_time)
    _last_sample_time = now
    
    current_state = {}
    results = []
    
    for p in psutil.process_iter(['pid', 'name']):
        try:
            pid = p.info['pid']
            name = p.info.get('name')
            if pid == OWN_PID or not name:
                continue
            
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


def get_proc_count():
    try:
        return len(list(psutil.process_iter(['pid'])))
    except Exception:
        return 0


def check_and_fix_csv():
    """
    Returns True if file exists with correct or compatible columns.
    Returns False if file doesn't exist (needs new header).
    """
    if not os.path.exists(filename):
        return False
    try:
        existing = pd.read_csv(filename, nrows=1)
        existing_cols = existing.columns.tolist()
        if existing_cols == COLUMNS:
            return True
        else:
            print(f"WARNING: CSV has {len(existing_cols)} columns, expected {len(COLUMNS)}.")
            print(f"  Existing : {existing_cols}")
            print(f"  Expected : {COLUMNS}")
            return False  # Trigger writing new header or column adaptation
    except Exception:
        return False


file_needs_header = not check_and_fix_csv()

with open(filename, "a", newline="") as f:
    writer = csv.writer(f)

    if file_needs_header:
        writer.writerow(COLUMNS)

    prev_net     = psutil.net_io_counters()
    ram_total_gb = round(psutil.virtual_memory().total / (1024 ** 3), 2)

    # Prime ALL process CPU counters once at startup
    for p in psutil.process_iter(['pid']):
        try:
            p.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    print("=" * 50)
    print("  AI Sentinel — Data Collector")
    print(f"  Own PID  : {OWN_PID}")
    print(f"  Total RAM: {ram_total_gb} GB")
    print(f"  Columns  : {len(COLUMNS)}")
    print("=" * 50)
    print(f"Writing to: {filename}")
    print("Press Ctrl+C to stop.\n")

    sample_count = 0
    while True:
        try:
            # cpu_percent(interval=1) blocks for 1 second and measures accurately.
            cpu = psutil.cpu_percent(interval=1)

            ts_str = time.strftime("%Y-%m-%d %H:%M:%S")
            vm          = psutil.virtual_memory()
            ram         = vm.percent
            ram_used_gb = round(vm.used / (1024 ** 3), 2)

            sw           = psutil.swap_memory()
            swap_percent = sw.percent

            disk = psutil.disk_usage('/').percent

            net        = psutil.net_io_counters()
            sent_delta = max(0, net.bytes_sent - prev_net.bytes_sent)
            recv_delta = max(0, net.bytes_recv - prev_net.bytes_recv)
            prev_net   = net

            proc_count = get_proc_count()
            top_app    = get_top_process()

            writer.writerow([
                ts_str, cpu, ram, disk,
                ram_used_gb, ram_total_gb, swap_percent,
                sent_delta, recv_delta,
                proc_count, top_app
            ])
            f.flush()

            sample_count += 1
            if sample_count % 10 == 0:
                print(f"[{sample_count:5d}] [{ts_str}] CPU:{cpu:5.1f}%  "
                      f"RAM:{ram:5.1f}% ({ram_used_gb:.1f}/{ram_total_gb:.1f}GB)  "
                      f"Swap:{swap_percent:.0f}%  Top:{top_app}")

        except KeyboardInterrupt:
            print(f"\nStopped after {sample_count} samples.")
            break
        except Exception as e:
            print(f"Error: {e}")