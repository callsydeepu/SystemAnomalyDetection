import psutil
import time
import csv
import os
import pandas as pd
from pathlib import Path
import warnings

warnings.filterwarnings("ignore")

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data"
DATA_FILE = DATA_DIR / "system_data.csv"

COLUMNS = ["timestamp", "cpu", "ram", "disk", "ram_used_gb", "ram_total_gb",
           "swap_percent", "sent_delta", "recv_delta", "proc", "top_process"]

from src.monitoring.process_monitor import get_proc_count, get_top_process

def get_system_disk_anchor():
    """Returns the primary drive anchor on Windows or '/' on Unix."""
    if os.name == "nt":
        return Path.cwd().anchor or "C:\\"
    return "/"

def check_and_fix_csv(file_path=DATA_FILE):
    """
    Returns True if CSV exists with exact 11 COLUMNS header.
    If the file exists but has an invalid header, backs it up and resets the header safely.
    """
    if not file_path.exists():
        return False
    try:
        if file_path.stat().st_size == 0:
            return False
        existing = pd.read_csv(file_path, nrows=1)
        if existing.columns.tolist() == COLUMNS:
            return True
        # If columns do not match, safely preserve old file and signal header recreation
        backup_corrupt = file_path.parent / f"system_data_badheader_{int(time.time())}.csv"
        file_path.rename(backup_corrupt)
        return False
    except Exception:
        return False

def collect_telemetry_sample(prev_net=None):
    """
    Collects a single 1-second telemetry sample from the OS.
    Returns (sample_dict, current_net_counters).
    """
    cpu = psutil.cpu_percent(interval=1)
    ts_str = time.strftime("%Y-%m-%d %H:%M:%S")
    vm = psutil.virtual_memory()
    ram = vm.percent
    ram_used_gb = round(vm.used / (1024 ** 3), 2)
    ram_total_gb = round(vm.total / (1024 ** 3), 2)
    
    sw = psutil.swap_memory()
    swap_percent = sw.percent
    
    try:
        disk = psutil.disk_usage(get_system_disk_anchor()).percent
    except Exception:
        disk = 0.0
    
    net = psutil.net_io_counters()
    if prev_net:
        sent_delta = max(0, net.bytes_sent - prev_net.bytes_sent)
        recv_delta = max(0, net.bytes_recv - prev_net.bytes_recv)
    else:
        sent_delta = 0
        recv_delta = 0
        
    proc_count = get_proc_count()
    top_app = get_top_process()
    
    sample = {
        "timestamp": ts_str,
        "cpu": cpu,
        "ram": ram,
        "disk": disk,
        "ram_used_gb": ram_used_gb,
        "ram_total_gb": ram_total_gb,
        "swap_percent": swap_percent,
        "sent_delta": sent_delta,
        "recv_delta": recv_delta,
        "proc": proc_count,
        "top_process": top_app
    }
    return sample, net
