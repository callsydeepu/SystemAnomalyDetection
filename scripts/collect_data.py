import psutil
import time
import csv
import sys
import pandas as pd
from pathlib import Path
import warnings

warnings.filterwarnings("ignore")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

DATA_DIR = PROJECT_ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)
filename = DATA_DIR / "system_data.csv"

COLUMNS = ["timestamp", "cpu", "ram", "disk", "ram_used_gb", "ram_total_gb",
           "swap_percent", "sent_delta", "recv_delta", "proc", "top_process"]
OWN_PID = psutil.Process().pid

from src.monitoring.process_monitor import get_proc_count, get_top_process, get_top_process_details
from src.monitoring.system_monitor import check_and_fix_csv, get_system_disk_anchor

def main():
    file_needs_header = not check_and_fix_csv(filename)
    num_cpus = psutil.cpu_count() or 1
    
    with open(filename, "a", newline="") as f:
        writer = csv.writer(f)
        if file_needs_header:
            writer.writerow(COLUMNS)
            f.flush()
            
        prev_net = psutil.net_io_counters()
        ram_total_gb = round(psutil.virtual_memory().total / (1024 ** 3), 2)
        
        # Prime process CPU counters
        for p in psutil.process_iter(['pid']):
            try:
                p.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        print("=" * 60)
        print("  AI Sentinel — Real-Time OS Anomaly Monitor")
        print("=" * 60)
        print(f"  Monitoring PID : {OWN_PID}")
        print(f"  CPU Cores      : {num_cpus}")
        print(f"  Total RAM      : {ram_total_gb} GB")
        print(f"  Telemetry File : {filename}")
        print("=" * 60)
        print("  Active OS Monitoring Started...")
        print("  Press Ctrl+C to stop.\n")

        sample_count = 0
        while True:
            try:
                cpu = psutil.cpu_percent(interval=1)
                ts_str = time.strftime("%Y-%m-%d %H:%M:%S")
                vm = psutil.virtual_memory()
                ram = vm.percent
                ram_used_gb = round(vm.used / (1024 ** 3), 2)

                sw = psutil.swap_memory()
                swap_percent = sw.percent
                try:
                    disk = psutil.disk_usage(get_system_disk_anchor()).percent
                except Exception:
                    disk = 0.0

                net = psutil.net_io_counters()
                sent_delta = max(0, net.bytes_sent - prev_net.bytes_sent)
                recv_delta = max(0, net.bytes_recv - prev_net.bytes_recv)
                prev_net = net

                proc_count = get_proc_count()
                top_app, top_cpu_val, proc_map, ps_debug = get_top_process_details()

                writer.writerow([
                    ts_str, cpu, ram, disk,
                    ram_used_gb, ram_total_gb, swap_percent,
                    sent_delta, recv_delta,
                    proc_count, top_app
                ])
                f.flush()

                sample_count += 1
                if sample_count % 5 == 0:
                    sorted_top5 = sorted(proc_map.items(), key=lambda x: x[1], reverse=True)[:5]
                    top5_str = ", ".join([f"{name}: {val:.1f}%" for name, val in sorted_top5])
                    print(f"[{sample_count:6d}] [{ts_str}] Total SysCPU:{cpu:5.1f}% (Cores:{num_cpus}) | RAM:{ram:5.1f}% ({ram_used_gb:.1f}/{ram_total_gb:.1f}GB) | Procs:{proc_count:3d} | Top App: {top_app} ({top_cpu_val:.1f}%) | PS Procs: {ps_debug['ps_count']} | Top 5: [{top5_str}]")

            except KeyboardInterrupt:
                print(f"\nStopped after {sample_count} samples.")
                break
            except Exception as e:
                print(f"Sampling error: {e}")
                time.sleep(1)

if __name__ == "__main__":
    main()
