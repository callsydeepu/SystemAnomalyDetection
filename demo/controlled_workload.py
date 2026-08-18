import sys
import time
import math
import multiprocessing
import os

def cpu_workload_worker(stop_time):
    """
    Computes CPU-intensive math operations (trigonometric & square root iterations)
    to generate a realistic, controlled CPU load without modifying disk/system state.
    """
    x = 0.0001
    while time.time() < stop_time:
        for _ in range(100_000):
            x = math.sin(x) + math.cos(x) + math.sqrt(abs(x) + 1.0)
            if x > 1000:
                x = 0.0001

def main():
    duration = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    num_workers = max(1, multiprocessing.cpu_count() - 1)
    
    print("=" * 60)
    print("  AI Sentinel — Controlled Demonstration Workload")
    print("=" * 60)
    print(f"  Process Name : controlled_workload.py")
    print(f"  Target Duration: {duration} seconds")
    print(f"  Worker Threads : {num_workers} CPU cores")
    print(f"  PID            : {os.getpid()}")
    print("=" * 60)
    print("  Generating safe, real-time CPU computational load...")
    print("  Press Ctrl+C at any time to halt early.\n")
    
    stop_time = time.time() + duration
    processes = []
    
    try:
        for _ in range(num_workers):
            p = multiprocessing.Process(target=cpu_workload_worker, args=(stop_time,))
            p.daemon = True
            p.start()
            processes.append(p)
            
        start_t = time.time()
        while time.time() < stop_time:
            elapsed = int(time.time() - start_t)
            remaining = duration - elapsed
            print(f"\r  [RUNNING] Elapsed: {elapsed:2d}s | Remaining: {remaining:2d}s | Active Cores: {num_workers}", end="", flush=True)
            time.sleep(1)
            
        print("\n\n[COMPLETE] Workload finished naturally. Releasing CPU resources...")
        
    except KeyboardInterrupt:
        print("\n\n[STOPPED] Demonstration workload halted by user.")
    finally:
        for p in processes:
            if p.is_alive():
                p.terminate()
        print("  All demo processes terminated cleanly. System returning to normal.\n")

if __name__ == "__main__":
    main()
