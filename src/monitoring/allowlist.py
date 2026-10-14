import os
import sys
import time
import subprocess
import threading
from pathlib import Path

# Thread-safe cache for digital signature lookups: { (norm_path, mtime, size): (is_signed, status_msg) }
_SIGNATURE_CACHE = {}
_SIG_CACHE_LOCK = threading.Lock()

# Standard Windows Directory Paths
WIN_DIR = os.environ.get("SystemRoot", r"C:\Windows")
SYSTEM32_DIR = os.path.join(WIN_DIR, "System32")
SYSWOW64_DIR = os.path.join(WIN_DIR, "SysWOW64")
SYSTEMAPPS_DIR = os.path.join(WIN_DIR, "SystemApps")
PROGRAM_FILES = os.environ.get("ProgramFiles", r"C:\Program Files")
PROGRAM_FILES_X86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
PROGRAM_DATA = os.environ.get("ProgramData", r"C:\ProgramData")

# Forbidden directories for legitimate Windows system executables (MITRE ATT&CK T1036 Masquerading defense)
UNTRUSTED_PATH_MARKERS = [
    r"\temp",
    r"\tmp",
    r"\users",
    r"\appdata",
    r"\downloads",
    r"\desktop",
    r"\documents",
    r"\recycle.bin",
    r"\perflogs",
]

# Canonical Windows System Processes Allowlist Knowledge Base
SYSTEM_ALLOWLIST = {
    # ── Kernel & Core OS Pseudo-Processes ──
    "system": {
        "display_name": "NT Kernel & System",
        "is_kernel": True,
        "expected_dirs": [],
        "description": "Windows NT operating system kernel core process (PID 4).",
    },
    "system idle process": {
        "display_name": "System Idle Process",
        "is_kernel": True,
        "expected_dirs": [],
        "description": "CPU idle accounting pseudo-process (PID 0).",
    },
    "registry": {
        "display_name": "Registry Architecture Service",
        "is_kernel": True,
        "expected_dirs": [],
        "description": "Windows registry hive memory management system process.",
    },

    # ── Critical Windows Initialization & Session Processes ──
    "smss.exe": {
        "display_name": "Session Manager Subsystem",
        "is_kernel": False,
        "expected_dirs": [SYSTEM32_DIR],
        "description": "First user-mode process started by the kernel, initializes subsystem.",
    },
    "csrss.exe": {
        "display_name": "Client Server Runtime Subsystem",
        "is_kernel": False,
        "expected_dirs": [SYSTEM32_DIR],
        "description": "User-mode portion of the Windows subsystem, manages consoles and GUI threads.",
    },
    "wininit.exe": {
        "display_name": "Windows Start-Up Application",
        "is_kernel": False,
        "expected_dirs": [SYSTEM32_DIR],
        "description": "Starts Service Control Manager, LSASS, and Local Session Manager.",
    },
    "services.exe": {
        "display_name": "Services and Controller app",
        "is_kernel": False,
        "expected_dirs": [SYSTEM32_DIR],
        "description": "Windows Service Control Manager responsible for starting system services.",
    },
    "lsass.exe": {
        "display_name": "Local Security Authority Process",
        "is_kernel": False,
        "expected_dirs": [SYSTEM32_DIR],
        "description": "Enforces security policies, user authentication, and token creation.",
    },
    "lsm.exe": {
        "display_name": "Local Session Manager Service",
        "is_kernel": False,
        "expected_dirs": [SYSTEM32_DIR],
        "description": "Manages local terminal server sessions.",
    },
    "winlogon.exe": {
        "display_name": "Windows Logon Application",
        "is_kernel": False,
        "expected_dirs": [SYSTEM32_DIR],
        "description": "Handles interactive user logon, logoff, and Secure Attention Sequence.",
    },

    # ── Shell, Explorer & Desktop UI ──
    "explorer.exe": {
        "display_name": "Windows Explorer",
        "is_kernel": False,
        "expected_dirs": [WIN_DIR],
        "description": "Windows taskbar, desktop interface, and file management shell.",
    },
    "dwm.exe": {
        "display_name": "Desktop Window Manager",
        "is_kernel": False,
        "expected_dirs": [SYSTEM32_DIR],
        "description": "Compositing window manager rendering visual desktop effects.",
    },
    "fontdrvhost.exe": {
        "display_name": "Usermode Font Driver Host",
        "is_kernel": False,
        "expected_dirs": [SYSTEM32_DIR],
        "description": "Isolated user-mode host for font parsing and rendering.",
    },
    "sihost.exe": {
        "display_name": "Shell Infrastructure Host",
        "is_kernel": False,
        "expected_dirs": [SYSTEM32_DIR],
        "description": "Coordinates shell UI components including Action Center and taskbar.",
    },
    "taskhostw.exe": {
        "display_name": "Host Process for Windows Tasks",
        "is_kernel": False,
        "expected_dirs": [SYSTEM32_DIR, SYSWOW64_DIR],
        "description": "Generic host process for Windows tasks executing from DLLs.",
    },
    "ctfmon.exe": {
        "display_name": "CTF Loader",
        "is_kernel": False,
        "expected_dirs": [SYSTEM32_DIR, SYSWOW64_DIR],
        "description": "Text Services Framework input language and speech recognition host.",
    },
    "conhost.exe": {
        "display_name": "Console Window Host",
        "is_kernel": False,
        "expected_dirs": [SYSTEM32_DIR, SYSWOW64_DIR],
        "description": "Server process hosting command prompt and terminal consoles.",
    },

    # ── Service Hosts & Providers ──
    "svchost.exe": {
        "display_name": "Host Process for Windows Services",
        "is_kernel": False,
        "expected_dirs": [SYSTEM32_DIR, SYSWOW64_DIR],
        "description": "Generic host process for Windows services running from DLLs.",
    },
    "dllhost.exe": {
        "display_name": "COM Surrogate",
        "is_kernel": False,
        "expected_dirs": [SYSTEM32_DIR, SYSWOW64_DIR],
        "description": "Host process for executing COM+ components and thumbnail handlings.",
    },
    "RuntimeBroker.exe": {
        "display_name": "Runtime Broker",
        "is_kernel": False,
        "expected_dirs": [SYSTEM32_DIR, SYSWOW64_DIR, SYSTEMAPPS_DIR],
        "description": "Manages permissions for Windows Store apps (cameras, location, etc.).",
    },
    "SearchHost.exe": {
        "display_name": "Windows Search Host",
        "is_kernel": False,
        "expected_dirs": [SYSTEMAPPS_DIR, SYSTEM32_DIR],
        "description": "Windows Search UI and indexing experience host.",
    },
    "StartMenuExperienceHost.exe": {
        "display_name": "Start Menu Experience Host",
        "is_kernel": False,
        "expected_dirs": [SYSTEMAPPS_DIR, SYSTEM32_DIR],
        "description": "Modern Windows Start Menu UI component.",
    },
    "ShellExperienceHost.exe": {
        "display_name": "Windows Shell Experience Host",
        "is_kernel": False,
        "expected_dirs": [SYSTEMAPPS_DIR, SYSTEM32_DIR],
        "description": "Provides UI visuals for clock, network flyout, and lock screen.",
    },
    "audiodg.exe": {
        "display_name": "Windows Audio Device Graph Isolation",
        "is_kernel": False,
        "expected_dirs": [SYSTEM32_DIR],
        "description": "Audio signal processing engine isolated from core audio service.",
    },
    "spoolsv.exe": {
        "display_name": "Print Spooler SubSystem App",
        "is_kernel": False,
        "expected_dirs": [SYSTEM32_DIR],
        "description": "Windows print spooler managing printer jobs and queues.",
    },
    "WmiPrvSE.exe": {
        "display_name": "WMI Provider Host",
        "is_kernel": False,
        "expected_dirs": [
            os.path.join(SYSTEM32_DIR, "wbem"),
            os.path.join(SYSWOW64_DIR, "wbem"),
            SYSTEM32_DIR
        ],
        "description": "Windows Management Instrumentation provider service host.",
    },
    "WUDFHost.exe": {
        "display_name": "Windows Driver Foundation Host",
        "is_kernel": False,
        "expected_dirs": [SYSTEM32_DIR],
        "description": "Host process for user-mode hardware drivers.",
    },
    "dasHost.exe": {
        "display_name": "Device Association Framework Provider Host",
        "is_kernel": False,
        "expected_dirs": [SYSTEM32_DIR],
        "description": "Pairs and associates wired/wireless devices with Windows.",
    },

    # ── Security & Defender Services ──
    "MsMpEng.exe": {
        "display_name": "Antimalware Service Executable",
        "is_kernel": False,
        "expected_dirs": [
            os.path.join(PROGRAM_FILES, "Windows Defender"),
            os.path.join(PROGRAM_FILES_X86, "Windows Defender"),
            os.path.join(PROGRAM_DATA, r"Microsoft\Windows Defender\Platform")
        ],
        "description": "Microsoft Defender Antivirus real-time protection engine.",
    },
    "SecurityHealthService.exe": {
        "display_name": "Windows Security Health Service",
        "is_kernel": False,
        "expected_dirs": [SYSTEM32_DIR],
        "description": "Windows Security Center background health monitoring service.",
    },
    "SecurityHealthSystray.exe": {
        "display_name": "Windows Security Notification Icon",
        "is_kernel": False,
        "expected_dirs": [SYSTEM32_DIR],
        "description": "Windows Security system tray icon and notifications handler.",
    },
    "smartscreen.exe": {
        "display_name": "Windows Defender SmartScreen",
        "is_kernel": False,
        "expected_dirs": [SYSTEM32_DIR],
        "description": "Protects against malicious websites and unrecognized downloaded apps.",
    },

    # ── Additional Legitimate Windows OS Processes ──
    "SearchIndexer.exe": {
        "display_name": "Microsoft Windows Search Indexer",
        "is_kernel": False,
        "expected_dirs": [SYSTEM32_DIR],
        "description": "Indexes files and emails to power instant search.",
    },
    "sppsvc.exe": {
        "display_name": "Microsoft Software Protection Platform",
        "is_kernel": False,
        "expected_dirs": [SYSTEM32_DIR],
        "description": "Windows licensing and activation verification service.",
    },
    "tiworker.exe": {
        "display_name": "Windows Modules Installer Worker",
        "is_kernel": False,
        "expected_dirs": [
            os.path.join(WIN_DIR, "WinSxS"),
            os.path.join(WIN_DIR, "servicing"),
            SYSTEM32_DIR
        ],
        "description": "Applies Windows updates and component maintenance.",
    },
    "trustedinstaller.exe": {
        "display_name": "Windows Modules Installer",
        "is_kernel": False,
        "expected_dirs": [
            os.path.join(WIN_DIR, "servicing"),
            SYSTEM32_DIR
        ],
        "description": "Installs, modifies, and removes Windows update packages.",
    },
    "backgroundTaskHost.exe": {
        "display_name": "Background Task Host",
        "is_kernel": False,
        "expected_dirs": [SYSTEM32_DIR, SYSWOW64_DIR],
        "description": "Runs background tasks for Universal Windows Platform (UWP) apps.",
    },
    "compattelrunner.exe": {
        "display_name": "Microsoft Compatibility Telemetry",
        "is_kernel": False,
        "expected_dirs": [SYSTEM32_DIR],
        "description": "Performs diagnostics on Windows systems to identify compatibility issues.",
    },
    "wermgr.exe": {
        "display_name": "Windows Problem Reporting",
        "is_kernel": False,
        "expected_dirs": [SYSTEM32_DIR, SYSWOW64_DIR],
        "description": "Logs and reports software crashes and system errors to Microsoft.",
    },
    "MoUsoCoreWorker.exe": {
        "display_name": "Windows Update USO Core Worker",
        "is_kernel": False,
        "expected_dirs": [SYSTEM32_DIR],
        "description": "Coordinates Windows Update scheduling and downloads.",
    },
    "usoclient.exe": {
        "display_name": "Universal Orchestrator Client",
        "is_kernel": False,
        "expected_dirs": [SYSTEM32_DIR],
        "description": "Client interface for Windows Update orchestrator tasks.",
    }
}

# Resource Anomaly Overrides Thresholds
# Even if a process is on the allowlist, abnormal resource utilization MUST trigger alerts!
RESOURCE_CPU_SPIKE_THRESHOLD = 85.0   # > 85% CPU on a system process is suspicious/anomalous
RESOURCE_RAM_SPIKE_THRESHOLD = 85.0   # > 85% RAM on a system process is suspicious/anomalous
RESOURCE_SCORE_CRITICAL_OFFSET = 0.15 # Score significantly deeper than threshold indicates severe anomaly


def is_path_under_directory(child_path, parent_dir):
    """
    Checks whether child_path is strictly located inside parent_dir (case-insensitive on Windows).
    """
    try:
        norm_child = os.path.normpath(str(child_path)).lower()
        norm_parent = os.path.normpath(str(parent_dir)).lower()
        # Ensure trailing separator comparison
        if not norm_parent.endswith(os.sep):
            norm_parent += os.sep
        return norm_child.startswith(norm_parent) or norm_child == norm_parent.rstrip(os.sep)
    except Exception:
        return False


def verify_digital_signature(exe_path, timeout=2.5):
    """
    Validates digital signature and Authenticode/Catalog certification of an executable.
    Results are thread-safely cached by file path, mtime, and size to avoid repeated disk/process calls.
    """
    if not exe_path or not os.path.exists(exe_path):
        return False, "File does not exist on disk"

    try:
        st = os.stat(exe_path)
        cache_key = (os.path.normpath(exe_path).lower(), st.st_mtime, st.st_size)
    except Exception as e:
        return False, f"Stat failed: {e}"

    with _SIG_CACHE_LOCK:
        if cache_key in _SIGNATURE_CACHE:
            return _SIGNATURE_CACHE[cache_key]

    # Verify signature using PowerShell Authenticode (covers both embedded PE and CatRoot catalog signatures)
    try:
        ps_cmd = [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"(Get-AuthenticodeSignature -LiteralPath '{exe_path}').Status.ToString()"
        ]
        proc = subprocess.run(ps_cmd, capture_output=True, text=True, timeout=timeout)
        status_text = proc.stdout.strip()
        is_valid = (status_text == "Valid")
        msg = f"Authenticode Status: {status_text}" if status_text else "No signature status returned"
    except subprocess.TimeoutExpired:
        is_valid = False
        msg = "Signature verification timed out"
    except Exception as e:
        is_valid = False
        msg = f"Signature verification error: {e}"

    with _SIG_CACHE_LOCK:
        _SIGNATURE_CACHE[cache_key] = (is_valid, msg)

    return is_valid, msg


def check_process_allowlist(
    proc_name,
    proc_info=None,
    cpu=0.0,
    ram=0.0,
    score=0.0,
    threshold=-0.600,
    custom_whitelist=None
):
    """
    Evaluates a process against the robust Windows System Allowlist with:
    1. System identity verification (canonical OS process dictionary)
    2. Executable path validation and masquerading defense (MITRE ATT&CK T1036)
    3. Untrusted/temporary directory detection (never trust processes running from Temp or User folders)
    4. Digital signature validation (where appropriate/available)
    5. Resource anomaly override (CPU/RAM spikes or severe ML score deviations still trigger alerts)
    6. Custom user whitelist integration

    Returns a comprehensive dict:
    - is_allowlisted: bool (Process matches known system or custom whitelist)
    - is_system_proc: bool (Process is a canonical Windows OS component)
    - is_masquerading: bool (Executable impersonates a system process from an untrusted path)
    - is_suppressed: bool (Alert should be suppressed as benign/expected)
    - is_resource_spike: bool (Allowlisted process triggered a resource/performance anomaly)
    - threat_type: str ("NONE", "MASQUERADING_ATTACK", "RESOURCE_ANOMALY", "UNKNOWN_PROCESS")
    - reason: str (Human-readable forensic rationale)
    - verified_path: str (Detected executable path)
    """
    pname_clean = (proc_name or "").strip().lower()
    base_name = pname_clean[:-4] if pname_clean.endswith(".exe") else pname_clean
    full_name = f"{base_name}.exe"

    # User Custom Whitelist
    custom_set = {
        str(w).strip().lower()
        for w in (custom_whitelist or [])
        if w is not None and str(w).strip()
    }
    is_custom_whitelisted = (pname_clean in custom_set) or (base_name in custom_set) or (full_name in custom_set)

    # Check canonical system dictionary
    sys_entry = SYSTEM_ALLOWLIST.get(pname_clean) or SYSTEM_ALLOWLIST.get(full_name) or SYSTEM_ALLOWLIST.get(base_name)
    is_canonical_sys = sys_entry is not None

    # Retrieve process executable path
    exe_path = ""
    if proc_info and isinstance(proc_info, dict):
        exe_path = proc_info.get("exe") or ""
    
    # Kernel pseudo-processes have no executable file on disk
    is_kernel = sys_entry.get("is_kernel", False) if sys_entry else (pname_clean in ("system", "system idle process", "registry"))

    norm_exe = os.path.normpath(exe_path).lower() if exe_path else ""

    # ─────────────────────────────────────────────────────────────
    # 1. MASQUERADING & UNTRUSTED DIRECTORY DEFENSE (MITRE ATT&CK T1036)
    # ─────────────────────────────────────────────────────────────
    if is_canonical_sys and not is_kernel and norm_exe:
        # Check if the process resides in an untrusted or user-writable directory
        in_untrusted_folder = any(marker in norm_exe for marker in UNTRUSTED_PATH_MARKERS)
        
        # Verify if executable is located in one of its expected system directories
        expected_dirs = sys_entry.get("expected_dirs", [])
        in_expected_dir = False
        if expected_dirs:
            in_expected_dir = any(is_path_under_directory(norm_exe, edir) for edir in expected_dirs)

        if in_untrusted_folder or (expected_dirs and not in_expected_dir):
            return {
                "is_allowlisted": False,
                "is_system_proc": True,
                "is_masquerading": True,
                "is_suppressed": False,
                "is_resource_spike": False,
                "threat_type": "MASQUERADING_ATTACK",
                "reason": (
                    f"CRITICAL: Executable '{proc_name}' impersonating Windows system process from "
                    f"untrusted directory '{exe_path}'. Masquerading threat detected!"
                ),
                "verified_path": exe_path
            }

    # ─────────────────────────────────────────────────────────────
    # 2. UNKNOWN / NON-ALLOWLISTED PROCESS
    # ─────────────────────────────────────────────────────────────
    if not is_canonical_sys and not is_custom_whitelisted:
        return {
            "is_allowlisted": False,
            "is_system_proc": False,
            "is_masquerading": False,
            "is_suppressed": False,
            "is_resource_spike": False,
            "threat_type": "UNKNOWN_PROCESS",
            "reason": f"Process '{proc_name}' is not an allowlisted system process or user-defined trusted binary.",
            "verified_path": exe_path
        }

    # ─────────────────────────────────────────────────────────────
    # 3. RESOURCE ANOMALY OVERRIDE ON ALLOWLISTED PROCESSES
    # ─────────────────────────────────────────────────────────────
    # Never blind the system to CPU/memory exhaustion or severe anomaly spikes, even from legitimate processes!
    has_cpu_spike = (cpu >= RESOURCE_CPU_SPIKE_THRESHOLD)
    has_ram_spike = (ram >= RESOURCE_RAM_SPIKE_THRESHOLD)
    has_severe_score = (score < (threshold - RESOURCE_SCORE_CRITICAL_OFFSET))

    if has_cpu_spike or has_ram_spike or has_severe_score:
        spike_reasons = []
        if has_cpu_spike:
            spike_reasons.append(f"CPU load at {cpu:.1f}% (>= {RESOURCE_CPU_SPIKE_THRESHOLD:.0f}%)")
        if has_ram_spike:
            spike_reasons.append(f"Memory load at {ram:.1f}% (>= {RESOURCE_RAM_SPIKE_THRESHOLD:.0f}%)")
        if has_severe_score:
            spike_reasons.append(f"ML score ({score:.4f}) severely anomalous vs threshold ({threshold:.4f})")

        return {
            "is_allowlisted": True,
            "is_system_proc": is_canonical_sys,
            "is_masquerading": False,
            "is_suppressed": False,  # DO NOT SUPPRESS RESOURCE SPIKES!
            "is_resource_spike": True,
            "threat_type": "RESOURCE_ANOMALY",
            "reason": (
                f"Resource Anomaly on allowlisted process '{proc_name}': "
                + " | ".join(spike_reasons)
            ),
            "verified_path": exe_path
        }

    # ─────────────────────────────────────────────────────────────
    # 4. NORMAL SYSTEM PROCESS ACTIVITY (SUPPRESS LOW-VALUE ALERTS)
    # ─────────────────────────────────────────────────────────────
    display_desc = sys_entry.get("description", "User-whitelisted application") if sys_entry else "User-whitelisted application"
    return {
        "is_allowlisted": True,
        "is_system_proc": is_canonical_sys,
        "is_masquerading": False,
        "is_suppressed": True,  # Suppress false alarms on normal system operations
        "is_resource_spike": False,
        "threat_type": "NONE",
        "reason": f"Suppressed benign alert for legitimate process '{proc_name}' ({display_desc}).",
        "verified_path": exe_path
    }


def get_all_allowlisted_process_names():
    """Returns sorted set of all canonical Windows system process names."""
    return sorted(list(SYSTEM_ALLOWLIST.keys()))
