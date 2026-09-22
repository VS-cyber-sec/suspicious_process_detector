#!/usr/bin/env python3
"""
Suspicious Process Detector
============================
Scans every running process on the host and flags any that look suspicious
based on three heuristics:

  1. High CPU usage      - CPU% above a configurable threshold (default 80%)
  2. Unusual process name - masquerading as a known system process from the
                             wrong location, matching known offensive-security
                             tool names, or looking like a randomly generated
                             filename
  3. Temp-directory execution - the binary (or its working directory) lives
                             inside a common temp/staging path such as
                             /tmp, C:\\Windows\\Temp, or %LOCALAPPDATA%\\Temp

Results are written to a timestamped, human-readable report (default:
suspicious_processes.txt). Processes can trigger more than one heuristic -
the more flags a process has, the higher up the report it appears.

Usage:
    python suspicious_process_detector.py
    python suspicious_process_detector.py --cpu-threshold 70 --output report.txt
    python suspicious_process_detector.py --interval 2

Author: Vaishnavi Chavan
"""

import argparse
import os
import platform
import re
import sys
import tempfile
import time
from datetime import datetime

try:
    import psutil
except ImportError:
    sys.exit("[!] psutil is required. Install it with: pip install psutil")


# ---------------------------------------------------------------------------
# Detection knowledge base
# ---------------------------------------------------------------------------

# Well-known system process names mapped to the directories they are
# legitimately expected to run from. Malware frequently reuses these exact
# names ("masquerading") but drops its binary somewhere else entirely -
# e.g. a "svchost.exe" running from C:\Users\Public is a major red flag.
KNOWN_SYSTEM_PROCESSES = {
    # Windows
    "svchost.exe": [r"c:\windows\system32", r"c:\windows\syswow64"],
    "csrss.exe": [r"c:\windows\system32"],
    "lsass.exe": [r"c:\windows\system32"],
    "winlogon.exe": [r"c:\windows\system32"],
    "explorer.exe": [r"c:\windows"],
    "services.exe": [r"c:\windows\system32"],
    "smss.exe": [r"c:\windows\system32"],
    "wininit.exe": [r"c:\windows\system32"],
    "spoolsv.exe": [r"c:\windows\system32"],
    "taskhostw.exe": [r"c:\windows\system32"],
    # Linux
    "systemd": ["/usr/lib/systemd", "/lib/systemd", "/sbin", "/usr/sbin"],
    "sshd": ["/usr/sbin", "/sbin"],
    "cron": ["/usr/sbin", "/sbin"],
    "init": ["/sbin", "/usr/sbin"],
}

# Names commonly associated with offensive-security / post-exploitation
# tooling. Seeing these running unexpectedly on an endpoint is worth
# investigating.
SUSPICIOUS_KEYWORDS = [
    "mimikatz", "psexec", "procdump", "pwdump", "netcat", "ncat",
    "meterpreter", "cobaltstrike", "beacon", "empire", "bloodhound",
    "sharphound", "rubeus", "lazagne", "hydra",
]

# Long, purely alphanumeric filenames (e.g. "a8f3c91e2b7740d1.exe") are a
# classic signature of auto-generated dropper/payload names.
GIBBERISH_RE = re.compile(r"^[a-z0-9]{16,}\.(exe|dll|bin|elf)?$", re.IGNORECASE)


def get_temp_dirs():
    """Build the set of directories treated as 'temp / staging' locations."""
    dirs = set()
    dirs.add(tempfile.gettempdir().lower())
    for var in ("TEMP", "TMP"):
        v = os.environ.get(var)
        if v:
            dirs.add(v.lower())
    dirs.update({"/tmp", "/var/tmp", "/dev/shm", r"c:\windows\temp"})
    local_appdata = os.environ.get("LOCALAPPDATA")
    if local_appdata:
        dirs.add(os.path.join(local_appdata, "Temp").lower())
    return {d for d in dirs if d}


TEMP_DIRS = get_temp_dirs()


# ---------------------------------------------------------------------------
# Heuristics
# ---------------------------------------------------------------------------

def check_high_cpu(info, threshold):
    """Flag processes above the CPU% threshold."""
    cpu = info.get("cpu_percent")
    if cpu is not None and cpu > threshold:
        return [f"High CPU usage: {cpu:.1f}% (threshold {threshold:.0f}%)"]
    return []


def check_unusual_name(info):
    """Flag processes with a masquerading, known-bad, or gibberish name."""
    reasons = []
    name = (info.get("name") or "").strip()
    exe = (info.get("exe") or "").strip()
    lname = name.lower()

    if not name:
        return ["Process has no readable name"]

    # Masquerading: name matches a known system process, but exe path doesn't
    if lname in KNOWN_SYSTEM_PROCESSES and exe:
        expected_dirs = KNOWN_SYSTEM_PROCESSES[lname]
        exe_lower = exe.lower()
        if not any(exe_lower.startswith(d) for d in expected_dirs):
            reasons.append(
                f"Name mimics system process '{name}' but runs from an "
                f"unexpected path ({exe})"
            )

    # Known offensive-security tool name
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in lname:
            reasons.append(f"Name matches known suspicious keyword '{kw}'")
            break

    # Randomly generated-looking filename
    if GIBBERISH_RE.match(name):
        reasons.append("Name looks auto-generated (long random-looking string)")

    return reasons


def check_temp_execution(info):
    """Flag processes running from, or working out of, a temp directory."""
    exe = (info.get("exe") or "").lower()
    cwd = (info.get("cwd") or "").lower()
    for d in TEMP_DIRS:
        if exe.startswith(d) or cwd.startswith(d):
            return [f"Running from a temp/staging directory ({d})"]
    return []


# ---------------------------------------------------------------------------
# Scan + report
# ---------------------------------------------------------------------------

def scan_processes(cpu_threshold=80.0, sample_interval=1.0):
    """Scan all processes and return (findings, total_scanned)."""
    procs = list(psutil.process_iter(
        attrs=["pid", "name", "exe", "cwd", "username"]
    ))

    # psutil needs two cpu_percent() calls spaced apart to give a meaningful
    # reading - the first call always returns 0.0. Prime it here, then sleep.
    for p in procs:
        try:
            p.cpu_percent(None)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    time.sleep(sample_interval)

    findings = []
    for p in procs:
        try:
            info = dict(p.info)
            info["cpu_percent"] = p.cpu_percent(None)
            info["pid"] = p.pid
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Process exited mid-scan, or we don't have permission to read it
            continue

        reasons = []
        reasons += check_high_cpu(info, cpu_threshold)
        reasons += check_unusual_name(info)
        reasons += check_temp_execution(info)

        if reasons:
            findings.append({
                "pid": info.get("pid"),
                "name": info.get("name") or "N/A",
                "exe": info.get("exe") or "N/A",
                "cwd": info.get("cwd") or "N/A",
                "username": info.get("username") or "N/A",
                "cpu_percent": info.get("cpu_percent"),
                "reasons": reasons,
            })

    # Most flags first = highest apparent risk first
    findings.sort(key=lambda f: len(f["reasons"]), reverse=True)
    return findings, len(procs)


def write_report(findings, total_scanned, output_path, cpu_threshold):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("SUSPICIOUS PROCESS DETECTOR - SCAN REPORT\n")
        f.write("=" * 70 + "\n")
        f.write(f"Scan time         : {now}\n")
        f.write(f"Host              : {platform.node()} "
                f"({platform.system()} {platform.release()})\n")
        f.write(f"CPU threshold     : {cpu_threshold:.0f}%\n")
        f.write(f"Processes scanned : {total_scanned}\n")
        f.write(f"Flagged processes : {len(findings)}\n")
        f.write("=" * 70 + "\n\n")

        if not findings:
            f.write("No suspicious processes detected.\n")
            return

        for i, entry in enumerate(findings, 1):
            cpu_str = f"{entry['cpu_percent']:.1f}" if entry["cpu_percent"] is not None else "N/A"
            f.write(f"[{i}] PID {entry['pid']} - {entry['name']}\n")
            f.write(f"    Path       : {entry['exe']}\n")
            f.write(f"    Working dir: {entry['cwd']}\n")
            f.write(f"    User       : {entry['username']}\n")
            f.write(f"    CPU%       : {cpu_str}\n")
            f.write(f"    Risk score : {len(entry['reasons'])} flag(s)\n")
            f.write("    Reasons:\n")
            for r in entry["reasons"]:
                f.write(f"      - {r}\n")
            f.write("-" * 70 + "\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Scan running processes for suspicious CPU usage, "
                     "unusual names, or temp-directory execution."
    )
    parser.add_argument(
        "--cpu-threshold", type=float, default=80.0,
        help="CPU percentage above which a process is flagged (default: 80.0)"
    )
    parser.add_argument(
        "--interval", type=float, default=1.0,
        help="Seconds to wait between the two CPU samples (default: 1.0)"
    )
    parser.add_argument(
        "--output", type=str, default="suspicious_processes.txt",
        help="Path to write the report to (default: suspicious_processes.txt)"
    )
    args = parser.parse_args()

    print(f"[*] Scanning running processes "
          f"(CPU threshold: {args.cpu_threshold:.0f}%, sampling {args.interval}s)...")

    findings, total = scan_processes(
        cpu_threshold=args.cpu_threshold, sample_interval=args.interval
    )
    write_report(findings, total, args.output, args.cpu_threshold)

    print(f"[+] Scanned {total} processes, flagged {len(findings)}.")
    print(f"[+] Report written to: {os.path.abspath(args.output)}")

    if findings:
        print("\nTop flagged processes:")
        for entry in findings[:5]:
            print(f"  PID {entry['pid']:<8} {entry['name']:<25} "
                  f"{len(entry['reasons'])} flag(s)")


if __name__ == "__main__":
    main()
