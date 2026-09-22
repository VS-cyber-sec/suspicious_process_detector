# Suspicious Process Detector

A lightweight, cross-platform host-based detection script in Python. It scans
every running process and flags the ones that look suspicious using three
heuristics commonly used by SOC analysts and EDR tooling: abnormal CPU usage,
unusual process names, and execution from a temp/staging directory.

## Why this project

Endpoint compromise often shows up in small anomalies before it shows up in
alerts: a process pretending to be `svchost.exe` from the wrong folder, a
payload dropped in `%TEMP%`, or a miner quietly pegging a CPU core. This
script is a minimal, readable implementation of the kind of process-heuristic
logic that sits underneath real EDR/AV products and SIEM detection rules —
built as a hands-on exercise in process monitoring and heuristic detection.

## Detection logic

| Heuristic | What it checks | Why it matters |
|---|---|---|
| **High CPU usage** | Flags any process above a CPU% threshold (default `80%`) | Cryptominers, brute-forcers, and some C2 beacons/loops show up as CPU spikes |
| **Unusual name** | (a) Name matches a known Windows/Linux system process (`svchost.exe`, `lsass.exe`, `sshd`, etc.) but the binary is **not** running from its expected system directory — classic process masquerading. (b) Name contains a known offensive-security tool keyword (`mimikatz`, `psexec`, `cobaltstrike`, etc). (c) Name looks auto-generated — a long random alphanumeric string, typical of dropped payloads | Masquerading and generic-looking filenames are two of the most common ways malware tries to blend in |
| **Temp-directory execution** | Flags any process whose executable path or working directory sits inside a temp/staging location (`/tmp`, `/var/tmp`, `/dev/shm`, `C:\Windows\Temp`, `%LOCALAPPDATA%\Temp`, etc.) | Temp folders are the most common drop location for malware because they're world-writable and rarely monitored |

Each process can trigger more than one heuristic. The report is sorted so
that processes with the most flags (highest apparent risk) appear first,
giving a rough triage order.

## How CPU measurement works

`psutil`'s `cpu_percent()` needs two samples spaced apart to give a real
reading — the first call always returns `0.0`. The script primes a reading
for every process, sleeps for `--interval` seconds (default `1.0`), then
takes the real measurement. This mirrors how most monitoring tools sample
CPU over an interval rather than trusting an instantaneous value.

## Usage

```bash
pip install -r requirements.txt

# Basic scan — writes suspicious_processes.txt in the current directory
python suspicious_process_detector.py

# Custom CPU threshold and output path
python suspicious_process_detector.py --cpu-threshold 70 --output report.txt

# Longer sampling window for a more accurate CPU reading
python suspicious_process_detector.py --interval 2
```

**Note:** on Windows and Linux, some processes (especially system/root-owned
ones) may not expose their `exe` or `cwd` path without elevated privileges.
The script handles `AccessDenied` gracefully and simply skips what it can't
read rather than crashing.

### CLI options

| Flag | Default | Description |
|---|---|---|
| `--cpu-threshold` | `80.0` | CPU% above which a process is flagged |
| `--interval` | `1.0` | Seconds between the two CPU samples |
| `--output` | `suspicious_processes.txt` | Report output path |

## Sample report output

```
======================================================================
SUSPICIOUS PROCESS DETECTOR - SCAN REPORT
======================================================================
Scan time         : 2026-09-22 11:00:03
Host              : DESKTOP-VC01 (Windows 10)
CPU threshold     : 80%
Processes scanned : 187
Flagged processes : 1
======================================================================

[1] PID 4821 - svchost.exe
    Path       : C:\Users\Public\svchost.exe
    Working dir: C:\Users\Public
    User       : DESKTOP-VC01\vaish
    CPU%       : 91.4
    Risk score : 3 flag(s)
    Reasons:
      - High CPU usage: 91.4% (threshold 80%)
      - Name mimics system process 'svchost.exe' but runs from an unexpected path (C:\Users\Public\svchost.exe)
      - Running from a temp/staging directory (C:\Users\Public)
----------------------------------------------------------------------
```

## Limitations

- Heuristic, not signature-based — it's meant to surface anomalies for a
  human (or downstream tool) to triage, not to definitively confirm malware.
- A single CPU sample can be noisy; short-lived legitimate spikes (a build
  process, a video export) can trigger a false positive.
- The "known system process" table only covers a handful of common Windows
  and Linux process names — it's easy to extend with more entries.
- No persistence, network, or parent-process-chain analysis yet (see below).

## Possible extensions

- Add parent-process validation (e.g. `lsass.exe` should be spawned by
  `wininit.exe`, not by a random shell)
- Check for processes with no signed binary / no digital signature (Windows)
- Add a JSON/CSV output mode for feeding into a SIEM (e.g. Splunk, Wazuh)
- Add a `--watch` mode that re-scans on an interval and only reports new
  findings
- Whitelist file so known "unusual but legitimate" processes don't reappear
  in every report

## Tech stack

Python 3 · [psutil](https://github.com/giampaolo/psutil)

---
*Built as a hands-on process monitoring / heuristic detection exercise.*
