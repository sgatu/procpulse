# Ultra-Light Windows Process Telemetry & Load Diagnostics (`procpulse`)

An ultra-lightweight, continuous Windows process and system telemetry agent written in pure Rust. Engineered for 24/7 background production monitoring with **zero third-party runtime dependencies**, **~220 KB stripped binary size**, **~2 MB resident memory**, and **negligible CPU footprint** (sampling loop sleeps between intervals).

`procpulse` continuously samples targeted processes and the host machine, aggregates measurements over a configurable window (e.g. 60 seconds), and writes RFC 4180 compliant CSV records designed for seamless ingestion into Grafana Alloy, Prometheus, and Loki.

---

## Table of Contents

1. [Key Features](#key-features)
2. [Win32 Security & Permission Model](#win32-security--permission-model)
3. [Building & Testing](#building--testing)
   - 3.1. [Prerequisites](#prerequisites)
   - 3.2. [Using Cargo](#using-cargo)
   - 3.3. [Using Make](#using-make)
4. [Configuration](#configuration)
   - 4.1. [`procpulse.ini`](#procpulseini)
   - 4.2. [Command-Line Arguments](#command-line-arguments)
5. [CSV Output Schema](#csv-output-schema)
   - 5.1. [CPU Measurement Math & Diagnostics](#cpu-measurement-math--diagnostics)
     - 5.1.1. [Monotonic Timing & Skew Immunity](#monotonic-timing--skew-immunity)
     - 5.1.2. [Diagnosing Performance: Cycles vs. CPU Time](#diagnosing-performance-cycles-vs-cpu-time)
6. [Running as a Windows Service](#running-as-a-windows-service)
   - 6.1. [Option 1: NSSM (Recommended for Simplicity)](#option-1-nssm-recommended-for-simplicity)
   - 6.2. [Option 2: WinSW (Windows Service Wrapper - XML Config)](#option-2-winsw-windows-service-wrapper---xml-config)
   - 6.3. [Verifying Service Operation](#verifying-service-operation)
7. [Grafana & Alloy Telemetry Pipeline](#grafana--alloy-telemetry-pipeline)
8. [License](#license)

---

## Key Features

- **Pure Win32 Architecture**: Built exclusively with raw Windows APIs via `windows-sys`. Zero runtime frameworks, zero C runtime dependencies, zero dynamic allocations during sampling loops.
- **Flexible Process Targeting**:
  - Exact binary name matching (e.g. `MyApplication.exe`).
  - Wildcard pattern matching (`*` and `?`, e.g. `worker-*.exe`, `session_??.exe`).
  - Multiple simultaneous targets (comma or semicolon separated: `worker-*.exe, server.exe`).
  - Full path filtering (e.g. `C:\Apps\Service.exe`).
- **Robust Multi-Core CPU Calculation**:
  - Uses `GetProcessTimes` kernel and user deltas calculated against monotonic hardware timestamps (`std::time::Instant`).
  - Normalized against total machine logical core capacity (`0.0%` to `100.0%`), immune to system clock adjustments and delayed scheduler ticks.
- **Dual CPU Accounting & Diagnostics**:
  - **`app_cpu_cycles`**: Cumulative thread cycles executed on hardware via `QueryProcessCycleTime`.
  - **`app_cpu_time_ms`**: Raw scheduler CPU time charged across all threads via `GetProcessTimes`.
  - Enables deriving the diagnostic ratio:
    $$\text{Cycles / CPU Second} = \frac{\text{app CPU cycles}}{\text{app CPU time (ms)} / 1000}$$
    to distinguish real compute spikes from virtualization / scheduler interrupt quantum artifacts under machine load.
- **Comprehensive Memory Tracking**:
  - **Working Set RAM** (`WorkingSetSize`): Total resident memory.
  - **Private Committed Bytes** (`PagefileUsage`): Dedicated virtual memory allocation.
  - **Active Private RAM** (`PrivateWorkingSet` via `PROCESS_MEMORY_COUNTERS_EX2`): Resident physical private memory matching Task Manager's "Processes" tab Memory column.
- **Dynamic Process Lifecycle & Argument Isolation**:
  - Periodically scans for newly spawned or restarted instances.
  - Extracts and normalizes command-line arguments (`NtQueryInformationProcess`) to track distinct roles (e.g. `--server alpha` vs `--server beta`) under identical executable names.
  - Detects process exit mid-window and immediately flushes partial aggregated samples.
- **Graceful Shutdown**:
  - Traps `Ctrl+C` and service stop signals (`SetConsoleCtrlHandler`), flushing pending measurements to disk before exiting.
- **Privilege Escalation**:
  - Automatically attempts to enable `SeDebugPrivilege` upon startup to allow monitoring processes running under SYSTEM or other sessions when executed with Administrator rights.
- **Rolling CSV Rotation**:
  - Size-based rolling file rotation (defaults: **2 MB** per file, **5 backup files retained**).
  - Renames active file to `.1.csv`, shifting older backups up (`.1` $\to$ `.2` $\dots$ $\to$ `.N`), and re-creates active file with a clean CSV header.
  - Tailer-friendly architecture: releases write handle before rotation and works seamlessly with Grafana Alloy (`loki.source.file`) and Promtail on Windows without lock collisions or data loss.

---

## Win32 Security & Permission Model

`procpulse` is built under the principle of least privilege. It queries targeted workloads using non-invasive, read-only Windows telemetry APIs:

| Mechanism | Win32 API | Required Access Rights | Safety Guarantee & Notes |
|---|---|---|---|
| **Process Discovery** | `CreateToolhelp32Snapshot` | Standard user token | Enumerates process IDs and image names without opening process handles. |
| **Command-Line Retrieval** | `NtQueryInformationProcess` | `PROCESS_QUERY_LIMITED_INFORMATION` | Non-invasive query (`ProcessCommandLineInformation`). Does **not** require `PROCESS_VM_READ` or PEB dereferencing. Falls back cleanly to `[arguments_unavailable]` if access is restricted. |
| **Lifetime Detection** | `WaitForSingleObject(handle, 0)` | `SYNCHRONIZE` | Non-blocking instantaneous check (`WAIT_TIMEOUT` vs `WAIT_OBJECT_0`), avoiding exit-code 259 (`STILL_ACTIVE`) ambiguities. |
| **CPU Time Tracking** | `GetProcessTimes` | `PROCESS_QUERY_LIMITED_INFORMATION` | Cumulative user and kernel runtime `FILETIME` counters. |
| **CPU Cycle Tracking** | `QueryProcessCycleTime` | `PROCESS_QUERY_LIMITED_INFORMATION` | Hardware cycle counter queried via the existing process handle without additional handle allocations. |
| **Memory Tracking** | `K32GetProcessMemoryInfo` | `PROCESS_QUERY_LIMITED_INFORMATION` | Queries `PROCESS_MEMORY_COUNTERS_EX2` for resident Working Set, Private Bytes, and active Private Working Set. |
| **Host Machine Load** | `GetSystemTimes` & `GlobalMemoryStatusEx` | Standard user token | Whole-machine CPU idle/kernel/user times and physical RAM availability. |
| **Graceful Exit** | `SetConsoleCtrlHandler` | Standard user token | Captures console close, logoff, and shutdown events to flush pending records. |

> [!NOTE]
> All per-process monitoring operations require solely `PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE`—the lowest privilege level possible on Windows.
> `procpulse` requires **no kernel drivers**, **no DLL injection**, **no memory scraping (`PROCESS_VM_READ`)**, and **no invasive hooks**.

---

## Building & Testing

### Prerequisites
- [Rust toolchain](https://rustup.rs/) (edition 2024, stable 1.85+)
- Windows OS (Windows 10/11, Windows Server 2016+)

### Using Cargo

```cmd
# Build debug binary
cargo build

# Build optimized, stripped release binary (~220 KB)
cargo build --release --bin procpulse

# Run the complete test suite (unit + integration)
cargo test
```

### Using Make

A cross-platform `Makefile` is included in the project root:

```cmd
make help      # Show available targets
make build     # Build procpulse in debug mode
make release   # Build optimized release binary (target/release/procpulse.exe)
make test      # Run all unit and integration tests
make check     # Fast syntax and type checking without code generation
make clean     # Remove build artifacts (target/)
make run       # Run procpulse in debug mode
```
```

---

## Configuration

`procpulse` determines its configuration using the following precedence:
1. **Command-line arguments** (highest priority; overrides all settings).
2. **`procpulse.ini`** (automatically loaded if present in the same directory as `procpulse.exe`; `procmon.ini` supported as fallback).
3. **Internal defaults** (lowest priority).

### `procpulse.ini`

A template is provided as [`procpulse.ini.example`](file:///C:/Users/Bacon/RustroverProjects/procmon/procpulse.ini.example). To use it:
1. Copy or rename `procpulse.ini.example` to `procpulse.ini` (remove the `.example` extension).
2. Place `procpulse.ini` in the same directory as `procpulse.exe`.

```ini
# Target executable(s) or wildcard pattern(s) to monitor:
target = worker-*.exe, server.exe; "session_??.exe"

# Output CSV file destination path (default: procpulse_metrics.csv):
output = procpulse_metrics.csv

# Metric sampling interval in seconds (default: 2):
sample_interval_secs = 2

# Process discovery scan interval in seconds (default: 6):
discovery_interval_secs = 6

# Aggregation and CSV flush interval in seconds (default: 60):
aggregation_interval_secs = 60

# Maximum CSV size in bytes before rolling rotation (default: 2097152 [2 MB], 0 to disable):
max_bytes = 2097152

# Maximum number of rotated backup files to retain (default: 5):
max_files = 5
```

### Command-Line Arguments

All configuration options can be set or overridden via CLI:

```cmd
# Run with defaults, monitoring a specific target
procpulse.exe --target MyApplication.exe

# Monitor multiple targets with custom intervals and output file
procpulse.exe --target "worker-*.exe, server.exe" --output C:\logs\metrics.csv --sample-interval 2 --flush-interval 60

# Custom rotation policy: rotate at 5 MB (5242880 bytes) and keep 10 backups
procpulse.exe --target worker-*.exe --max-bytes 5242880 --max-files 10

# Disable rotation (unlimited CSV growth)
procpulse.exe --target server.exe --max-bytes 0

# Positional arguments are also supported: [TARGET] [OUTPUT_CSV]
procpulse.exe worker-*.exe C:\logs\metrics.csv
```

---

## CSV Output Schema

`procpulse` outputs an RFC 4180 compliant CSV row for each tracked process at every aggregation flush (default: every 60 seconds).

```csv
timestamp,executable,args,pid,app_cpu_avg,app_cpu_peak,app_cpu_cycles,app_cpu_time_ms,app_ram_mb_avg,app_ram_mb_peak,app_priv_ram_mb_avg,app_priv_ram_mb_peak,app_priv_active_mb_avg,app_priv_active_mb_peak,system_cpu_avg,system_cpu_peak,system_ram_mb_avg,system_ram_mb_peak,samples
```

| # | Column | Type | Units | Description |
|---|---|---|---|---|
| 1 | `timestamp` | String (ISO 8601) | UTC | Aggregation window flush timestamp (e.g. `2026-09-13T14:50:00Z`). |
| 2 | `executable` | String | – | Process image filename (e.g. `worker-alpha.exe`). |
| 3 | `args` | String | – | Normalized command-line arguments (e.g. `--server alpha --port 8001`). |
| 4 | `pid` | Integer (`u32`) | – | Windows Process ID. |
| 5 | `app_cpu_avg` | Float (`f64`) | % | Average application CPU usage normalized against total machine capacity (`0.0%` to `100.0%`). |
| 6 | `app_cpu_peak` | Float (`f64`) | % | Peak single-sample application CPU usage recorded during the window. |
| 7 | `app_cpu_cycles` | Integer (`u64`) | Cycles | Total raw hardware CPU cycles consumed across all threads (`QueryProcessCycleTime`). |
| 8 | `app_cpu_time_ms` | Integer (`u64`) | Milliseconds | Total raw process CPU time (kernel + user) charged across all threads (`GetProcessTimes`). |
| 9 | `app_ram_mb_avg` | Float (`f64`) | MB | Average resident Working Set memory (`WorkingSetSize`). |
| 10 | `app_ram_mb_peak` | Float (`f64`) | MB | Peak resident Working Set memory (`PeakWorkingSetSize`). |
| 11 | `app_priv_ram_mb_avg` | Float (`f64`) | MB | Average total private committed memory (`PagefileUsage` / Private Bytes). |
| 12 | `app_priv_ram_mb_peak` | Float (`f64`) | MB | Peak total private committed memory (`PeakPagefileUsage`). |
| 13 | `app_priv_active_mb_avg` | Float (`f64`) | MB | Average active private memory in physical RAM (`PrivateWorkingSet` / Task Manager "Memory"). |
| 14 | `app_priv_active_mb_peak` | Float (`f64`) | MB | Peak active private memory in physical RAM. |
| 15 | `system_cpu_avg` | Float (`f64`) | % | Average whole-machine system CPU load (`GetSystemTimes`). |
| 16 | `system_cpu_peak` | Float (`f64`) | % | Peak single-sample whole-machine system CPU load. |
| 17 | `system_ram_mb_avg` | Float (`f64`) | MB | Average system-wide physical RAM used (`GlobalMemoryStatusEx`). |
| 18 | `system_ram_mb_peak` | Float (`f64`) | MB | Peak system-wide physical RAM used. |
| 19 | `samples` | Integer (`u32`) | Count | Number of discrete sampling ticks accumulated in this flush window. |

### CPU Measurement Math & Diagnostics

#### Monotonic Timing & Skew Immunity
Many tools calculate per-process CPU usage simply as:
$$\text{Process CPU \%} = \frac{\Delta \text{Process Time}}{\Delta \text{System Total Time}} \times 100$$
Under heavy system load, the monitor thread can be preempted between the system and process queries. For lightweight processes (~0.05%–0.5% CPU), this timing divergence causes noticeable proportional skew.

To guarantee mathematical consistency, `procpulse` tracks each process using **per-process monotonic hardware timestamps** (`std::time::Instant`):
$$\text{App CPU Avg \%} = \frac{\Delta \text{Process CPU Time}}{\Delta \text{Elapsed Wall Time} \times \text{Logical Cores}} \times 100$$
This ensures process CPU metrics are strictly bounded and immune to scheduler preemption jitter, time dilation, and system clock adjustments.

#### Diagnosing Performance: Cycles vs. CPU Time
`procpulse` records both hardware CPU cycles (`app_cpu_cycles`) and scheduler CPU time (`app_cpu_time_ms`), enabling derivation of the **Cycles / CPU Sec** ratio:
$$\text{Cycles / CPU Second} = \frac{\text{app CPU cycles}}{\text{app CPU time (ms)} / 1000}$$
- **High CPU Time + High Cycles**: Genuine compute-bound activity (heavy computational loops, algorithm execution).
- **High CPU Time + Low Cycles**: Resource contention, hypervisor steal time (in virtual machines / cloud instances), lock contention (spin-lock starvation), or interrupt storms where scheduler time is billed without physical execution cycles.

---

## Running as a Windows Service

To run `procpulse` unattended in the background 24/7 and survive system reboots, use a service wrapper such as **NSSM** or **WinSW**. The wrapper supervises the binary and correctly routes Windows shutdown and stop signals (`CTRL_CLOSE_EVENT` / `CTRL_C_EVENT`) to allow `procpulse` to flush pending CSV data before terminating.

---

### Option 1: NSSM (Recommended for Simplicity)

**NSSM (Non-Sucking Service Manager)** is a lightweight, single-binary utility for running any executable as a service.

#### Step 1: Download NSSM
1. Download NSSM from [nssm.cc/download](https://nssm.cc/download).
2. Extract `nssm.exe` from the `win64/` directory and place it in a utility folder (e.g. `C:\Tools\nssm.exe`) or `C:\Windows\System32`.

#### Step 2: Prepare Application Directory
Create a dedicated deployment directory, for example `C:\Procpulse\`:
1. Copy `target\release\procpulse.exe` to `C:\Procpulse\procpulse.exe`.
2. Copy `procpulse.ini.example` to `C:\Procpulse\procpulse.ini` and configure your target executables and paths.

#### Step 3: Install the Service
Open an **Administrator PowerShell** or Command Prompt and execute:

```powershell
# 1. Install the service binary
nssm install ProcpulseService "C:\Procpulse\procpulse.exe"

# 2. Set the working directory (crucial for finding procpulse.ini)
nssm set ProcpulseService AppDirectory "C:\Procpulse"

# 3. (Optional) Provide CLI arguments if you want to override procpulse.ini
# nssm set ProcpulseService AppParameters "--target worker-*.exe --output C:\Procpulse\metrics.csv"

# 4. Configure graceful shutdown handling:
# Allows procpulse up to 1500ms to handle console/window close signals and flush pending samples to CSV
nssm set ProcpulseService AppStopMethodConsole 1500
nssm set ProcpulseService AppStopMethodWindow 1500
nssm set ProcpulseService AppStopMethodThreads 0
nssm set ProcpulseService AppThrottle 5000
```

#### Step 4: Manage the Service

```powershell
# Start the service
nssm start ProcpulseService

# Check service status
nssm status ProcpulseService

# Stop the service (triggers graceful CSV flush)
nssm stop ProcpulseService

# Restart the service
nssm restart ProcpulseService

# Uninstall / remove the service
nssm remove ProcpulseService confirm
```

---

### Option 2: WinSW (Windows Service Wrapper - XML Config)

**WinSW** is an open-source wrapper popular in enterprise IT environments because it is configured via a version-controlled XML file beside the executable.

#### Step 1: Download WinSW
1. Download `WinSW-x64.exe` from [GitHub Releases](https://github.com/winsw/winsw/releases).
2. Copy `WinSW-x64.exe` to `C:\Procpulse\` and rename it to `procpulse-service.exe`.

#### Step 2: Create `procpulse-service.xml`
In `C:\Procpulse\`, create `procpulse-service.xml` alongside `procpulse.exe`:

```xml
<service>
  <id>ProcpulseService</id>
  <name>Ultra-Light Process Telemetry &amp; Load Diagnostics</name>
  <description>Continuously monitors target application telemetry and writes aggregated CSV records.</description>
  <executable>C:\Procpulse\procpulse.exe</executable>
  <workingdirectory>C:\Procpulse</workingdirectory>
  
  <!-- Leave empty to use procpulse.ini, or specify CLI overrides -->
  <arguments></arguments>
  
  <!-- Auto-restart policy if crashed -->
  <onfailure action="restart" delay="10 sec"/>
  
  <!-- Graceful shutdown timeout (in ms) allowing procpulse to flush CSV buffers -->
  <stoptimeout>5000</stoptimeout>
  <stopexecutableforcefirst>false</stopexecutableforcefirst>
  
  <log mode="roll">
    <logpath>C:\Procpulse\service_logs</logpath>
  </log>
</service>
```

#### Step 3: Install & Manage the Service
Open an **Administrator PowerShell**:

```powershell
# Install the service into Windows SCM
.\procpulse-service.exe install

# Start the service
.\procpulse-service.exe start

# Check service status
.\procpulse-service.exe status

# Stop the service (triggers graceful CSV flush)
.\procpulse-service.exe stop

# Uninstall / remove the service
.\procpulse-service.exe uninstall
```

---

### Verifying Service Operation
1. Check that the service is running:
   ```powershell
   Get-Service ProcpulseService
   ```
2. Open Windows Task Manager and confirm:
   - `procpulse.exe` consumes negligible CPU (typically near 0.0%) and ~2–3 MB of memory.
3. Check the output CSV file:
   - New records appear every flush interval (default: 60s) while the target application is running.

---

## Grafana & Alloy Telemetry Pipeline

`procpulse` is built to pair with **Grafana Alloy**:

```
[Target App]
     │ (Win32 APIs)
     ▼
[procpulse] ──(writes CSV)──► [metrics.csv]
                                   │
                                   ▼ (tails CSV)
                           [Grafana Alloy]
                             │           │
           (Prometheus remote-write)   (Loki push)
                             ▼           ▼
                      [Prometheus]    [Loki]
                             │           │
                             └─────┬─────┘
                                   ▼
                           [Grafana Dashboard]
```

1. **Telemetry Ingestion**:
   - Uses `loki.source.file` to tail the output CSV (`procpulse_metrics.csv`).
   - Extracts all 19 columns with regex into named fields.
   - Exposes Prometheus gauges: `procpulse_app_cpu_percent`, `procpulse_app_cpu_cycles`, `procpulse_app_cpu_time_ms`, `procpulse_app_priv_active_mb`, `procpulse_app_ram_ws_mb`, `procpulse_system_cpu_percent`, `procpulse_system_ram_used_mb`.
   - Attaches labels for `executable`, `args`, and `machine` hostname.
2. **Dashboard Visualizations**:
   - Visualizes Application Memory, CPU %, Cycles, and the derived `Cycles / CPU Sec` ratio.

---

## License

Internal proprietary monitoring tool.
