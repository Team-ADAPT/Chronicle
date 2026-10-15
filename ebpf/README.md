# Chronicle — eBPF Telemetry Collection Layer

The **eBPF Telemetry Layer** is the kernel-level observation subsystem of Chronicle. It captures real-time host process behaviour, system call events, file system operations, and network connections with minimal system overhead.

---

## 1. Architecture

```text
User Space                     Kernel Space
┌─────────────────────────┐   ┌──────────────────────────────┐
│  Chronicle Collector    │   │  eBPF Probes (BCC / C)       │
│  (Python / BCC Engine)  │   │                              │
│                         │   │  • sys_enter_execve          │
│  • Perf Ring Buffer ◄───┼───┼──• sys_enter_clone / fork    │
│  • Event Normalizer     │   │  • sched_process_exit        │
│  • Behaviour Windows    │   │  • sys_enter_openat          │
│  • psutil Fallback      │   │  • sys_enter_unlinkat        │
└─────────────────────────┘   │  • sys_enter_connect         │
                              │  • sys_enter_accept4         │
                              └──────────────────────────────┘
```

---

## 2. Monitored Telemetry

### 2.1 Process Behaviour
- **Creation & Execution:** Captured via `sys_enter_execve`, `sys_enter_clone`, and `sys_enter_fork`. Tracks executable path, binary hash, arguments, PID, TID, PPID, and UID.
- **Termination:** Captured via `sched_process_exit`. Records exit codes, process lifetime duration, and crashed vs clean exit states.
- **Hierarchy:** Tracks parent-child process lineages to detect unauthorized command-and-control shells or unusual process spawning patterns.

### 2.2 System Calls
- **Tracepoints:** Monitored via `sys_enter` and sensitive kprobes.
- **Monitored Families:** File syscalls (`open`, `read`, `write`, `unlink`), network syscalls (`connect`, `accept`, `sendto`, `recvfrom`), process syscalls (`execve`, `clone`, `fork`), and privileged/sensitive syscalls (`ptrace`, `bpf`, `init_module`).

### 2.3 File Interactions
- **Operations:** Open, Read, Write, Create, Delete (`unlinkat`), Rename (`renameat`).
- **Accounting:** File paths (with optional hashing/privacy sanitization), access flags (`O_RDONLY`, `O_WRONLY`, `O_CREAT`), and byte transfer metrics.

### 2.4 Network Activity
- **Socket Operations:** Outbound connections (`sys_enter_connect`), inbound connections (`sys_enter_accept4`).
- **Network Parameters:** Protocol families (`AF_INET`, `AF_INET6`), destination IP addresses, destination ports, and transmitted/received byte volumes.

---

## 3. Implementation Details

Chronicle provides two interfaces for telemetry collection:

1. **Embedded Live Collector (`src/chronicle/collector.py`):**
   - Integrated directly into the `ChroniclePipeline`.
   - Attaches BCC probes dynamically on Linux kernels.
   - Includes automatic, zero-crash fallback to live host monitoring via `psutil` when running in unprivileged environments, containers, or non-Linux hosts.

2. **Standalone Data Collection Pipeline (`eBPF_collector.py`):**
   - High-throughput dataset generation utility.
   - Emits structured CSV files:
     - `process_instances.csv`: Registered process executions and lifecycles.
     - `telemetry_events.csv`: Raw kernel events with timestamps and arguments.
     - `behaviour_windows.csv`: 5-second aggregated behavioural feature windows.
     - `system_metrics.csv`: Host-wide CPU, memory, and I/O metrics.

---

## 4. Kernel Requirements & Prerequisites

For native eBPF probe execution on Linux:

```bash
# Ubuntu / Debian
sudo apt update
sudo apt install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r) python3-psutil
```

Privileges:
- Requires `root` or `CAP_BPF` capability to load eBPF bytecode into the kernel.
- If run without root, Chronicle automatically operates in `psutil` fallback mode to ensure uninterrupted desktop usability and testing.
