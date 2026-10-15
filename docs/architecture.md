# Chronicle — System Architecture

**Understand behaviour. Learn from history. Detect anomalies.**

---

## 1. High-Level Architecture

Chronicle is architected as an end-to-end host security and activity monitoring pipeline:

```text
                           CHRONICLE PIPELINE
                                Linux Host
                                    │
                                    ▼
                         [eBPF / C Kernel Probes]
                                    │ (kprobes on execve, fork, openat, etc.)
                                    ▼
                     [Telemetry Collection & Normalization]
                                    │
                                    ▼
                        [Privacy Sanitization Layer]
                                    │ (Redacts passwords, tokens, API keys)
                                    ▼
                 [Local Database Storage: PostgreSQL / SQLite]
                  ┌─────────────────┴─────────────────┐
                  ▼                                   ▼
        [Raw Telemetry History]              [Behaviour Windows]
                  │                                   │
                  └─────────────────┬─────────────────┘
                                    ▼
                      [Behaviour Profiling Engine]
                     (Robust stats: Median, IQR, NMAD)
                                    │
                                    ▼
                           [Feature Extraction]
                      (Historical vs Current Deltas)
                                    │
                                    ▼
                     [In-Process Machine Learning]
                    (Isolation Forest + XGBoost Models)
                                    │
                                    ▼
                      [Risk Scoring & Explanation]
                       (0-100 Score + Evidence list)
                                    │
                                    ▼
                     [Chronicle Desktop Application]
                    (pywebview WebKit Native UI Window)
```

---

## 2. Core Subsystems & Components

| Component | Modules | Description |
| --- | --- | --- |
| **Kernel Observation Layer** | `eBPF_collector.py`, `src/chronicle/collector.py` | Hooks Linux kernel tracepoints and kprobes via BCC C code; captures process, file, network, and syscall telemetry. Falls back gracefully to `psutil`. |
| **Privacy Layer** | `chronicle/db/privacy.py` | Automatically scrubs sensitive tokens, credentials, passwords, and private file path details before data hits disk or ML pipelines. |
| **Storage Engine (DBMS)** | `chronicle/db/connection.py`, `repository.py`, `models.py` | Dual-engine relational repository supporting PostgreSQL (for high-volume historical logging) and SQLite (for zero-config local desktop operation). |
| **Schema & Migrations** | `chronicle/db/migrations.py`, `database/schema.sql` | Automated schema versioning and execution tracking for both database engines. |
| **Retention Manager** | `chronicle/db/retention.py` | Enforces configurable time-based and row-count-based retention windows, safeguarding disk resources. |
| **Historical Profiling** | `chronicle/db/profiling.py`, `src/chronicle/storage.py` | Computes program-level baseline profiles across executions; calculates robust Z-scores, deviation metrics, and baseline maturity stages. |
| **ML Detection Engine** | `src/chronicle/ml_detector.py`, `ML/src/` | Evaluates feature vectors using embedded Isolation Forest (unsupervised) and XGBoost (supervised) models directly within Python. |
| **Risk & Alert Engine** | `src/chronicle/risk_engine.py`, `profiling.py` | Synthesizes multi-category risk evidence into normalized 0–100 risk scores and human-readable explanations. |
| **Desktop Dashboard** | `app.py`, `ui/` | Lightweight native WebKit application (`pywebview`) rendering real-time processes, charts, profiles, and alert investigation views. |
| **Debian Packaging** | `packaging/build_deb.sh`, `chronicle.desktop` | Compiles and packages application binaries, assets, desktop launcher, and system icons into standard `.deb` format. |

---

## 3. Data Flow & Processing Stages

### Stage 1: Kernel Event Capture
- eBPF kprobes attach to:
  - Process creation/termination: `sys_enter_execve`, `sys_enter_clone`, `sched_process_exit`.
  - File operations: `sys_enter_openat`, `sys_enter_unlinkat`, `sys_enter_renameat`.
  - Network operations: `sys_enter_connect`, `sys_enter_accept4`.
  - System call aggregation: Per-syscall invocation counters in kernel maps.

### Stage 2: Normalization & Aggregation
- Events are grouped into temporal **Behaviour Windows** (default: 5.0 seconds).
- Per-window metrics include: CPU usage %, RSS/VMS memory, syscall counts, distinct file operations, byte I/O, network socket counts, and sensitive syscall spikes.

### Stage 3: Privacy Sanitization
- Values matching sensitive credential patterns (`password`, `secret`, `token`, `api_key`, `credential`) are scrubbed before storage (`[REDACTED_CREDENTIAL]`).
- File paths can optionally be masked or hashed.

### Stage 4: Persistent Relational Storage
- Telemetry events and behaviour windows are batched and inserted into the local database with foreign-key relationships linked to unique `instance_id` values.

### Stage 5: Historical Baseline Profiling
- For each unique program (`profile_id` based on binary hash/comm):
  - Robust center (Median) and dispersion (Normalized Median Absolute Deviation - NMAD / IQR) are computed.
  - Baselines track maturity stages: `COLD_START` (< 5 observations), `LEARNING`, and `MATURE` (>= 20 observations).
  - Anti-poisoning filters prevent known attack windows from corrupting the baseline.

### Stage 6: Anomaly Detection & Risk Scoring
- Live windows are compared against historical baselines:
  - Z-scores on resource usage, syscall burst rates, and I/O volumes.
  - Unprecedented events: Outbound connections from programs with 0 historical network activity, sensitive syscall invocations (`ptrace`, `bpf`), or unexpected child binary spawns.
  - Embedded ML models produce independent anomaly confidence scores.
- Risk Engine computes a composite score (0–100) with explainable reasons.

---

## 4. Operating Systems Concepts Applied

1. **Kernel Telemetry & eBPF:** In-kernel bytecode execution via BCC for non-invasive, low-overhead event monitoring.
2. **Process Lifecycle:** Tracking process states, process IDs (PID, PPID, TGID), user IDs, parent-child process hierarchies, and exit codes.
3. **System Call Interception:** Monitoring privileged and security-sensitive system calls (`execve`, `clone`, `ptrace`, `bpf`, `init_module`).
4. **File System Activity:** Tracking open flags, reads, writes, unlinks, and renames.
5. **Network Sockets:** Monitoring TCP/UDP transport-layer socket establishment, local/remote endpoints, and traffic volumes.
6. **Hardware Resource Accounting:** CPU times, voluntary/involuntary context switches, memory RSS/VMS, and file descriptor limits.

---

## 5. Database Management Systems (DBMS) Concepts Applied

1. **Relational Model & Integrity:** Formal schema with primary keys, foreign keys (`instance_id`), and constraints ensuring referential integrity across processes, events, windows, metrics, profiles, and detections.
2. **Dual-Engine Abstraction:** Pluggable database layer supporting PostgreSQL (production enterprise backend) and SQLite (zero-dependency embedded backend).
3. **Schema Migrations:** Versioned migration tracking (`schema_migrations` table) ensuring predictable, reproducible schema evolution.
4. **Indexing & Query Optimization:** Targeted B-Tree indexes on temporal ranges (`start_time`, `timestamp`), program identifiers (`profile_id`), process names (`comm`), and risk scores for sub-millisecond retrieval.
5. **Data Aggregation & Grouping:** Analytical queries aggregating historical window distributions, percentiles, and lifecycle statistics.
6. **Data Retention & Lifecycle Policies:** Configurable automated pruning of stale telemetry events to constrain local disk utilization.
7. **Transaction Safety:** ACID compliance across batch inserts and baseline profile updates.

---

## 6. Privacy & Security Architecture

Chronicle adheres to a strict **local-first** security model:
- **Local Isolation:** All telemetry, profiling data, and detections reside exclusively on the host machine.
- **Air-Gapped Operation:** The system initiates zero external network connections; no telemetry, metrics, or diagnostics are transmitted externally.
- **Local Interface Binding:** API services bind strictly to `127.0.0.1`.
- **Sensitive Data Sanitization:** In-memory redaction prevents accidental credential logging in process metadata or arguments.
