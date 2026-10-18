-- SQLite Schema for Chronicle Host Behaviour Analysis
-- Provides complete relational schema matching PostgreSQL definitions
-- for zero-dependency, local-first host operation.

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 1. Process Instances
CREATE TABLE IF NOT EXISTS process_instances (
    instance_id TEXT PRIMARY KEY,
    profile_id TEXT NOT NULL,
    pid INTEGER NOT NULL,
    ppid INTEGER,
    parent_instance_id TEXT REFERENCES process_instances(instance_id) ON DELETE SET NULL,
    comm TEXT NOT NULL,
    executable TEXT,
    executable_hash TEXT,
    uid INTEGER,
    start_time TEXT NOT NULL,
    end_time TEXT,
    exit_code INTEGER,
    preexisting INTEGER NOT NULL DEFAULT 0,
    windows_written INTEGER NOT NULL DEFAULT 0,
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_proc_pid ON process_instances(pid);
CREATE INDEX IF NOT EXISTS idx_proc_comm ON process_instances(comm);
CREATE INDEX IF NOT EXISTS idx_proc_profile_id ON process_instances(profile_id);
CREATE INDEX IF NOT EXISTS idx_proc_start_time ON process_instances(start_time);
CREATE INDEX IF NOT EXISTS idx_proc_end_time ON process_instances(end_time);

-- 2. Telemetry Events
CREATE TABLE IF NOT EXISTS telemetry_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_uuid TEXT UNIQUE,
    instance_id TEXT REFERENCES process_instances(instance_id) ON DELETE CASCADE,
    pid INTEGER,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    syscall_category TEXT,
    file_identifier TEXT,
    network_identifier TEXT,
    payload TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON telemetry_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_instance_id ON telemetry_events(instance_id);
CREATE INDEX IF NOT EXISTS idx_events_type_time ON telemetry_events(event_type, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_category ON telemetry_events(syscall_category);

-- 3. Behaviour Windows
CREATE TABLE IF NOT EXISTS behaviour_windows (
    window_id INTEGER PRIMARY KEY AUTOINCREMENT,
    window_index INTEGER NOT NULL,
    instance_id TEXT REFERENCES process_instances(instance_id) ON DELETE CASCADE,
    profile_id TEXT NOT NULL,
    pid INTEGER,
    ppid INTEGER,
    comm TEXT,
    executable TEXT,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    duration_s REAL NOT NULL,

    -- Syscall counts
    syscall_count INTEGER NOT NULL DEFAULT 0,
    syscalls_file INTEGER NOT NULL DEFAULT 0,
    syscalls_network INTEGER NOT NULL DEFAULT 0,
    syscalls_process INTEGER NOT NULL DEFAULT 0,
    syscalls_memory INTEGER NOT NULL DEFAULT 0,
    syscalls_ipc INTEGER NOT NULL DEFAULT 0,
    syscalls_other INTEGER NOT NULL DEFAULT 0,
    syscalls_sensitive INTEGER NOT NULL DEFAULT 0,
    distinct_syscalls INTEGER NOT NULL DEFAULT 0,

    -- File metrics
    file_read_count INTEGER NOT NULL DEFAULT 0,
    file_write_count INTEGER NOT NULL DEFAULT 0,
    file_open_count INTEGER NOT NULL DEFAULT 0,
    file_open_write_count INTEGER NOT NULL DEFAULT 0,
    file_create_count INTEGER NOT NULL DEFAULT 0,
    file_delete_count INTEGER NOT NULL DEFAULT 0,
    file_rename_count INTEGER NOT NULL DEFAULT 0,
    unique_files INTEGER NOT NULL DEFAULT 0,
    bytes_read INTEGER NOT NULL DEFAULT 0,
    bytes_written INTEGER NOT NULL DEFAULT 0,

    -- Network metrics
    network_count INTEGER NOT NULL DEFAULT 0,
    net_connect_count INTEGER NOT NULL DEFAULT 0,
    net_accept_count INTEGER NOT NULL DEFAULT 0,
    unique_dest_ips INTEGER NOT NULL DEFAULT 0,
    unique_dest_ports INTEGER NOT NULL DEFAULT 0,
    tcp_tx_bytes INTEGER NOT NULL DEFAULT 0,
    tcp_rx_bytes INTEGER NOT NULL DEFAULT 0,
    udp_tx_bytes INTEGER NOT NULL DEFAULT 0,

    -- Process relation metrics
    child_process_count INTEGER NOT NULL DEFAULT 0,
    thread_create_count INTEGER NOT NULL DEFAULT 0,
    exec_count INTEGER NOT NULL DEFAULT 0,

    -- Resource metrics
    cpu_usage REAL NOT NULL DEFAULT 0.0,
    memory_usage REAL NOT NULL DEFAULT 0.0,
    memory_rss_bytes INTEGER NOT NULL DEFAULT 0,
    memory_vms_bytes INTEGER NOT NULL DEFAULT 0,
    memory_percent REAL NOT NULL DEFAULT 0.0,
    num_threads INTEGER NOT NULL DEFAULT 0,
    num_fds INTEGER NOT NULL DEFAULT 0,
    disk_read_bytes INTEGER NOT NULL DEFAULT 0,
    disk_write_bytes INTEGER NOT NULL DEFAULT 0,
    ctx_switches_voluntary INTEGER NOT NULL DEFAULT 0,
    ctx_switches_involuntary INTEGER NOT NULL DEFAULT 0,

    -- Bookkeeping & labels
    alive_at_end INTEGER NOT NULL DEFAULT 1,
    label TEXT DEFAULT 'unlabeled',
    label_binary INTEGER,
    scenario TEXT DEFAULT 'ambient',
    experiment_id TEXT,

    -- Feature vectors and schema version
    feature_data TEXT NOT NULL DEFAULT '{}',
    schema_version TEXT NOT NULL DEFAULT '1.0',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_win_instance_time ON behaviour_windows(instance_id, start_time);
CREATE INDEX IF NOT EXISTS idx_win_profile_time ON behaviour_windows(profile_id, start_time);
CREATE INDEX IF NOT EXISTS idx_win_start_end ON behaviour_windows(start_time, end_time);
CREATE INDEX IF NOT EXISTS idx_win_label ON behaviour_windows(label);

-- 4. System Metrics
CREATE TABLE IF NOT EXISTS system_metrics (
    metric_id INTEGER PRIMARY KEY AUTOINCREMENT,
    window_index INTEGER NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    duration_s REAL NOT NULL,

    cpu_percent_total REAL NOT NULL DEFAULT 0.0,
    cpu_user REAL NOT NULL DEFAULT 0.0,
    cpu_system REAL NOT NULL DEFAULT 0.0,
    cpu_idle REAL NOT NULL DEFAULT 0.0,
    cpu_iowait REAL NOT NULL DEFAULT 0.0,
    cpu_steal REAL NOT NULL DEFAULT 0.0,
    cpu_core_max REAL NOT NULL DEFAULT 0.0,

    load_1m REAL NOT NULL DEFAULT 0.0,
    load_5m REAL NOT NULL DEFAULT 0.0,
    load_15m REAL NOT NULL DEFAULT 0.0,

    mem_total INTEGER NOT NULL DEFAULT 0,
    mem_used INTEGER NOT NULL DEFAULT 0,
    mem_available INTEGER NOT NULL DEFAULT 0,
    mem_percent REAL NOT NULL DEFAULT 0.0,
    swap_used INTEGER NOT NULL DEFAULT 0,
    swap_percent REAL NOT NULL DEFAULT 0.0,

    disk_read_bytes_sec REAL NOT NULL DEFAULT 0.0,
    disk_write_bytes_sec REAL NOT NULL DEFAULT 0.0,
    disk_read_ops_sec REAL NOT NULL DEFAULT 0.0,
    disk_write_ops_sec REAL NOT NULL DEFAULT 0.0,
    disk_util_percent REAL NOT NULL DEFAULT 0.0,

    net_bytes_sent_sec REAL NOT NULL DEFAULT 0.0,
    net_bytes_recv_sec REAL NOT NULL DEFAULT 0.0,
    net_packets_sent_sec REAL NOT NULL DEFAULT 0.0,
    net_packets_recv_sec REAL NOT NULL DEFAULT 0.0,
    tcp_connections INTEGER NOT NULL DEFAULT 0,

    procs_running INTEGER NOT NULL DEFAULT 0,
    procs_total INTEGER NOT NULL DEFAULT 0,
    procs_blocked INTEGER NOT NULL DEFAULT 0,
    ctx_switches_sec REAL NOT NULL DEFAULT 0.0,
    interrupts_sec REAL NOT NULL DEFAULT 0.0,

    experiment_id TEXT,
    extra TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sys_time ON system_metrics(start_time);

-- 5. Process Behaviour Profiles
CREATE TABLE IF NOT EXISTS process_profiles (
    profile_id TEXT NOT NULL,
    comm TEXT NOT NULL,
    executable TEXT,
    executable_hash TEXT,
    profile_version INTEGER NOT NULL DEFAULT 1,
    observations_count INTEGER NOT NULL DEFAULT 0,
    time_period_start TEXT,
    time_period_end TEXT,
    baseline_stats TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (profile_id, profile_version)
);

CREATE INDEX IF NOT EXISTS idx_profile_comm ON process_profiles(comm);
CREATE INDEX IF NOT EXISTS idx_profile_updated ON process_profiles(updated_at);

-- 6. Model Detections & Anomalies
CREATE TABLE IF NOT EXISTS detections (
    detection_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id TEXT REFERENCES process_instances(instance_id) ON DELETE SET NULL,
    window_id INTEGER REFERENCES behaviour_windows(window_id) ON DELETE SET NULL,
    detector_name TEXT NOT NULL,
    anomaly_score REAL,
    risk_score REAL,
    is_anomaly INTEGER NOT NULL DEFAULT 1,
    mitre_technique TEXT,
    scenario TEXT,
    description TEXT,
    details TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_detections_time ON detections(timestamp);
CREATE INDEX IF NOT EXISTS idx_detections_instance ON detections(instance_id);
CREATE INDEX IF NOT EXISTS idx_detections_detector ON detections(detector_name);
CREATE INDEX IF NOT EXISTS idx_detections_risk ON detections(risk_score);
CREATE INDEX IF NOT EXISTS idx_win_profile_label ON behaviour_windows(profile_id, label);
CREATE INDEX IF NOT EXISTS idx_win_instance_index ON behaviour_windows(instance_id, window_index);
CREATE INDEX IF NOT EXISTS idx_proc_profile_start ON process_instances(profile_id, start_time);
CREATE INDEX IF NOT EXISTS idx_proc_comm_start ON process_instances(comm, start_time);
CREATE INDEX IF NOT EXISTS idx_detections_inst_time ON detections(instance_id, timestamp);
