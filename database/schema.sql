-- ============================================================================
-- Chronicle — Complete Master Relational Database Schema
-- PBL Project Documentation | Team ID: OSDBMS-V-2026-T-005
-- Graphic Era (Deemed to be University), Dehradun | Academic Session 2026–27
-- ============================================================================
-- Modules: Telemetry Storage, Behaviour Windows, Historical Baselines, Detections
-- Database Engines Supported: PostgreSQL 14+ (Production) and SQLite 3.35+ (Fallback)
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 0. Schema Migration Version Tracking
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ----------------------------------------------------------------------------
-- 1. Process Instances Table
-- ----------------------------------------------------------------------------
-- Represents a single lifecycle execution of an operating system process.
-- Linux aggressively recycles PIDs; therefore, instance_id (UUID string) serves
-- as the globally unique, non-reusable surrogate primary key.
CREATE TABLE IF NOT EXISTS process_instances (
    instance_id VARCHAR(64) PRIMARY KEY,
    profile_id VARCHAR(64) NOT NULL,
    pid INTEGER NOT NULL,
    ppid INTEGER,
    parent_instance_id VARCHAR(64) REFERENCES process_instances(instance_id) ON DELETE SET NULL,
    comm VARCHAR(255) NOT NULL,
    executable TEXT,
    executable_hash VARCHAR(128),
    uid INTEGER,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE,
    exit_code INTEGER,
    preexisting BOOLEAN NOT NULL DEFAULT FALSE,
    windows_written INTEGER NOT NULL DEFAULT 0,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_proc_time CHECK (end_time IS NULL OR end_time >= start_time)
);

CREATE INDEX IF NOT EXISTS idx_proc_pid ON process_instances(pid);
CREATE INDEX IF NOT EXISTS idx_proc_comm ON process_instances(comm);
CREATE INDEX IF NOT EXISTS idx_proc_profile_id ON process_instances(profile_id);
CREATE INDEX IF NOT EXISTS idx_proc_start_time ON process_instances(start_time);
CREATE INDEX IF NOT EXISTS idx_proc_end_time ON process_instances(end_time);
CREATE INDEX IF NOT EXISTS idx_proc_parent_instance ON process_instances(parent_instance_id);
CREATE INDEX IF NOT EXISTS idx_proc_profile_start ON process_instances(profile_id, start_time);
CREATE INDEX IF NOT EXISTS idx_proc_comm_start ON process_instances(comm, start_time);

-- ----------------------------------------------------------------------------
-- 2. Telemetry Events Table
-- ----------------------------------------------------------------------------
-- Stores discrete, kernel-level atomic events (execve, fork, open, unlink, connect).
CREATE TABLE IF NOT EXISTS telemetry_events (
    event_id BIGSERIAL PRIMARY KEY,
    event_uuid VARCHAR(64) UNIQUE,
    instance_id VARCHAR(64) REFERENCES process_instances(instance_id) ON DELETE CASCADE,
    pid INTEGER,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    syscall_category VARCHAR(64),
    file_identifier TEXT,
    network_identifier VARCHAR(255),
    payload JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON telemetry_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_instance_id ON telemetry_events(instance_id);
CREATE INDEX IF NOT EXISTS idx_events_type_time ON telemetry_events(event_type, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_syscall_cat ON telemetry_events(syscall_category);

-- ----------------------------------------------------------------------------
-- 3. Behaviour Windows Table
-- ----------------------------------------------------------------------------
-- Aggregates multi-metric process activity over fixed-duration time intervals (e.g., 5 seconds).
-- Serves as the primary feature carrier for statistical baseline calculation and ML detection.
CREATE TABLE IF NOT EXISTS behaviour_windows (
    window_id BIGSERIAL PRIMARY KEY,
    instance_id VARCHAR(64) NOT NULL REFERENCES process_instances(instance_id) ON DELETE CASCADE,
    profile_id VARCHAR(64) NOT NULL,
    pid INTEGER NOT NULL,
    comm VARCHAR(255) NOT NULL,
    executable TEXT,
    window_index INTEGER NOT NULL,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE NOT NULL,
    duration_s DOUBLE PRECISION NOT NULL DEFAULT 5.0,

    -- Resource utilization metrics
    cpu_usage DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    memory_usage DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    memory_rss_bytes BIGINT NOT NULL DEFAULT 0,
    memory_vms_bytes BIGINT NOT NULL DEFAULT 0,
    memory_percent DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    num_threads INTEGER NOT NULL DEFAULT 1,
    num_fds INTEGER NOT NULL DEFAULT 0,
    disk_read_bytes BIGINT NOT NULL DEFAULT 0,
    disk_write_bytes BIGINT NOT NULL DEFAULT 0,
    ctx_switches_voluntary BIGINT NOT NULL DEFAULT 0,
    ctx_switches_involuntary BIGINT NOT NULL DEFAULT 0,

    -- System call frequency and breakdown
    syscall_count INTEGER NOT NULL DEFAULT 0,
    distinct_syscalls INTEGER NOT NULL DEFAULT 0,
    syscalls_file INTEGER NOT NULL DEFAULT 0,
    syscalls_network INTEGER NOT NULL DEFAULT 0,
    syscalls_process INTEGER NOT NULL DEFAULT 0,
    syscalls_memory INTEGER NOT NULL DEFAULT 0,
    syscalls_ipc INTEGER NOT NULL DEFAULT 0,
    syscalls_other INTEGER NOT NULL DEFAULT 0,
    syscalls_sensitive INTEGER NOT NULL DEFAULT 0,

    -- File system interaction metrics
    file_open_count INTEGER NOT NULL DEFAULT 0,
    file_open_write_count INTEGER NOT NULL DEFAULT 0,
    file_read_count INTEGER NOT NULL DEFAULT 0,
    file_write_count INTEGER NOT NULL DEFAULT 0,
    file_delete_count INTEGER NOT NULL DEFAULT 0,
    file_rename_count INTEGER NOT NULL DEFAULT 0,
    unique_files INTEGER NOT NULL DEFAULT 0,
    bytes_read BIGINT NOT NULL DEFAULT 0,
    bytes_written BIGINT NOT NULL DEFAULT 0,

    -- Network interaction metrics
    network_count INTEGER NOT NULL DEFAULT 0,
    net_connect_count INTEGER NOT NULL DEFAULT 0,
    net_accept_count INTEGER NOT NULL DEFAULT 0,
    unique_dest_ips INTEGER NOT NULL DEFAULT 0,
    unique_dest_ports INTEGER NOT NULL DEFAULT 0,
    tcp_tx_bytes BIGINT NOT NULL DEFAULT 0,
    tcp_rx_bytes BIGINT NOT NULL DEFAULT 0,
    udp_tx_bytes BIGINT NOT NULL DEFAULT 0,

    -- Process relationships and executions
    child_process_count INTEGER NOT NULL DEFAULT 0,
    thread_create_count INTEGER NOT NULL DEFAULT 0,
    exec_count INTEGER NOT NULL DEFAULT 0,

    -- Training labels and ground truth
    label VARCHAR(64) DEFAULT 'benign',
    label_binary INTEGER DEFAULT 0,

    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_win_time CHECK (end_time >= start_time),
    CONSTRAINT uq_instance_window UNIQUE (instance_id, window_index)
);

CREATE INDEX IF NOT EXISTS idx_win_instance_id ON behaviour_windows(instance_id);
CREATE INDEX IF NOT EXISTS idx_win_profile_id ON behaviour_windows(profile_id);
CREATE INDEX IF NOT EXISTS idx_win_start_time ON behaviour_windows(start_time);
CREATE INDEX IF NOT EXISTS idx_win_end_time ON behaviour_windows(end_time);
CREATE INDEX IF NOT EXISTS idx_win_comm ON behaviour_windows(comm);
CREATE INDEX IF NOT EXISTS idx_win_label ON behaviour_windows(label);
CREATE INDEX IF NOT EXISTS idx_win_profile_label ON behaviour_windows(profile_id, label);
CREATE INDEX IF NOT EXISTS idx_win_instance_index ON behaviour_windows(instance_id, window_index);

-- ----------------------------------------------------------------------------
-- 4. System Metrics Table
-- ----------------------------------------------------------------------------
-- Captures host-wide system performance to contextualize process resource consumption.
CREATE TABLE IF NOT EXISTS system_metrics (
    metric_id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    cpu_percent DOUBLE PRECISION NOT NULL,
    memory_used_bytes BIGINT NOT NULL,
    memory_total_bytes BIGINT NOT NULL,
    memory_percent DOUBLE PRECISION NOT NULL,
    disk_read_bytes_sec DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    disk_write_bytes_sec DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    net_tx_bytes_sec DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    net_rx_bytes_sec DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    process_count INTEGER NOT NULL,
    thread_count INTEGER NOT NULL,
    context_switches_sec DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    interrupts_sec DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sys_metrics_time ON system_metrics(timestamp);

-- ----------------------------------------------------------------------------
-- 5. Process Behaviour Profiles Table
-- ----------------------------------------------------------------------------
-- Stores aggregated historical behavioural baselines per program identity.
-- Maintains robust center (median) and scale (NMAD) for anomaly comparison.
CREATE TABLE IF NOT EXISTS process_profiles (
    profile_id VARCHAR(64) NOT NULL,
    comm VARCHAR(255) NOT NULL,
    executable TEXT,
    executable_hash VARCHAR(128),
    profile_version INTEGER NOT NULL DEFAULT 1,
    observations_count INTEGER NOT NULL DEFAULT 0,
    time_period_start TIMESTAMP WITH TIME ZONE,
    time_period_end TIMESTAMP WITH TIME ZONE,
    baseline_stats JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (profile_id, profile_version)
);

CREATE INDEX IF NOT EXISTS idx_profile_comm ON process_profiles(comm);
CREATE INDEX IF NOT EXISTS idx_profile_updated ON process_profiles(updated_at);

-- ----------------------------------------------------------------------------
-- 6. Model Detections & Anomalies Table
-- ----------------------------------------------------------------------------
-- Stores results from ML models (Isolation Forest, XGBoost) and statistical deviations.
CREATE TABLE IF NOT EXISTS detections (
    detection_id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id VARCHAR(64) REFERENCES process_instances(instance_id) ON DELETE SET NULL,
    window_id BIGINT REFERENCES behaviour_windows(window_id) ON DELETE SET NULL,
    detector_name VARCHAR(64) NOT NULL,
    anomaly_score DOUBLE PRECISION,
    risk_score DOUBLE PRECISION,
    is_anomaly BOOLEAN NOT NULL DEFAULT TRUE,
    mitre_technique VARCHAR(64),
    scenario VARCHAR(128),
    description TEXT,
    details JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_detections_time ON detections(timestamp);
CREATE INDEX IF NOT EXISTS idx_detections_instance ON detections(instance_id);
CREATE INDEX IF NOT EXISTS idx_detections_window ON detections(window_id);
CREATE INDEX IF NOT EXISTS idx_detections_detector ON detections(detector_name);
CREATE INDEX IF NOT EXISTS idx_detections_risk ON detections(risk_score);
CREATE INDEX IF NOT EXISTS idx_detections_anomaly_time ON detections(is_anomaly, timestamp);
CREATE INDEX IF NOT EXISTS idx_detections_inst_time ON detections(instance_id, timestamp);
