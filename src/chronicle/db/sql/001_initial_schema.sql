-- Migration 001: Initial Chronicle Telemetry Schema
-- Creates schema_migrations, process_instances, telemetry_events,
-- behaviour_windows, and system_metrics tables with indexes and constraints.

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 1. Process Instances
-- Linux reuses PIDs, so instance_id (UUID string) serves as permanent unique identity.
CREATE TABLE IF NOT EXISTS process_instances (
    instance_id VARCHAR(64) PRIMARY KEY,
    profile_id VARCHAR(64) NOT NULL,
    pid INTEGER NOT NULL,
    ppid INTEGER,
    parent_instance_id VARCHAR(64) REFERENCES process_instances(instance_id) ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED,
    comm VARCHAR(255) NOT NULL,
    executable TEXT,
    executable_hash VARCHAR(128),
    uid INTEGER,
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ,
    exit_code INTEGER,
    preexisting BOOLEAN NOT NULL DEFAULT FALSE,
    windows_written INTEGER NOT NULL DEFAULT 0,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_proc_time CHECK (end_time IS NULL OR end_time >= start_time)
);

CREATE INDEX IF NOT EXISTS idx_proc_pid ON process_instances(pid);
CREATE INDEX IF NOT EXISTS idx_proc_comm ON process_instances(comm);
CREATE INDEX IF NOT EXISTS idx_proc_profile_id ON process_instances(profile_id);
CREATE INDEX IF NOT EXISTS idx_proc_start_time ON process_instances(start_time);
CREATE INDEX IF NOT EXISTS idx_proc_end_time ON process_instances(end_time);
CREATE INDEX IF NOT EXISTS idx_proc_parent_instance ON process_instances(parent_instance_id);

-- 2. Telemetry Events
-- Stores raw observations (process lifecycle, file ops, network sockets, etc.).
-- instance_id is nullable so system-level events can be logged without a process association.
CREATE TABLE IF NOT EXISTS telemetry_events (
    event_id BIGSERIAL PRIMARY KEY,
    event_uuid VARCHAR(64) UNIQUE,
    instance_id VARCHAR(64) REFERENCES process_instances(instance_id) ON DELETE CASCADE,
    pid INTEGER,
    timestamp TIMESTAMPTZ NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    syscall_category VARCHAR(64),
    file_identifier TEXT,
    network_identifier VARCHAR(255),
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON telemetry_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_instance_id ON telemetry_events(instance_id);
CREATE INDEX IF NOT EXISTS idx_events_type_time ON telemetry_events(event_type, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_category ON telemetry_events(syscall_category);
CREATE INDEX IF NOT EXISTS idx_events_file_id ON telemetry_events(file_identifier) WHERE file_identifier IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_events_net_id ON telemetry_events(network_identifier) WHERE network_identifier IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_events_created_at ON telemetry_events(created_at);
CREATE INDEX IF NOT EXISTS idx_events_payload_gin ON telemetry_events USING gin (payload);

-- 3. Behaviour Windows
-- Stores aggregated feature rows per process (or system) over window intervals.
CREATE TABLE IF NOT EXISTS behaviour_windows (
    window_id BIGSERIAL PRIMARY KEY,
    window_index INTEGER NOT NULL,
    instance_id VARCHAR(64) REFERENCES process_instances(instance_id) ON DELETE CASCADE,
    profile_id VARCHAR(64) NOT NULL,
    pid INTEGER,
    ppid INTEGER,
    comm VARCHAR(255),
    executable TEXT,
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ NOT NULL,
    duration_s DOUBLE PRECISION NOT NULL,

    -- Syscall counts
    syscall_count BIGINT NOT NULL DEFAULT 0,
    syscalls_file BIGINT NOT NULL DEFAULT 0,
    syscalls_network BIGINT NOT NULL DEFAULT 0,
    syscalls_process BIGINT NOT NULL DEFAULT 0,
    syscalls_memory BIGINT NOT NULL DEFAULT 0,
    syscalls_ipc BIGINT NOT NULL DEFAULT 0,
    syscalls_other BIGINT NOT NULL DEFAULT 0,
    syscalls_sensitive BIGINT NOT NULL DEFAULT 0,
    distinct_syscalls INTEGER NOT NULL DEFAULT 0,

    -- File metrics
    file_read_count BIGINT NOT NULL DEFAULT 0,
    file_write_count BIGINT NOT NULL DEFAULT 0,
    file_open_count BIGINT NOT NULL DEFAULT 0,
    file_open_write_count BIGINT NOT NULL DEFAULT 0,
    file_create_count BIGINT NOT NULL DEFAULT 0,
    file_delete_count BIGINT NOT NULL DEFAULT 0,
    file_rename_count BIGINT NOT NULL DEFAULT 0,
    unique_files INTEGER NOT NULL DEFAULT 0,
    bytes_read BIGINT NOT NULL DEFAULT 0,
    bytes_written BIGINT NOT NULL DEFAULT 0,

    -- Network metrics
    network_count BIGINT NOT NULL DEFAULT 0,
    net_connect_count BIGINT NOT NULL DEFAULT 0,
    net_accept_count BIGINT NOT NULL DEFAULT 0,
    unique_dest_ips INTEGER NOT NULL DEFAULT 0,
    unique_dest_ports INTEGER NOT NULL DEFAULT 0,
    tcp_tx_bytes BIGINT NOT NULL DEFAULT 0,
    tcp_rx_bytes BIGINT NOT NULL DEFAULT 0,
    udp_tx_bytes BIGINT NOT NULL DEFAULT 0,

    -- Process relation metrics
    child_process_count INTEGER NOT NULL DEFAULT 0,
    thread_create_count INTEGER NOT NULL DEFAULT 0,
    exec_count INTEGER NOT NULL DEFAULT 0,

    -- Resource metrics
    cpu_usage DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    memory_usage DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    memory_rss_bytes BIGINT NOT NULL DEFAULT 0,
    memory_vms_bytes BIGINT NOT NULL DEFAULT 0,
    memory_percent DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    num_threads INTEGER NOT NULL DEFAULT 0,
    num_fds INTEGER NOT NULL DEFAULT 0,
    disk_read_bytes BIGINT NOT NULL DEFAULT 0,
    disk_write_bytes BIGINT NOT NULL DEFAULT 0,
    ctx_switches_voluntary BIGINT NOT NULL DEFAULT 0,
    ctx_switches_involuntary BIGINT NOT NULL DEFAULT 0,

    -- Bookkeeping & labels
    alive_at_end SMALLINT NOT NULL DEFAULT 1,
    label VARCHAR(64) DEFAULT 'unlabeled',
    label_binary SMALLINT,
    scenario VARCHAR(128) DEFAULT 'ambient',
    experiment_id VARCHAR(128),

    -- Arbitrary feature vectors / syscall histograms
    feature_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    schema_version VARCHAR(32) NOT NULL DEFAULT '1.0',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_window_time CHECK (end_time >= start_time AND duration_s >= 0)
);

CREATE INDEX IF NOT EXISTS idx_win_instance_time ON behaviour_windows(instance_id, start_time);
CREATE INDEX IF NOT EXISTS idx_win_profile_time ON behaviour_windows(profile_id, start_time);
CREATE INDEX IF NOT EXISTS idx_win_start_end ON behaviour_windows(start_time, end_time);
CREATE INDEX IF NOT EXISTS idx_win_end_time ON behaviour_windows(end_time);
CREATE INDEX IF NOT EXISTS idx_win_created_at ON behaviour_windows(created_at);
CREATE INDEX IF NOT EXISTS idx_win_label ON behaviour_windows(label);
CREATE INDEX IF NOT EXISTS idx_win_experiment ON behaviour_windows(experiment_id);
CREATE INDEX IF NOT EXISTS idx_win_feature_gin ON behaviour_windows USING gin (feature_data);

-- 4. System Metrics
-- System-wide CPU, memory, disk, network measurements per window.
CREATE TABLE IF NOT EXISTS system_metrics (
    metric_id BIGSERIAL PRIMARY KEY,
    window_index INTEGER NOT NULL,
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ NOT NULL,
    duration_s DOUBLE PRECISION NOT NULL,

    cpu_percent_total DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    cpu_user DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    cpu_system DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    cpu_idle DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    cpu_iowait DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    cpu_steal DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    cpu_core_max DOUBLE PRECISION NOT NULL DEFAULT 0.0,

    load_1m DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    load_5m DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    load_15m DOUBLE PRECISION NOT NULL DEFAULT 0.0,

    mem_total BIGINT NOT NULL DEFAULT 0,
    mem_used BIGINT NOT NULL DEFAULT 0,
    mem_available BIGINT NOT NULL DEFAULT 0,
    mem_percent DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    swap_used BIGINT NOT NULL DEFAULT 0,
    swap_percent DOUBLE PRECISION NOT NULL DEFAULT 0.0,

    disk_root_percent DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    disk_used_percent_max DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    disk_read_bytes BIGINT NOT NULL DEFAULT 0,
    disk_write_bytes BIGINT NOT NULL DEFAULT 0,

    net_bytes_sent BIGINT NOT NULL DEFAULT 0,
    net_bytes_recv BIGINT NOT NULL DEFAULT 0,
    net_packets_sent BIGINT NOT NULL DEFAULT 0,
    net_packets_recv BIGINT NOT NULL DEFAULT 0,

    conn_established INTEGER NOT NULL DEFAULT 0,
    conn_listen INTEGER NOT NULL DEFAULT 0,
    conn_total INTEGER NOT NULL DEFAULT 0,

    process_count INTEGER NOT NULL DEFAULT 0,
    tracked_instances INTEGER NOT NULL DEFAULT 0,
    events_received BIGINT NOT NULL DEFAULT 0,
    events_lost BIGINT NOT NULL DEFAULT 0,

    label VARCHAR(64) DEFAULT 'unlabeled',
    label_binary SMALLINT,
    scenario VARCHAR(128) DEFAULT 'ambient',
    experiment_id VARCHAR(128),

    raw_metrics JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_sys_metric_time CHECK (end_time >= start_time AND duration_s >= 0)
);

CREATE INDEX IF NOT EXISTS idx_sys_metrics_time ON system_metrics(start_time, end_time);
CREATE INDEX IF NOT EXISTS idx_sys_metrics_end_time ON system_metrics(end_time);
CREATE INDEX IF NOT EXISTS idx_sys_metrics_created_at ON system_metrics(created_at);
CREATE INDEX IF NOT EXISTS idx_sys_metrics_experiment ON system_metrics(experiment_id);
