-- Migration 002: Process Behaviour Profiles & Model Detections
-- Creates process_profiles table for historical program-level baselines
-- and detections table for supervised / unsupervised anomaly outputs.

-- 5. Process Behaviour Profiles
-- Aggregates historical baseline statistics per program identity.
CREATE TABLE IF NOT EXISTS process_profiles (
    profile_id VARCHAR(64) NOT NULL,
    comm VARCHAR(255) NOT NULL,
    executable TEXT,
    executable_hash VARCHAR(128),
    profile_version INTEGER NOT NULL DEFAULT 1,
    observations_count INTEGER NOT NULL DEFAULT 0,
    time_period_start TIMESTAMPTZ,
    time_period_end TIMESTAMPTZ,
    baseline_stats JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (profile_id, profile_version)
);

CREATE INDEX IF NOT EXISTS idx_profile_comm ON process_profiles(comm);
CREATE INDEX IF NOT EXISTS idx_profile_updated ON process_profiles(updated_at);

-- 6. Model Detections & Anomalies
-- Stores results from XGBoost, Isolation Forest, and baseline deviation checks.
CREATE TABLE IF NOT EXISTS detections (
    detection_id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    instance_id VARCHAR(64) REFERENCES process_instances(instance_id) ON DELETE SET NULL,
    window_id BIGINT REFERENCES behaviour_windows(window_id) ON DELETE SET NULL,
    detector_name VARCHAR(64) NOT NULL,
    anomaly_score DOUBLE PRECISION,
    risk_score DOUBLE PRECISION,
    is_anomaly BOOLEAN NOT NULL DEFAULT TRUE,
    mitre_technique VARCHAR(64),
    scenario VARCHAR(128),
    description TEXT,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_detections_time ON detections(timestamp);
CREATE INDEX IF NOT EXISTS idx_detections_instance ON detections(instance_id);
CREATE INDEX IF NOT EXISTS idx_detections_window ON detections(window_id);
CREATE INDEX IF NOT EXISTS idx_detections_detector ON detections(detector_name);
CREATE INDEX IF NOT EXISTS idx_detections_risk ON detections(risk_score);
CREATE INDEX IF NOT EXISTS idx_detections_anomaly_time ON detections(is_anomaly, timestamp);
