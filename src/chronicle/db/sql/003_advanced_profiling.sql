-- Migration 003: Advanced Behavioural Baselining and Profiling Indexes
-- Optimizes historical process telemetry retrieval, time-range slicing,
-- clean baseline filtering, and cross-instance identity queries.

CREATE INDEX IF NOT EXISTS idx_win_profile_label ON behaviour_windows(profile_id, label);
CREATE INDEX IF NOT EXISTS idx_win_instance_index ON behaviour_windows(instance_id, window_index);
CREATE INDEX IF NOT EXISTS idx_proc_profile_start ON process_instances(profile_id, start_time);
CREATE INDEX IF NOT EXISTS idx_proc_comm_start ON process_instances(comm, start_time);
CREATE INDEX IF NOT EXISTS idx_detections_inst_time ON detections(instance_id, timestamp);
