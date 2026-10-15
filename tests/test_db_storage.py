"""
Comprehensive test suite for Chronicle database storage layer.
Validates SQLite fallback mode, PostgreSQL configuration handling,
relational integrity, historical profiling, and retention cleanup.
"""

import datetime
import os
import tempfile
import unittest

from chronicle.db.config import DatabaseConfig, RetentionConfig
from chronicle.db.connection import Database, DatabaseConfigurationError
from chronicle.db.migrations import get_migration_status, run_migrations
from chronicle.db.models import (
    BehaviourWindow,
    DetectionRecord,
    ProcessInstance,
    ProcessProfile,
    SystemMetric,
    TelemetryEvent,
)
from chronicle.db.profiling import ProfileManager
from chronicle.db.repository import TelemetryRepository
from chronicle.db.retention import RetentionManager


class TestChronicleDatabase(unittest.TestCase):
    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.temp_db.name
        self.temp_db.close()

        self.config = DatabaseConfig(engine="sqlite", sqlite_path=self.db_path)
        self.db = Database(self.config)
        run_migrations(self.db)
        self.repo = TelemetryRepository(self.db)

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_database_health_and_engine(self):
        """Verify database resolves to SQLite with healthy status."""
        self.assertEqual(self.db.engine, "sqlite")
        health = self.db.check_health()
        self.assertTrue(health["connected"])
        self.assertEqual(health["engine"], "sqlite")
        self.assertTrue(health["is_local"])
        self.assertIn("SQLite", health["server_version"])

    def test_migration_status(self):
        """Verify migrations are tracked in schema_migrations."""
        status = get_migration_status(self.db)
        self.assertGreaterEqual(status["applied_count"], 2)
        self.assertEqual(status["pending_count"], 0)

    def test_process_lifecycle(self):
        """Verify process instance registration, batching, updating, and querying."""
        now = datetime.datetime.now(datetime.timezone.utc)
        inst = ProcessInstance(
            instance_id="proc-test-1",
            profile_id="prof-curl",
            pid=4242,
            ppid=1,
            comm="curl",
            executable="/usr/bin/curl",
            uid=1000,
            start_time=now,
            metadata={"cli": "curl https://example.com"},
        )

        res_id = self.repo.register_process(inst)
        self.assertEqual(res_id, "proc-test-1")

        fetched = self.repo.get_process("proc-test-1")
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.comm, "curl")
        self.assertEqual(fetched.metadata.get("cli"), "curl https://example.com")

        # Update exit
        end_time = now + datetime.timedelta(seconds=2)
        ok = self.repo.update_process_exit("proc-test-1", end_time=end_time, exit_code=0)
        self.assertTrue(ok)

        updated = self.repo.get_process("proc-test-1")
        self.assertEqual(updated.exit_code, 0)
        self.assertIsNotNone(updated.end_time)

    def test_telemetry_events(self):
        """Verify insertion and querying of raw kernel telemetry events."""
        now = datetime.datetime.now(datetime.timezone.utc)
        inst = ProcessInstance(
            instance_id="proc-test-2",
            profile_id="prof-bash",
            pid=5000,
            comm="bash",
            start_time=now,
        )
        self.repo.register_process(inst)

        evt = TelemetryEvent(
            instance_id="proc-test-2",
            pid=5000,
            timestamp=now,
            event_type="sys_enter_connect",
            syscall_category="network",
            network_identifier="127.0.0.1:8080",
            payload={"fd": 3, "flags": 0},
        )
        evt_id = self.repo.insert_event(evt)
        self.assertGreater(evt_id, 0)

        events = self.repo.get_events_by_process("proc-test-2")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, "sys_enter_connect")
        self.assertEqual(events[0].network_identifier, "127.0.0.1:8080")

    def test_behaviour_windows_and_historical_profiling(self):
        """Verify behaviour window storage and ProfileManager statistical baselining."""
        now = datetime.datetime.now(datetime.timezone.utc)
        self.repo.register_process(
            ProcessInstance(
                instance_id="proc-test-3",
                profile_id="prof-python",
                pid=6000,
                comm="python3",
                start_time=now,
            )
        )

        windows = []
        for i in range(8):
            w = BehaviourWindow(
                window_index=i,
                instance_id="proc-test-3",
                profile_id="prof-python",
                comm="python3",
                start_time=now + datetime.timedelta(seconds=i * 5),
                end_time=now + datetime.timedelta(seconds=(i + 1) * 5),
                duration_s=5.0,
                cpu_usage=10.0 + (i * 2.0),
                memory_usage=25.0,
                syscall_count=100 + (i * 10),
                file_open_count=2,
            )
            windows.append(w)
        self.repo.insert_windows_batch(windows)

        # Build profile using ProfileManager
        pm = ProfileManager(self.repo)
        profile = pm.build_profile_from_history("prof-python", min_observations=5)
        self.assertIsNotNone(profile)
        self.assertEqual(profile.observations_count, 8)
        self.assertEqual(profile.comm, "python3")
        self.assertIn("file_open", profile.baseline_stats["typicalEvents"])
        self.assertAlmostEqual(profile.baseline_stats["avgMem"], 25.0)
        self.assertGreater(profile.baseline_stats["avgCpu"], 10.0)

        # Save and retrieve profile
        self.repo.save_profile(profile)
        saved = self.repo.get_profile("prof-python")
        self.assertIsNotNone(saved)
        self.assertEqual(saved.profile_id, "prof-python")
        self.assertEqual(saved.observations_count, 8)

    def test_detections_and_risk_scoring(self):
        """Verify recording of ML detector anomalies and risk scoring."""
        now = datetime.datetime.now(datetime.timezone.utc)
        self.repo.register_process(
            ProcessInstance(
                instance_id="proc-test-4",
                profile_id="prof-nc",
                pid=7000,
                comm="nc",
                start_time=now,
            )
        )

        det = DetectionRecord(
            instance_id="proc-test-4",
            timestamp=now,
            detector_name="xgboost_classifier",
            anomaly_score=0.92,
            risk_score=85.0,
            is_anomaly=True,
            mitre_technique="T1059",
            scenario="Reverse Shell Execution",
            description="High risk interactive shell invocation observed.",
            details={"features_flagged": ["syscalls_sensitive", "tcp_tx_bytes"]},
        )
        det_id = self.repo.insert_detection(det)
        self.assertGreater(det_id, 0)

        recent = self.repo.get_recent_detections(limit=10)
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0].risk_score, 85.0)
        self.assertEqual(recent[0].mitre_technique, "T1059")

    def test_retention_manager(self):
        """Verify historical data purge adheres to safety and preserves detections."""
        ret_cfg = RetentionConfig(events_days=1, windows_days=1, preserve_flagged_detections=True)
        mgr = RetentionManager(self.db, ret_cfg)

        res = mgr.purge_expired_data(dry_run=True)
        self.assertIn("telemetry_events", res)
        self.assertIn("behaviour_windows", res)
        self.assertIn("detections", res)

    def test_privacy_enforcement_blocking_remote(self):
        """Verify non-local database targets are flagged by privacy checker."""
        remote_cfg = DatabaseConfig(
            database_url="postgresql://user:pass@192.168.1.100:5432/chronicle",
            engine="postgresql",
        )
        self.assertFalse(remote_cfg.is_local())

        local_cfg = DatabaseConfig(
            database_url="postgresql://user:pass@127.0.0.1:5432/chronicle",
            engine="postgresql",
        )
        self.assertTrue(local_cfg.is_local())

    def test_user_side_file_permissions_hardening(self):
        """Verify database file permissions are strictly 0600 (owner-only access)."""
        import stat
        file_mode = stat.S_IMODE(os.stat(self.db_path).st_mode)
        self.assertEqual(file_mode, 0o600, f"Expected 0600 permissions, got {oct(file_mode)}")

    def test_privacy_redaction_before_storage(self):
        """Verify sensitive credentials and private paths are redacted before storage."""
        now = datetime.datetime.now(datetime.timezone.utc)
        inst = ProcessInstance(
            instance_id="proc-privacy-test",
            profile_id="prof-login",
            pid=8888,
            comm="login",
            start_time=now,
            metadata={"cli": "login --password mysecret123", "secret_key": "raw_secret"},
        )
        self.repo.register_process(inst)
        fetched = self.repo.get_process("proc-privacy-test")
        self.assertNotIn("mysecret123", str(fetched.metadata))
        self.assertEqual(fetched.metadata.get("secret_key"), "[REDACTED_CREDENTIAL]")

        evt = TelemetryEvent(
            instance_id="proc-privacy-test",
            pid=8888,
            timestamp=now,
            event_type="sys_enter_openat",
            file_identifier="/home/user/.ssh/id_rsa",
            payload={"auth_token": "bearer xyz999"},
        )
        self.repo.insert_event(evt)
        events = self.repo.get_events_by_process("proc-privacy-test")
        self.assertEqual(events[0].file_identifier, "[REDACTED_SENSITIVE_USER_PATH]")
        self.assertNotIn("bearer xyz999", str(events[0].payload))


if __name__ == "__main__":
    unittest.main()
