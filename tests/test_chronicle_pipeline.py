"""
Unit and integration tests for Chronicle Pipeline:
Observer (eBPF/psutil) -> DBMS (SQLite & Profiler) -> ML (Isolation Forest & XGBoost) -> Risk & Alerts -> API
"""
import json
import sys
from pathlib import Path

# Add project root and src to path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import unittest
from chronicle.api import ChronicleAPIHandler
from chronicle.config import ChronicleConfig
from chronicle.collector import TelemetryCollector, ATTACK_SYSCALL_PATTERNS
from chronicle.ml_detector import MLDetectionEngine, PLAIDFeatureExtractor
from chronicle.pipeline import ChroniclePipeline
from chronicle.risk_engine import RiskEngine
from chronicle.storage import ChronicleDatabase, OnlineMetric, ProcessProfile


def test_online_metric_welford():
    """Verify Welford's algorithm mean, variance, and Z-score calculations."""
    m = OnlineMetric()
    data = [10.0, 12.0, 14.0, 16.0, 18.0]
    for x in data:
        m.update(x)

    assert m.count == 5
    assert m.mean == 14.0
    assert m.variance == 10.0
    assert abs(m.std - 3.1622) < 0.001
    # Test Z-Score
    z = m.z_score(20.3244)
    assert abs(z - 2.0) < 0.01


def test_process_profile_deviations():
    """Verify historical baseline deviations."""
    prof = ProcessProfile("nginx", user="www-data")
    for _ in range(30):
        prof.update(cpu=1.5, mem=42.0, syscalls=320)

    # Normal sample
    normal_devs = prof.evaluate_deviations(cpu=1.6, mem=43.0, syscalls=325)
    assert normal_devs["max_z"] < 2.0

    # Anomalous burst sample
    anomaly_devs = prof.evaluate_deviations(cpu=15.0, mem=250.0, syscalls=5000)
    assert anomaly_devs["max_z"] > 3.0


def test_sqlite_storage(tmp_path):
    """Verify SQLite database CRUD operations."""
    db_file = tmp_path / "test_chronicle.db"
    db = ChronicleDatabase(db_file)

    ev = {
        "id": "evt-test-1",
        "timestamp": "12:00:00",
        "pid": 1234,
        "ppid": 1,
        "comm": "test_app",
        "user": "root",
        "eventType": "execve",
        "cpu": 2.5,
        "mem": 30.0,
        "syscalls": 100,
        "riskScore": 15,
        "status": "SAFE",
        "anomalyDetails": "Normal",
    }
    db.insert_event(ev)
    recent = db.get_recent_events(limit=10)
    assert len(recent) == 1
    assert recent[0]["comm"] == "test_app"

    alt = {
        "id": "ALT-001",
        "timestamp": "12:00:01",
        "pid": 1234,
        "comm": "test_app",
        "riskScore": 85,
        "category": "EXECUTION",
        "description": "Suspicious behavior",
        "reasons": ["High CPU", "Anomalous syscall"],
        "status": "ACTIVE",
    }
    db.insert_alert(alt)
    alerts = db.get_active_alerts(limit=10)
    assert len(alerts) == 1
    assert alerts[0]["id"] == "ALT-001"

    db.update_alert_status("ALT-001", "ACKNOWLEDGED")
    assert len(db.get_active_alerts(limit=10)) == 0

    db.insert_alert({**alt, "id": "ALT-002", "status": "ACTIVE"})
    db.insert_alert({**alt, "id": "ALT-003", "status": "ACTIVE"})
    assert db.update_active_alerts_status("ACKNOWLEDGED") == 2
    assert len(db.get_active_alerts(limit=10)) == 0


def test_plaid_feature_extraction():
    """Verify exact 401 feature vector extraction from syscall names."""
    cols_path = ROOT / "ML" / "models" / "plaid_feature_columns.json"
    extractor = PLAIDFeatureExtractor(cols_path)
    assert len(extractor.columns) == 401

    seq = ["openat", "read", "fstat", "close", "read", "write"]
    df = extractor.extract(seq)
    assert df.shape == (1, 401)
    assert df["seq_length"].iloc[0] == 6.0
    assert df["sc_openat_count"].iloc[0] == 1.0


def test_ml_detection_engine():
    """Verify ML engine inference with Isolation Forest and XGBoost."""
    ml = MLDetectionEngine(ROOT / "ML" / "models")
    assert ml.loaded is True

    # Test benign sequence
    benign_seq = ["epoll_wait", "recvfrom", "writev", "sendto"]
    res_benign = ml.predict_sequence(benign_seq)
    assert res_benign["ml_available"] is True
    assert "if_score" in res_benign
    assert "xgb_prob" in res_benign

    # Test attack sequence
    attack_seq = ATTACK_SYSCALL_PATTERNS["interactive_shell_from_daemon"]
    res_attack = ml.predict_sequence(attack_seq)
    assert res_attack["ml_available"] is True


def test_risk_engine():
    """Verify contextual risk scoring and explainability."""
    # 1. Nominal case
    res_safe = RiskEngine.evaluate(
        comm="nginx",
        pid=1000,
        user="www-data",
        event_type="sys_sample",
        deviations={"cpu_z": 0.2, "mem_z": 0.1, "syscalls_z": 0.3, "max_z": 0.3},
        ml_result={"ml_available": True, "if_pred": 1, "if_score": 0.05, "xgb_attack": False},
    )
    assert res_safe.risk_score < 40
    assert res_safe.status == "SAFE"
    assert res_safe.eval_status == "evaluated"

    # 2. Attack scenario with heuristics and high Z-score
    res_attack = RiskEngine.evaluate(
        comm="nginx",
        pid=3812,
        user="www-data",
        event_type="execve",
        deviations={"cpu_z": 4.5, "mem_z": 3.8, "syscalls_z": 5.2, "max_z": 5.2},
        ml_result={"ml_available": True, "if_pred": -1, "if_score": -0.15, "xgb_attack": True, "xgb_prob": 0.99},
        heuristic_flags=["interactive_shell_from_daemon"],
    )
    assert res_attack.risk_score >= 70
    assert res_attack.status == "ANOMALOUS"
    assert len(res_attack.reasons) >= 3
    assert "interactive shell" in res_attack.anomaly_details
    assert res_attack.eval_status == "evaluated"
    assert res_attack.detection_source == "both"
    assert res_attack.risk_category in ("High", "Critical")


def test_pipeline_and_api(tmp_path):
    """Verify complete end-to-end ChroniclePipeline and REST API handler."""
    cfg = ChronicleConfig(
        data_dir=tmp_path,
        db_path=tmp_path / "chronicle.db",
        profiles_path=tmp_path / "profiles.json",
        ml_models_dir=ROOT / "ML" / "models",
    )
    pipeline = ChroniclePipeline(cfg)
    api = ChronicleAPIHandler(pipeline)

    # 1. Test GET /api/status
    code, ctype, body = api.handle_request("GET", "/api/status")
    assert code == 200
    status_data = json.loads(body.decode())
    assert status_data["status"] == "healthy"
    assert status_data["ml_loaded"] is True

    # 2. Test GET /api/stats
    code, _, body = api.handle_request("GET", "/api/stats")
    assert code == 200
    stats = json.loads(body.decode())
    assert "normalcy_percent" in stats
    assert "cpu_percent" in stats

    # 3. Test POST /api/simulate
    req_body = json.dumps({"scenario": "webshell"}).encode()
    code, _, body = api.handle_request("POST", "/api/simulate", req_body)
    assert code == 200
    sim_data = json.loads(body.decode())
    assert sim_data["status"] == "success"
    assert sim_data["event"]["riskScore"] >= 70
    assert sim_data["event"]["status"] == "ANOMALOUS"

    # 4. Test GET /api/events
    code, _, body = api.handle_request("GET", "/api/events")
    assert code == 200
    events = json.loads(body.decode())
    assert len(events) >= 1
    assert events[0]["comm"] == "nginx"

    # 5. Test GET /api/alerts
    code, _, body = api.handle_request("GET", "/api/alerts")
    assert code == 200
    alerts = json.loads(body.decode())
    assert len(alerts) >= 1

    # 6. Test POST /api/kill
    target_pid = events[0]["pid"]
    req_kill = json.dumps({"pid": target_pid}).encode()
    code, _, body = api.handle_request("POST", "/api/kill", req_kill)
    assert code == 200

    # 7. Test POST /api/alerts/ack
    alert_id = alerts[0]["id"]
    req_ack = json.dumps({"id": alert_id}).encode()
    code, _, body = api.handle_request("POST", "/api/alerts/ack", req_ack)
    assert code == 200
    assert all(
        alert["id"] != alert_id
        for alert in pipeline.db.get_active_alerts(limit=50)
    )

    # 8. Test POST /api/alerts/ack-all persists acknowledgment for active alerts
    code, _, body = api.handle_request("POST", "/api/simulate", req_body)
    assert code == 200
    second_simulation = json.loads(body.decode())["event"]
    code, _, body = api.handle_request("POST", "/api/alerts/ack-all")
    assert code == 200
    ack_data = json.loads(body.decode())
    assert ack_data["status"] == "success"
    assert ack_data["acknowledged_count"] >= 1
    assert pipeline.db.get_active_alerts(limit=50) == []
    assert any(
        event["id"] == second_simulation["id"] and event["status"] == "ANOMALOUS"
        for event in pipeline.get_events()
    )


def test_process_history_query_and_api(tmp_path):
    """Verify historical CPU, RAM, Network telemetry retrieval from local DB via API."""
    db_file = tmp_path / "test_hist.db"
    db = ChronicleDatabase(db_file)
    hist = db.get_process_history("python3", days=7)
    assert hist["comm"] == "python3"
    assert len(hist["timeline"]) > 0
    assert "avg_cpu" in hist["summary"]
    assert "avg_mem" in hist["summary"]
    assert "avg_net_kb" in hist["summary"]

    cfg = ChronicleConfig(db_path=db_file, enable_ebpf=False)
    pipeline = ChroniclePipeline(cfg)
    api = ChronicleAPIHandler(pipeline)

    code, _, body = api.handle_request("GET", "/api/history?comm=nginx&days=3")
    assert code == 200
    data = json.loads(body.decode())
    assert data["comm"] == "nginx"
    assert data["days"] == 3
    assert len(data["timeline"]) > 0
    assert data["summary"]["peak_cpu"] >= 0.0


def test_process_cluster_classification():
    """Verify process clustering logic categorizes programs into correct architectural groups."""
    from chronicle.collector import classify_process_cluster
    assert classify_process_cluster("systemd", "root") == "systemd"
    assert classify_process_cluster("cron", "root") == "systemd"
    assert classify_process_cluster("udevd", "root") == "systemd"
    assert classify_process_cluster("nginx", "www-data") == "nginx"
    assert classify_process_cluster("sshd", "root") == "nginx"
    assert classify_process_cluster("curl", "anurag") == "nginx"
    assert classify_process_cluster("bash", "anurag") == "bash"
    assert classify_process_cluster("zsh", "anurag") == "bash"
    assert classify_process_cluster("python3", "anurag") == "bash"
    assert classify_process_cluster("dockerd", "root") == "dockerd"
    assert classify_process_cluster("containerd", "root") == "dockerd"
    assert classify_process_cluster("redis-server", "redis") == "dockerd"


if __name__ == "__main__":
    import tempfile
    print("Running Chronicle pipeline tests...")
    test_online_metric_welford()
    print("  ✓ test_online_metric_welford")
    test_process_profile_deviations()
    print("  ✓ test_process_profile_deviations")
    test_plaid_feature_extraction()
    print("  ✓ test_plaid_feature_extraction")
    test_ml_detection_engine()
    print("  ✓ test_ml_detection_engine")
    test_risk_engine()
    print("  ✓ test_risk_engine")
    with tempfile.TemporaryDirectory() as td:
        test_sqlite_storage(Path(td))
        print("  ✓ test_sqlite_storage")
        test_pipeline_and_api(Path(td))
        print("  ✓ test_pipeline_and_api")
        test_process_history_query_and_api(Path(td))
        print("  ✓ test_process_history_query_and_api")
    test_process_cluster_classification()
    print("  ✓ test_process_cluster_classification")
    print("All Chronicle pipeline & integration tests PASSED!")
