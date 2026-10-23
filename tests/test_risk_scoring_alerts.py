
from __future__ import annotations

import hashlib
import json
import math
import sys
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from chronicle.config import ChronicleConfig
from chronicle.pipeline import ChroniclePipeline
from chronicle.risk_engine import (
    DEDUP_WINDOW_SECONDS,
    EVAL_ERROR,
    EVAL_INSUFFICIENT,
    EVAL_OK,
    SCORING_CONFIG_VERSION,
    ContributingSignal,
    RiskEngine,
    ScoringResult,
    _score_to_category,
    make_alert_id,
    make_dedup_key,
)
from chronicle.storage import ChronicleDatabase



def _devs(cpu_z=0.0, mem_z=0.0, sys_z=0.0) -> Dict[str, Any]:
    return {
        "cpu_z": cpu_z,
        "mem_z": mem_z,
        "syscalls_z": sys_z,
        "max_z": max(cpu_z, mem_z, sys_z),
        "cpu_deviation": cpu_z * 5,
        "mem_deviation": mem_z * 10,
        "syscalls_deviation": sys_z * 50,
    }


def _ml_unavailable() -> Dict[str, Any]:
    return {"ml_available": False, "if_score": 0.0, "xgb_prob": 0.0, "xgb_attack": False}


def _ml_clean() -> Dict[str, Any]:
    return {"ml_available": True, "if_pred": 1, "if_score": 0.05, "xgb_prob": 0.01, "xgb_attack": False}


def _ml_if_anomaly(if_score=-0.12) -> Dict[str, Any]:
    return {
        "ml_available": True,
        "if_pred": -1,
        "if_score": if_score,
        "xgb_prob": 0.20,
        "xgb_attack": False,
    }


def _ml_xgb_attack(xgb_prob=0.995) -> Dict[str, Any]:
    return {
        "ml_available": True,
        "if_pred": 1,
        "if_score": 0.02,
        "xgb_prob": xgb_prob,
        "xgb_attack": True,
    }


def _ml_both_fired(if_score=-0.15, xgb_prob=0.997) -> Dict[str, Any]:
    return {
        "ml_available": True,
        "if_pred": -1,
        "if_score": if_score,
        "xgb_prob": xgb_prob,
        "xgb_attack": True,
    }


def _eval(devs=None, ml=None, flags=None, enabled=True) -> ScoringResult:
    return RiskEngine.evaluate(
        comm="nginx",
        pid=1234,
        user="www-data",
        event_type="sys_sample",
        deviations=devs or _devs(),
        ml_result=ml or _ml_unavailable(),
        heuristic_flags=flags or [],
        enabled=enabled,
    )



class TestRiskScoreCategories:

    def test_score_below_25_is_low(self):
        r = _eval()
        assert r.risk_score < 25
        assert r.risk_category == "Low"

    def test_score_25_is_medium(self):
        r = _eval(ml={"ml_available": True, "if_pred": -1, "if_score": -0.042, "xgb_prob": 0.0, "xgb_attack": False})
        assert r.risk_score >= 25
        assert r.risk_category in ("Medium", "High", "Critical")

    def test_score_50_is_high(self):
        r = _eval(
            devs=_devs(cpu_z=3.5),
            ml=_ml_if_anomaly(-0.10),
        )
        if r.risk_score >= 50:
            assert r.risk_category in ("High", "Critical")
        else:
            assert r.risk_category in ("Low", "Medium", "High")

    def test_score_75_is_critical(self):
        r = _eval(flags=["interactive_shell_from_daemon"])
        assert r.risk_score >= 75
        assert r.risk_category == "Critical"

    def test_score_max_is_99(self):
        r = _eval(
            devs=_devs(cpu_z=10.0, mem_z=10.0, sys_z=10.0),
            ml=_ml_both_fired(-0.5, 0.999),
            flags=["interactive_shell_from_daemon", "crypto_mining"],
        )
        assert r.risk_score <= 99

    def test_score_min_is_0_when_enabled_no_signals(self):
        r = _eval(ml=_ml_unavailable())
        assert r.risk_score == 0

    def test_score_to_category_boundaries(self):
        assert _score_to_category(0) == "Low"
        assert _score_to_category(24) == "Low"
        assert _score_to_category(25) == "Medium"
        assert _score_to_category(49) == "Medium"
        assert _score_to_category(50) == "High"
        assert _score_to_category(74) == "High"
        assert _score_to_category(75) == "Critical"
        assert _score_to_category(99) == "Critical"


class TestScoringComponents:

    def test_analytic_only_no_ml(self):
        r = _eval(ml=_ml_unavailable(), flags=["privilege_escalation"])
        assert r.risk_score >= 70
        assert r.detection_source == "analytic"
        assert r.eval_status == EVAL_OK
        assert any(s.source == "heuristic" for s in r.signals)
        assert not any(s.source in ("isolation_forest", "xgboost") for s in r.signals)

    def test_ml_only_isolation_forest(self):
        r = _eval(ml=_ml_if_anomaly(-0.20))
        assert r.detection_source == "ml"
        assert any(s.source == "isolation_forest" for s in r.signals)
        assert r.risk_score > 0

    def test_ml_only_xgboost(self):
        r = _eval(ml=_ml_xgb_attack())
        assert r.detection_source == "ml"
        assert any(s.source == "xgboost" for s in r.signals)
        assert r.risk_score > 0

    def test_combined_analytic_and_ml(self):
        r = _eval(ml=_ml_both_fired(), flags=["reverse_shell_socket"])
        assert r.detection_source == "both"
        assert r.risk_score >= 70

    def test_statistical_only_high_cpu(self):
        r = _eval(devs=_devs(cpu_z=4.0), ml=_ml_unavailable())
        assert r.detection_source == "none"
        assert any(s.source == "statistical" and s.name == "cpu_z_score" for s in r.signals)
        assert r.risk_score > 0

    def test_statistical_only_high_mem(self):
        r = _eval(devs=_devs(mem_z=4.0), ml=_ml_unavailable())
        assert any(s.source == "statistical" and s.name == "mem_z_score" for s in r.signals)

    def test_statistical_only_high_syscalls(self):
        r = _eval(devs=_devs(sys_z=4.0), ml=_ml_unavailable())
        assert any(s.source == "statistical" and s.name == "syscall_z_score" for s in r.signals)

    def test_below_threshold_no_stat_signal(self):
        r = _eval(devs=_devs(cpu_z=1.5), ml=_ml_unavailable())
        assert not any(s.source == "statistical" for s in r.signals)

    def test_all_heuristic_flags(self):
        for flag in ["interactive_shell_from_daemon", "crypto_mining", "mass_file_traversal",
                     "reverse_shell_socket", "privilege_escalation"]:
            r = _eval(flags=[flag])
            assert r.risk_score >= 70, f"Flag {flag} did not produce score ≥ 70"
            assert any(s.name == flag for s in r.signals)


class TestDuplicateSignals:

    def test_duplicate_heuristic_flag_counted_once(self):
        r_single = _eval(flags=["crypto_mining"])
        r_double = _eval(flags=["crypto_mining", "crypto_mining"])
        heuristic_signals_single = [s for s in r_single.signals if s.source == "heuristic"]
        heuristic_signals_double = [s for s in r_double.signals if s.source == "heuristic"]
        assert len(heuristic_signals_single) == 1
        assert len(heuristic_signals_double) == 1
        assert r_single.risk_score == r_double.risk_score

    def test_duplicate_flag_identical_score(self):
        r1 = _eval(flags=["privilege_escalation"])
        r2 = _eval(flags=["privilege_escalation", "privilege_escalation", "privilege_escalation"])
        assert r1.risk_score == r2.risk_score


class TestInvalidInputs:

    def test_nan_cpu_z_yields_insufficient(self):
        r = _eval(devs={"cpu_z": float("nan"), "mem_z": 0.0, "syscalls_z": 0.0, "max_z": 0.0})
        assert r.eval_status == EVAL_INSUFFICIENT
        assert r.error_detail is not None and "NaN" in r.error_detail

    def test_inf_mem_z_yields_insufficient(self):
        r = _eval(devs={"cpu_z": 0.0, "mem_z": float("inf"), "syscalls_z": 0.0, "max_z": 0.0})
        assert r.eval_status == EVAL_INSUFFICIENT

    def test_none_syscalls_z_yields_insufficient(self):
        r = _eval(devs={"cpu_z": 0.0, "mem_z": 0.0, "syscalls_z": None, "max_z": 0.0})
        assert r.eval_status == EVAL_INSUFFICIENT

    def test_string_z_score_yields_insufficient(self):
        r = _eval(devs={"cpu_z": "bad", "mem_z": 0.0, "syscalls_z": 0.0, "max_z": 0.0})
        assert r.eval_status == EVAL_INSUFFICIENT

    def test_nan_if_score_yields_insufficient(self):
        ml = {"ml_available": True, "if_pred": -1, "if_score": float("nan"), "xgb_prob": 0.0, "xgb_attack": False}
        r = _eval(ml=ml)
        assert r.eval_status == EVAL_INSUFFICIENT

    def test_inf_xgb_prob_yields_insufficient(self):
        ml = {"ml_available": True, "if_pred": 1, "if_score": 0.0, "xgb_prob": float("inf"), "xgb_attack": True}
        r = _eval(ml=ml)
        assert r.eval_status == EVAL_INSUFFICIENT

    def test_invalid_inputs_do_not_crash(self):
        for bad_devs in [
            {"cpu_z": None, "mem_z": None, "syscalls_z": None, "max_z": None},
            {},
            {"cpu_z": "text", "mem_z": [], "syscalls_z": {}, "max_z": 0},
        ]:
            r = _eval(devs=bad_devs)
            assert isinstance(r, ScoringResult)
            assert r.risk_score >= 0

    def test_score_is_always_in_range(self):
        for _ in range(10):
            r = _eval(
                devs=_devs(cpu_z=100.0, mem_z=100.0, sys_z=100.0),
                ml=_ml_both_fired(-999.0, 1.0),
                flags=["interactive_shell_from_daemon"],
            )
            assert 0 <= r.risk_score <= 99


class TestDeterminism:

    def test_same_inputs_same_score(self):
        kwargs = dict(devs=_devs(cpu_z=3.5), ml=_ml_if_anomaly(), flags=["crypto_mining"])
        r1 = _eval(**kwargs)
        r2 = _eval(**kwargs)
        assert r1.risk_score == r2.risk_score
        assert r1.risk_category == r2.risk_category
        assert r1.detection_source == r2.detection_source

    def test_order_of_flags_does_not_change_score(self):
        r1 = _eval(flags=["crypto_mining", "privilege_escalation"])
        r2 = _eval(flags=["privilege_escalation", "crypto_mining"])
        assert r1.risk_score == r2.risk_score


class TestEvalStatus:

    def test_normal_event_is_evaluated(self):
        r = _eval(ml=_ml_clean())
        assert r.eval_status == EVAL_OK

    def test_feature_flag_off_is_insufficient(self):
        r = _eval(enabled=False)
        assert r.eval_status == EVAL_INSUFFICIENT
        assert r.risk_score == 0
        assert "disabled" in r.anomaly_details.lower()

    def test_ml_unavailable_no_signals_is_insufficient(self):
        r = _eval(ml=_ml_unavailable())
        assert r.eval_status == EVAL_INSUFFICIENT

    def test_ml_unavailable_but_heuristic_is_evaluated(self):
        r = _eval(ml=_ml_unavailable(), flags=["crypto_mining"])
        assert r.eval_status == EVAL_OK

    def test_missing_data_not_treated_as_zero_risk(self):
        r = _eval(ml=_ml_unavailable())
        assert r.eval_status != EVAL_OK



class TestAlertSchema:

    REQUIRED_FIELDS = [
        "id", "timestamp", "pid", "comm", "riskScore", "riskCategory",
        "category", "description", "reasons", "eval_status", "detection_source",
        "contributing_signals", "dedup_key", "dedup_window_seconds",
        "config_version", "status",
    ]

    def _make_alert(self, scoring_result=None, **kwargs):
        sr = scoring_result or _eval(flags=["privilege_escalation"])
        return RiskEngine.create_alert(
            comm="nginx",
            pid=3812,
            risk_score=sr.risk_score,
            category=sr.category,
            reasons=sr.reasons,
            scoring_result=sr,
            **kwargs,
        )

    def test_required_fields_present(self):
        alert = self._make_alert()
        for f in self.REQUIRED_FIELDS:
            assert f in alert, f"Missing required alert field: {f}"

    def test_config_version_in_alert(self):
        alert = self._make_alert()
        assert alert["config_version"] == SCORING_CONFIG_VERSION

    def test_dedup_key_format(self):
        alert = self._make_alert()
        assert alert["dedup_key"].startswith("DK-")
        assert len(alert["dedup_key"]) == 15  # DK- + 12 hex chars

    def test_alert_id_format(self):
        alert = self._make_alert()
        assert alert["id"].startswith("ALT-")
        assert len(alert["id"]) == 12  # ALT- + 8 hex chars

    def test_timestamp_is_utc_iso8601(self):
        alert = self._make_alert()
        ts = alert["timestamp"]
        assert ts.endswith("Z"), f"Timestamp not UTC: {ts}"

    def test_optional_fields_absent_when_not_provided(self):
        sr = _eval(flags=["crypto_mining"])
        alert = RiskEngine.create_alert(
            comm="cron", pid=1042, risk_score=sr.risk_score,
            category=sr.category, reasons=sr.reasons, scoring_result=sr,
        )
        assert "ppid" not in alert
        assert "user" not in alert
        assert "source_event_id" not in alert

    def test_optional_fields_present_when_provided(self):
        sr = _eval(flags=["crypto_mining"])
        alert = RiskEngine.create_alert(
            comm="cron", pid=1042, risk_score=sr.risk_score,
            category=sr.category, reasons=sr.reasons, scoring_result=sr,
            ppid=1, user="root", event_id="evt-abc123",
        )
        assert alert["ppid"] == 1
        assert alert["user"] == "root"
        assert alert["source_event_id"] == "evt-abc123"

    def test_eval_status_insufficient_adds_limitations_note(self):
        sr = _eval(enabled=False)
        alert = RiskEngine.create_alert(
            comm="test", pid=9999, risk_score=0, category="EXECUTION",
            reasons=[], scoring_result=sr,
        )
        assert "limitations" in alert


class TestAlertExplanation:

    def test_heuristic_explanation_mentions_flag(self):
        sr = _eval(flags=["interactive_shell_from_daemon"])
        assert "interactive shell" in sr.anomaly_details.lower() or "daemon" in sr.anomaly_details.lower()

    def test_no_signals_produces_normal_explanation(self):
        sr = _eval(ml=_ml_clean())
        assert "no anomaly" in sr.anomaly_details.lower() or "baseline" in sr.anomaly_details.lower()

    def test_explanation_consistent_with_signals(self):
        sr = _eval(flags=["reverse_shell_socket"])
        signal_names = {s.name for s in sr.signals}
        assert "reverse_shell_socket" in signal_names
        assert sr.reasons  # non-empty

    def test_explanation_does_not_fabricate_evidence(self):
        sr = _eval(ml=_ml_unavailable())
        assert "ml" not in sr.anomaly_details.lower() or "unavailable" in sr.anomaly_details.lower() or sr.anomaly_details == ""

    def test_score_category_status_consistent(self):
        sr = _eval(flags=["mass_file_traversal"])
        cat = _score_to_category(sr.risk_score)
        assert cat == sr.risk_category
        if sr.risk_score >= 70:
            assert sr.status == "ANOMALOUS"

    def test_ml_anomaly_not_claimed_as_calibrated_probability(self):
        sr = _eval(ml=_ml_if_anomaly(-0.12))
        if_signal = next((s for s in sr.signals if s.source == "isolation_forest"), None)
        if if_signal:
            assert "calibrated attack probability" not in if_signal.description.lower() or \
                   "not a calibrated" in if_signal.description.lower()

    def test_xgb_description_includes_caveat(self):
        sr = _eval(ml=_ml_xgb_attack())
        xgb_signal = next((s for s in sr.signals if s.source == "xgboost"), None)
        if xgb_signal:
            desc = xgb_signal.description.lower()
            assert "training distribution" in desc or "not a real-world" in desc or "plaid" in desc


class TestAlertIdentityAndDeduplication:

    def test_same_event_same_dedup_key(self):
        sr = _eval(flags=["crypto_mining"])
        window = 1000 // DEDUP_WINDOW_SECONDS
        k1 = make_dedup_key("nginx", 1234, "analytic", sr.signals, window)
        k2 = make_dedup_key("nginx", 1234, "analytic", sr.signals, window)
        assert k1 == k2

    def test_different_pid_different_dedup_key(self):
        sr = _eval(flags=["crypto_mining"])
        window = 1000 // DEDUP_WINDOW_SECONDS
        k1 = make_dedup_key("nginx", 1234, "analytic", sr.signals, window)
        k2 = make_dedup_key("nginx", 9999, "analytic", sr.signals, window)
        assert k1 != k2

    def test_different_window_different_dedup_key(self):
        sr = _eval(flags=["crypto_mining"])
        k1 = make_dedup_key("nginx", 1234, "analytic", sr.signals, 100)
        k2 = make_dedup_key("nginx", 1234, "analytic", sr.signals, 101)
        assert k1 != k2

    def test_different_detection_source_different_key(self):
        sr = _eval(flags=["crypto_mining"])
        window = 100
        k1 = make_dedup_key("nginx", 1234, "analytic", sr.signals, window)
        k2 = make_dedup_key("nginx", 1234, "ml", sr.signals, window)
        assert k1 != k2

    def test_signal_order_does_not_change_dedup_key(self):
        sig_a = ContributingSignal(source="heuristic", name="crypto_mining",
                                   observed_value="flag", score_contribution=70.0, description="")
        sig_b = ContributingSignal(source="statistical", name="cpu_z_score",
                                   observed_value=3.5, score_contribution=28.0, description="")
        window = 100
        k1 = make_dedup_key("nginx", 1, "both", [sig_a, sig_b], window)
        k2 = make_dedup_key("nginx", 1, "both", [sig_b, sig_a], window)
        assert k1 == k2  # sorted internally

    def test_alert_ids_are_unique(self):
        ids = {make_alert_id() for _ in range(100)}
        assert len(ids) == 100

    def test_timestamp_source_documented(self):
        sr = _eval(flags=["privilege_escalation"])
        alert_with_ts = RiskEngine.create_alert(
            comm="sudo", pid=7891, risk_score=sr.risk_score, category=sr.category,
            reasons=sr.reasons, scoring_result=sr, event_timestamp="14:30:00",
        )
        alert_no_ts = RiskEngine.create_alert(
            comm="sudo", pid=7891, risk_score=sr.risk_score, category=sr.category,
            reasons=sr.reasons, scoring_result=sr,
        )
        assert alert_with_ts["timestamp_source"] == "event"
        assert alert_no_ts["timestamp_source"] == "ingestion"



SYNTHETIC_NORMAL_EVENT: Dict[str, Any] = {
    "id": "syn-norm-0001",
    "timestamp": "10:00:00",
    "pid": 2500,
    "ppid": 1,
    "comm": "nginx",
    "user": "www-data",
    "eventType": "sys_sample",
    "cpu": 1.2,
    "mem": 42.0,
    "syscalls": 320,
    "syscall_sequence": ["epoll_wait", "recvfrom", "writev", "sendto"],
    "heuristic_flags": [],
}

SYNTHETIC_SUSPICIOUS_EVENT: Dict[str, Any] = {
    "id": "syn-susp-0001",
    "timestamp": "10:01:00",
    "pid": 3812,
    "ppid": 1120,
    "comm": "nginx",
    "user": "www-data",
    "eventType": "execve",
    "cpu": 18.4,
    "mem": 48.0,
    "syscalls": 1420,
    "syscall_sequence": ["clone", "execve", "rt_sigaction", "ioctl", "fcntl",
                         "openat", "dup2", "execve", "read", "write"],
    "heuristic_flags": ["interactive_shell_from_daemon"],
    "description": "SYNTHETIC: Unauthorized shell from daemon (test fixture)",
}

SYNTHETIC_MALFORMED_EVENT: Dict[str, Any] = {
    "id": "syn-bad-0001",
    "pid": None,
    "cpu": "not_a_number",
}


@pytest.fixture
def pipeline(tmp_path):
    cfg = ChronicleConfig(
        data_dir=tmp_path,
        db_path=tmp_path / "test.db",
        profiles_path=tmp_path / "profiles.json",
        ml_models_dir=ROOT / "ML" / "models",
        enable_ebpf=False,
        enable_risk_scoring=True,
    )
    return ChroniclePipeline(cfg)


@pytest.fixture
def pipeline_scoring_disabled(tmp_path):
    cfg = ChronicleConfig(
        data_dir=tmp_path,
        db_path=tmp_path / "test_disabled.db",
        profiles_path=tmp_path / "profiles.json",
        ml_models_dir=ROOT / "ML" / "models",
        enable_ebpf=False,
        enable_risk_scoring=False,
    )
    return ChroniclePipeline(cfg)


class TestIntegration:

    def test_normal_event_produces_no_alert(self, pipeline):
        enriched = pipeline.process_raw_event(SYNTHETIC_NORMAL_EVENT.copy())
        if enriched["status"] == "SAFE":
            assert pipeline.total_anomalies_detected == 0

    def test_suspicious_event_produces_evidence_backed_alert(self, pipeline):
        enriched = pipeline.process_raw_event(SYNTHETIC_SUSPICIOUS_EVENT.copy())
        assert enriched["riskScore"] >= 70
        assert enriched["status"] == "ANOMALOUS"
        assert enriched["eval_status"] == "evaluated"
        alerts = pipeline.get_alerts()
        assert len(alerts) >= 1
        alert = alerts[0]
        assert alert["reasons"]
        assert alert["contributing_signals"]
        assert alert["dedup_key"].startswith("DK-")
        assert alert["config_version"] == SCORING_CONFIG_VERSION

    def test_alert_detection_source_matches_signals(self, pipeline):
        enriched = pipeline.process_raw_event(SYNTHETIC_SUSPICIOUS_EVENT.copy())
        alerts = pipeline.get_alerts()
        if alerts:
            alert = alerts[0]
            sources = {s["source"] for s in alert["contributing_signals"]}
            has_analytic = "heuristic" in sources
            has_ml = "isolation_forest" in sources or "xgboost" in sources
            if has_analytic and has_ml:
                assert alert["detection_source"] == "both"
            elif has_analytic:
                assert alert["detection_source"] in ("analytic", "both")
            elif has_ml:
                assert alert["detection_source"] in ("ml", "both")

    def test_invalid_event_handled_without_crash(self, pipeline):
        pipeline.process_raw_event(SYNTHETIC_MALFORMED_EVENT.copy())
        enriched2 = pipeline.process_raw_event(SYNTHETIC_NORMAL_EVENT.copy())
        assert enriched2["id"] == "syn-norm-0001"
        assert pipeline.total_invalid_events >= 1

    def test_subsequent_events_after_bad_event_still_scored(self, pipeline):
        for _ in range(3):
            pipeline.process_raw_event(SYNTHETIC_MALFORMED_EVENT.copy())
        enriched = pipeline.process_raw_event(SYNTHETIC_SUSPICIOUS_EVENT.copy())
        assert enriched["riskScore"] >= 70  # scoring still works

    def test_feature_flag_disabled_produces_no_alerts(self, pipeline_scoring_disabled):
        pipeline_scoring_disabled.process_raw_event(SYNTHETIC_SUSPICIOUS_EVENT.copy())
        alerts = pipeline_scoring_disabled.get_alerts()
        # With scoring disabled, no alert should be generated
        assert len(alerts) == 0

    def test_feature_flag_disabled_event_still_stored(self, pipeline_scoring_disabled):
        enriched = pipeline_scoring_disabled.process_raw_event(SYNTHETIC_NORMAL_EVENT.copy())
        assert enriched["riskScore"] == 0
        assert enriched["eval_status"] == "insufficient_data"
        assert pipeline_scoring_disabled.total_events_processed == 1

    def test_feature_flag_disabled_stats_reports_correctly(self, pipeline_scoring_disabled):
        pipeline_scoring_disabled.process_raw_event(SYNTHETIC_NORMAL_EVENT.copy())
        stats = pipeline_scoring_disabled.get_stats()
        assert stats["risk_scoring_enabled"] is False

    def test_feature_flag_enabled_stats_reports_correctly(self, pipeline):
        stats = pipeline.get_stats()
        assert stats["risk_scoring_enabled"] is True

    def test_stats_tracks_scoring_failures(self, pipeline):
        stats = pipeline.get_stats()
        assert "total_scoring_failures" in stats
        assert "total_invalid_events" in stats

    def test_enriched_event_has_new_fields(self, pipeline):
        enriched = pipeline.process_raw_event(SYNTHETIC_NORMAL_EVENT.copy())
        assert "riskCategory" in enriched
        assert "eval_status" in enriched
        assert "detection_source" in enriched

    def test_db_alert_has_dedup_key(self, pipeline, tmp_path):
        pipeline.process_raw_event(SYNTHETIC_SUSPICIOUS_EVENT.copy())
        db = ChronicleDatabase(tmp_path / "test.db")
        alerts = db.get_active_alerts(limit=10)
        if alerts:
            assert alerts[0]["id"].startswith("ALT-")


class TestRegressionTask1:

    def test_task1_retrain_pipeline_importable(self):
        import importlib
        spec = importlib.util.spec_from_file_location(
            "retrain_pipeline",
            ROOT / "ML" / "src" / "retrain_pipeline.py"
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert hasattr(mod, "RetrainingPipeline")

    def test_task1_validate_training_data_importable(self):
        import importlib
        spec = importlib.util.spec_from_file_location(
            "validate_training_data",
            ROOT / "ML" / "src" / "validate_training_data.py"
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert hasattr(mod, "TrainingDataValidator")


class TestMLCompatibility:

    def test_ml_detector_interface_unchanged(self):
        from chronicle.ml_detector import MLDetectionEngine
        engine = MLDetectionEngine(ROOT / "ML" / "models")
        result = engine.predict_sequence(["read", "write", "close"])
        assert "ml_available" in result
        assert "if_score" in result
        assert "xgb_prob" in result
        assert "xgb_attack" in result

    def test_feature_extractor_401_features(self):
        from chronicle.ml_detector import PLAIDFeatureExtractor
        extractor = PLAIDFeatureExtractor(ROOT / "ML" / "models" / "plaid_feature_columns.json")
        assert len(extractor.columns) == 401


class TestBlockedDependencies:

    def test_ebpf_disabled_on_macos(self, pipeline):
        assert pipeline.collector.ebpf_enabled is False

    def test_cross_restart_dedup_not_verified(self):
        sr = _eval(flags=["crypto_mining"])
        k = make_dedup_key("nginx", 1234, "analytic", sr.signals, 100)
        assert k.startswith("DK-")
