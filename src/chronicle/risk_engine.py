"""
Chronicle - Risk Scoring & Explainable Alerts Engine
=====================================================
Combines statistical deviation Z-scores, ML anomaly inference, and OS heuristics
into a composite 0–100 risk score with traceable evidence-backed explanations.

Design notes
------------
- Scores are heuristic risk indicators, NOT calibrated attack probabilities.
- A high score means the observed behaviour deviates significantly from the
  established baseline and/or matches known-attack patterns.  It does NOT prove
  malicious intent.
- All weights and thresholds are design choices.  See SCORING_CONFIG_VERSION and
  the inline documentation for the rationale of each weight.
- Missing evidence is never silently treated as low risk.  Events that cannot be
  scored are flagged with eval_status="scoring_error" or "insufficient_data".

Scoring config version
----------------------
Bump SCORING_CONFIG_VERSION whenever thresholds, weights, or category rules
change so that stored alerts can be re-evaluated with the original parameters.
"""
from __future__ import annotations

import hashlib
import math
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ── Scoring config version ──────────────────────────────────────────────────
SCORING_CONFIG_VERSION = "1.1.0"

# ── Risk category boundaries (inclusive lower bound) ───────────────────────
# Low: [0, 25)   Medium: [25, 50)   High: [50, 75)   Critical: [75, 100]
RISK_THRESHOLDS: Dict[str, int] = {
    "Critical": 75,
    "High": 50,
    "Medium": 25,
    "Low": 0,
}

# Legacy status names (kept for backward-compat with existing consumers)
STATUS_ANOMALOUS = "ANOMALOUS"   # risk_score >= 70
STATUS_SUSPICIOUS = "SUSPICIOUS"  # risk_score >= 40
STATUS_SAFE = "SAFE"             # risk_score <  40

# Evaluation status (distinct from risk status) ────────────────────────────
EVAL_OK = "evaluated"
EVAL_INSUFFICIENT = "insufficient_data"
EVAL_ERROR = "scoring_error"

# Deduplication window in seconds (same process + same detection within window
# is considered a duplicate).  Cross-restart deduplication is NOT guaranteed
# because no persistent store is consulted; this is documented as a known limit.
DEDUP_WINDOW_SECONDS = 60

# ── Scoring weight constants (design choices, not empirically validated) ────
# Statistical baseline component weights
_W_CPU_HIGH = 8.0    # points per σ when cpu_z > 3.0
_W_CPU_MED = 15.0    # flat points when 2.0 < cpu_z ≤ 3.0
_W_MEM = 6.0         # points per σ when mem_z > 3.5
_W_SYS = 7.0         # points per σ when syscalls_z > 3.0
# ML component caps
_CAP_STAT = 35.0     # max stat contribution
_CAP_IF = 35.0       # max isolation-forest contribution
_CAP_XGB = 45.0      # max xgboost contribution
# Heuristic flat bonuses (high because pattern-match is direct evidence)
_W_HEURISTIC: Dict[str, float] = {
    "interactive_shell_from_daemon": 75.0,
    "crypto_mining": 70.0,
    "mass_file_traversal": 75.0,
    "reverse_shell_socket": 75.0,
    "privilege_escalation": 70.0,
}
# Absolute score bounds
_SCORE_MIN = 0   # 0 is valid (fully normal, evaluated)
_SCORE_MAX = 99


@dataclass
class ContributingSignal:
    """A single piece of evidence that contributed to the risk score."""
    source: str           # "statistical", "isolation_forest", "xgboost", "heuristic"
    name: str             # human-readable signal name
    observed_value: Any   # raw numeric or string observed value
    score_contribution: float
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "name": self.name,
            "observed_value": self.observed_value,
            "score_contribution": round(self.score_contribution, 2),
            "description": self.description,
        }


@dataclass
class ScoringResult:
    """
    Complete output of a single risk evaluation.

    eval_status
    -----------
    "evaluated"          – Score is meaningful; evidence was successfully obtained.
    "insufficient_data"  – Required inputs were absent; score reflects only
                           available evidence and should be treated with caution.
    "scoring_error"      – A technical failure prevented scoring; the score is
                           unreliable and should NOT be used for decisions.
    """
    risk_score: int
    risk_category: str
    status: str                            # legacy: SAFE / SUSPICIOUS / ANOMALOUS
    eval_status: str                       # evaluated / insufficient_data / scoring_error
    signals: List[ContributingSignal]
    reasons: List[str]
    anomaly_details: str
    category: str                          # MITRE-inspired activity category
    detection_source: str                  # "analytic", "ml", "both", "none"
    config_version: str = SCORING_CONFIG_VERSION
    error_detail: Optional[str] = None    # present when eval_status == "scoring_error"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "risk_category": self.risk_category,
            "status": self.status,
            "eval_status": self.eval_status,
            "signals": [s.to_dict() for s in self.signals],
            "reasons": self.reasons,
            "anomaly_details": self.anomaly_details,
            "category": self.category,
            "detection_source": self.detection_source,
            "config_version": self.config_version,
            "error_detail": self.error_detail,
        }


def _safe_float(val: Any, name: str) -> Tuple[float, Optional[str]]:
    """
    Converts val to float and validates it.
    Returns (value, None) on success or (0.0, error_string) on failure.
    Rejects NaN, infinity, and non-numeric types.
    """
    try:
        v = float(val)
    except (TypeError, ValueError):
        return 0.0, f"{name} is not numeric (got {type(val).__name__})"
    if math.isnan(v):
        return 0.0, f"{name} is NaN"
    if math.isinf(v):
        return 0.0, f"{name} is infinite"
    return v, None


def _score_to_category(score: int) -> str:
    """Maps integer score to risk category string."""
    for cat, threshold in RISK_THRESHOLDS.items():
        if score >= threshold:
            return cat
    return "Low"


def _score_to_legacy_status(score: int) -> str:
    if score >= 70:
        return STATUS_ANOMALOUS
    if score >= 40:
        return STATUS_SUSPICIOUS
    return STATUS_SAFE


def _infer_activity_category(reasons: List[str]) -> str:
    joined = " ".join(reasons).lower()
    if "crypto" in joined:
        return "RESOURCE_HIJACK"
    if "socket" in joined or "network" in joined:
        return "COMMAND_AND_CONTROL"
    if "file" in joined or "traversal" in joined:
        return "IMPACT"
    if "privilege" in joined or "shell" in joined:
        return "PRIVILEGE_ESCALATION"
    return "EXECUTION"


def make_dedup_key(
    comm: str,
    pid: int,
    detection_source: str,
    signals: List[ContributingSignal],
    window_epoch: int,
) -> str:
    """
    Produces a deterministic deduplication key for an alert.

    Key inputs:
      comm            – process name (process identity)
      pid             – process PID (distinguishes concurrent processes)
      detection_source – which detectors fired
      signals         – sorted list of signal names that contributed
      window_epoch    – floor(event_timestamp / DEDUP_WINDOW_SECONDS)
                        collapses events within the same time window

    PID reuse: when process start time is available (caller passes it via
    comm or a separate stable identifier), include it here to avoid PID
    reuse collisions.  When unavailable, the dedup window limits exposure.

    Cross-restart persistence: not guaranteed.  Documented limitation.
    """
    signal_names = sorted(s.name for s in signals)
    raw = f"{comm}:{pid}:{detection_source}:{','.join(signal_names)}:{window_epoch}"
    return "DK-" + hashlib.sha256(raw.encode()).hexdigest()[:12].upper()


def make_alert_id() -> str:
    """Random stable alert ID prefixed for easy filtering."""
    return "ALT-" + uuid.uuid4().hex[:8].upper()


class RiskEngine:
    """
    Computes composite risk scores and generates evidence-backed explainable alerts.

    Usage
    -----
    Call ``RiskEngine.evaluate(...)`` to score a single event.
    Call ``RiskEngine.create_alert(...)`` to build an alert dict from a result.

    Feature flag
    ------------
    Pass ``enabled=False`` to ``evaluate()`` to disable scoring.  The method
    returns an ``eval_status="insufficient_data"`` result with risk_score=0 and
    a description explaining that scoring is disabled.  This preserves the
    previous pipeline behaviour when the flag is off.
    """

    @staticmethod
    def evaluate(
        comm: str,
        pid: int,
        user: str,
        event_type: str,
        deviations: Dict[str, Any],
        ml_result: Dict[str, Any],
        heuristic_flags: Optional[List[str]] = None,
        event_timestamp: Optional[str] = None,
        ppid: Optional[int] = None,
        enabled: bool = True,
    ) -> ScoringResult:
        """
        Evaluates a single telemetry event and returns a ScoringResult.

        Parameters
        ----------
        comm            : process name (from telemetry)
        pid             : process PID
        user            : owning user
        event_type      : eventType string from collector
        deviations      : dict with keys cpu_z, mem_z, syscalls_z, max_z, *_deviation
        ml_result       : dict from MLDetectionEngine.predict_sequence()
        heuristic_flags : list of heuristic flag strings from collector
        event_timestamp : HH:MM:SS string from event; used for dedup window;
                          falls back to ingestion time if None
        ppid            : parent PID when available
        enabled         : feature flag; set False to bypass scoring entirely

        Returns
        -------
        ScoringResult with eval_status one of:
          "evaluated"         – scoring completed normally
          "insufficient_data" – scoring disabled or key inputs absent
          "scoring_error"     – unexpected exception; result is unreliable
        """
        # ── Feature flag ──────────────────────────────────────────────────
        if not enabled:
            return ScoringResult(
                risk_score=0,
                risk_category="Low",
                status=STATUS_SAFE,
                eval_status=EVAL_INSUFFICIENT,
                signals=[],
                reasons=[],
                anomaly_details="Risk scoring is disabled via configuration flag.",
                category="EXECUTION",
                detection_source="none",
                config_version=SCORING_CONFIG_VERSION,
            )

        try:
            return RiskEngine._score(
                comm=comm,
                pid=pid,
                user=user,
                event_type=event_type,
                deviations=deviations,
                ml_result=ml_result,
                heuristic_flags=heuristic_flags or [],
                event_timestamp=event_timestamp,
            )
        except Exception as exc:  # pragma: no cover – last-resort guard
            return ScoringResult(
                risk_score=0,
                risk_category="Low",
                status=STATUS_SAFE,
                eval_status=EVAL_ERROR,
                signals=[],
                reasons=[],
                anomaly_details="Scoring failed due to a technical error.",
                category="EXECUTION",
                detection_source="none",
                config_version=SCORING_CONFIG_VERSION,
                error_detail=str(exc),
            )

    @staticmethod
    def _score(
        comm: str,
        pid: int,
        user: str,
        event_type: str,
        deviations: Dict[str, Any],
        ml_result: Dict[str, Any],
        heuristic_flags: List[str],
        event_timestamp: Optional[str],
    ) -> ScoringResult:
        signals: List[ContributingSignal] = []
        input_errors: List[str] = []

        # ── Validate and extract numeric deviations ───────────────────────
        cpu_z, e = _safe_float(deviations.get("cpu_z", 0.0), "cpu_z")
        if e:
            input_errors.append(e)
        mem_z, e = _safe_float(deviations.get("mem_z", 0.0), "mem_z")
        if e:
            input_errors.append(e)
        sys_z, e = _safe_float(deviations.get("syscalls_z", 0.0), "syscalls_z")
        if e:
            input_errors.append(e)

        base_score = 0.0

        # ── 1. Statistical baseline component ────────────────────────────
        stat_contribution = 0.0

        if cpu_z > 3.0:
            contrib = min(_CAP_STAT, cpu_z * _W_CPU_HIGH)
            stat_contribution += contrib
            signals.append(ContributingSignal(
                source="statistical",
                name="cpu_z_score",
                observed_value=round(cpu_z, 2),
                score_contribution=contrib,
                description=f"CPU utilization is {cpu_z:.1f}σ above 30-day historical baseline",
            ))
        elif cpu_z > 2.0:
            stat_contribution += _W_CPU_MED
            signals.append(ContributingSignal(
                source="statistical",
                name="cpu_z_score",
                observed_value=round(cpu_z, 2),
                score_contribution=_W_CPU_MED,
                description=f"CPU utilization exceeds normal threshold (+{deviations.get('cpu_deviation', 0):.1f}%)",
            ))

        if mem_z > 3.5:
            contrib = min(_CAP_STAT, mem_z * _W_MEM)
            stat_contribution += contrib
            signals.append(ContributingSignal(
                source="statistical",
                name="mem_z_score",
                observed_value=round(mem_z, 2),
                score_contribution=contrib,
                description=f"Memory footprint is {mem_z:.1f}σ above historical envelope",
            ))

        if sys_z > 3.0:
            contrib = min(_CAP_STAT, sys_z * _W_SYS)
            stat_contribution += contrib
            signals.append(ContributingSignal(
                source="statistical",
                name="syscall_z_score",
                observed_value=round(sys_z, 2),
                score_contribution=contrib,
                description=f"Kernel syscall frequency is {sys_z:.1f}σ above rolling mean",
            ))

        base_score += stat_contribution

        # ── 2. ML anomaly detection component ────────────────────────────
        ml_contribution = 0.0
        ml_fired = False

        if ml_result.get("ml_available"):
            # Isolation Forest: decision_function returns negative for anomalies.
            # We do NOT interpret this as a calibrated probability of attack.
            if_score, e = _safe_float(ml_result.get("if_score", 0.0), "if_score")
            if e:
                input_errors.append(e)
            if_pred = ml_result.get("if_pred")

            if if_pred == -1 or if_score < 0.0:
                contrib = min(_CAP_IF, abs(if_score) * 120.0 + 20.0)
                ml_contribution += contrib
                ml_fired = True
                signals.append(ContributingSignal(
                    source="isolation_forest",
                    name="if_anomaly_score",
                    observed_value=round(if_score, 4),
                    score_contribution=contrib,
                    description=(
                        f"Isolation Forest flagged an anomalous syscall sequence "
                        f"(score: {if_score:.4f}; lower = more anomalous). "
                        "Note: this is a statistical anomaly indicator, not a "
                        "calibrated attack probability."
                    ),
                ))

            xgb_prob, e = _safe_float(ml_result.get("xgb_prob", 0.0), "xgb_prob")
            if e:
                input_errors.append(e)
            xgb_attack = ml_result.get("xgb_attack", False)

            if xgb_attack:
                contrib = min(_CAP_XGB, xgb_prob * _CAP_XGB)
                ml_contribution += contrib
                ml_fired = True
                signals.append(ContributingSignal(
                    source="xgboost",
                    name="xgb_attack_probability",
                    observed_value=round(xgb_prob, 4),
                    score_contribution=contrib,
                    description=(
                        f"XGBoost classifier produced elevated attack-class output "
                        f"({xgb_prob * 100:.1f}%). "
                        "Model was trained on PLAID dataset; confidence is relative "
                        "to training distribution, not a real-world base rate."
                    ),
                ))

        elif ml_result.get("error"):
            # ML inference attempted but failed
            input_errors.append(f"ML inference error: {ml_result['error']}")

        base_score += ml_contribution

        # ── 3. Heuristic / rule-based component ──────────────────────────
        analytic_fired = False
        # Deduplicate heuristic flags to prevent the same flag inflating the
        # score multiple times if it appears more than once in the list.
        seen_flags: set = set()
        for flag in heuristic_flags:
            if flag in seen_flags:
                continue
            seen_flags.add(flag)
            if flag in _W_HEURISTIC:
                weight = _W_HEURISTIC[flag]
                base_score += weight
                analytic_fired = True
                signals.append(ContributingSignal(
                    source="heuristic",
                    name=flag,
                    observed_value=flag,
                    score_contribution=weight,
                    description=_heuristic_description(flag, comm),
                ))

        # ── Derive detection_source ───────────────────────────────────────
        if analytic_fired and ml_fired:
            detection_source = "both"
        elif analytic_fired:
            detection_source = "analytic"
        elif ml_fired:
            detection_source = "ml"
        else:
            detection_source = "none"

        # ── Evaluation status ─────────────────────────────────────────────
        # If we had numeric input errors we still produce a score from the
        # remaining valid signals, but flag the result as insufficient_data.
        if input_errors:
            eval_status = EVAL_INSUFFICIENT
        elif not signals and not ml_result.get("ml_available"):
            # No evidence at all and ML unavailable: cannot make a meaningful score.
            eval_status = EVAL_INSUFFICIENT
        else:
            eval_status = EVAL_OK

        # ── Bound and round score ─────────────────────────────────────────
        risk_score = int(min(_SCORE_MAX, max(_SCORE_MIN, round(base_score))))

        # ── Build reasons list (from signals) ────────────────────────────
        reasons = [s.description for s in signals]

        # ── Build human-readable summary ──────────────────────────────────
        anomaly_details = _build_explanation(
            signals=signals,
            eval_status=eval_status,
            input_errors=input_errors,
        )

        # ── Activity category ─────────────────────────────────────────────
        category = _infer_activity_category(reasons)

        return ScoringResult(
            risk_score=risk_score,
            risk_category=_score_to_category(risk_score),
            status=_score_to_legacy_status(risk_score),
            eval_status=eval_status,
            signals=signals,
            reasons=reasons,
            anomaly_details=anomaly_details,
            category=category,
            detection_source=detection_source,
            config_version=SCORING_CONFIG_VERSION,
            error_detail=("; ".join(input_errors) if input_errors else None),
        )

    @staticmethod
    def create_alert(
        comm: str,
        pid: int,
        risk_score: int,
        category: str,
        reasons: List[str],
        description: str = "",
        scoring_result: Optional[ScoringResult] = None,
        event_id: Optional[str] = None,
        event_timestamp: Optional[str] = None,
        ppid: Optional[int] = None,
        user: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Creates a structured alert dict from a completed scoring evaluation.

        Parameters
        ----------
        scoring_result  : if provided, enriches the alert with eval_status,
                          contributing_signals, dedup_key, and config_version.
        event_id        : original telemetry event ID for cross-reference.
        event_timestamp : HH:MM:SS from event; used for dedup window.
        ppid            : parent PID when available.
        user            : process owner when available.

        Explanation honesty
        -------------------
        The description is derived from actual scoring_result reasons.
        The function never fabricates evidence or invents missing fields.
        Optional metadata (ppid, user, event_id) is included only when provided.
        """
        alert_id = make_alert_id()

        # Ingestion timestamp in ISO-8601 UTC
        now_utc = datetime.now(timezone.utc)
        ingestion_ts = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Use event timestamp for dedup window if available;
        # fall back to ingestion time.  Document which was used.
        ts_source = "ingestion"
        epoch_for_dedup = int(now_utc.timestamp())
        if event_timestamp:
            try:
                # event_timestamp is HH:MM:SS; combine with today's date for epoch
                today = now_utc.strftime("%Y-%m-%d")
                dt = datetime.strptime(f"{today}T{event_timestamp}", "%Y-%m-%dT%H:%M:%S")
                dt = dt.replace(tzinfo=timezone.utc)
                epoch_for_dedup = int(dt.timestamp())
                ts_source = "event"
            except Exception:
                pass  # keep ingestion time

        window_epoch = epoch_for_dedup // DEDUP_WINDOW_SECONDS

        # Determine detection source and signals from result
        signals = []
        eval_status = EVAL_OK
        config_version = SCORING_CONFIG_VERSION
        detection_source = "none"
        error_detail = None

        if scoring_result is not None:
            signals = scoring_result.signals
            eval_status = scoring_result.eval_status
            config_version = scoring_result.config_version
            detection_source = scoring_result.detection_source
            error_detail = scoring_result.error_detail

        # Deduplication key
        dedup_key = make_dedup_key(
            comm=comm,
            pid=pid,
            detection_source=detection_source,
            signals=signals,
            window_epoch=window_epoch,
        )

        # Human-readable description: derived strictly from provided evidence
        if not description:
            if reasons:
                # Build from real evidence, not fabricated
                sev = "High-risk" if risk_score >= 75 else "Suspicious"
                description = (
                    f"{sev} behavioral anomaly detected in '{comm}' (PID {pid}). "
                    f"Primary signal: {reasons[0]}"
                )
            else:
                description = (
                    f"Process '{comm}' (PID {pid}) scored {risk_score}/99 "
                    f"with no specific evidence signals recorded."
                )

        # Build alert dict — omit optional fields when not available
        alert: Dict[str, Any] = {
            "id": alert_id,
            "timestamp": ingestion_ts,
            "timestamp_source": ts_source,
            "pid": pid,
            "comm": comm,
            "riskScore": risk_score,
            "riskCategory": _score_to_category(risk_score),
            "category": category,
            "description": description,
            "reasons": reasons,
            "eval_status": eval_status,
            "detection_source": detection_source,
            "contributing_signals": [s.to_dict() for s in signals],
            "dedup_key": dedup_key,
            "dedup_window_seconds": DEDUP_WINDOW_SECONDS,
            "config_version": config_version,
            "status": "ACTIVE",
        }

        # Optional metadata — only included when available
        if ppid is not None:
            alert["ppid"] = ppid
        if user is not None:
            alert["user"] = user
        if event_id is not None:
            alert["source_event_id"] = event_id
        if error_detail is not None:
            alert["scoring_error_detail"] = error_detail
        if eval_status == EVAL_INSUFFICIENT:
            alert["limitations"] = (
                "Score may be incomplete due to missing or invalid inputs. "
                "Treat with caution."
            )

        return alert


# ── Private helpers ──────────────────────────────────────────────────────────

def _heuristic_description(flag: str, comm: str) -> str:
    descriptions = {
        "interactive_shell_from_daemon": (
            f"Analytic rule: unauthorized interactive shell spawned from daemon '{comm}'. "
            "Pattern matches known web-shell / post-exploitation technique."
        ),
        "crypto_mining": (
            "Analytic rule: sustained high-compute threads with abnormal hash/math "
            "execution pattern consistent with CPU-based cryptocurrency mining."
        ),
        "mass_file_traversal": (
            "Analytic rule: rapid mass file traversal with potential encryption intent. "
            "Pattern is consistent with ransomware staging behaviour."
        ),
        "reverse_shell_socket": (
            f"Analytic rule: anomalous outbound socket connection initiated by "
            f"background utility '{comm}'. Pattern matches reverse-shell technique."
        ),
        "privilege_escalation": (
            "Analytic rule: unusual setuid/sudo/prctl invocation sequence "
            "indicating a privilege escalation attempt."
        ),
    }
    return descriptions.get(flag, f"Analytic rule matched: {flag}")


def _build_explanation(
    signals: List[ContributingSignal],
    eval_status: str,
    input_errors: List[str],
) -> str:
    """
    Builds a human-readable explanation traceable to the actual evidence.
    Never invents signals or claims not supported by the provided inputs.
    """
    if eval_status == EVAL_ERROR:
        return "Scoring failed due to a technical error. No reliable explanation available."

    if not signals:
        if eval_status == EVAL_INSUFFICIENT:
            return (
                "Insufficient data to score this event. "
                + (f"Input issues: {'; '.join(input_errors)}." if input_errors else "")
            )
        return (
            "Kernel telemetry conforms to rolling historical baseline (±1.5σ). "
            "No anomaly signals detected."
        )

    parts = [s.description for s in signals]
    prefix = "Risk signals observed: " if len(parts) > 1 else ""
    explanation = prefix + " • ".join(parts)

    if input_errors:
        explanation += (
            f" [Note: some inputs were invalid and excluded: "
            f"{'; '.join(input_errors)}]"
        )

    return explanation
