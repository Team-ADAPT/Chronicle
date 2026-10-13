"""
Chronicle - Risk Scoring & Explainability Engine
Combines statistical deviations (Z-scores), ML anomaly inference,
and OS heuristics into a composite 0-100 risk score with explainable evidence.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


class RiskEngine:
    """Computes composite risk scores and contextual explainability evidence."""

    @staticmethod
    def evaluate(
        comm: str,
        pid: int,
        user: str,
        event_type: str,
        deviations: Dict[str, Any],
        ml_result: Dict[str, Any],
        heuristic_flags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        heuristic_flags = heuristic_flags or []
        reasons: List[str] = []
        base_score = 0.0

        cpu_z = deviations.get("cpu_z", 0.0)
        mem_z = deviations.get("mem_z", 0.0)
        sys_z = deviations.get("syscalls_z", 0.0)
        max_z = deviations.get("max_z", 0.0)

        # 1. Statistical Baselines (Z-Scores)
        if cpu_z > 3.0:
            base_score += min(35.0, cpu_z * 8.0)
            reasons.append(f"CPU utilization is {cpu_z:.1f}σ above 30-day historical baseline")
        elif cpu_z > 2.0:
            base_score += 15.0
            reasons.append(f"CPU utilization exceeds normal threshold (+{deviations.get('cpu_deviation', 0)}%)")

        if mem_z > 3.5:
            base_score += min(25.0, mem_z * 6.0)
            reasons.append(f"Memory footprint is {mem_z:.1f}σ above historical envelope")

        if sys_z > 3.0:
            base_score += min(30.0, sys_z * 7.0)
            reasons.append(f"Kernel syscall frequency is {sys_z:.1f}σ above rolling mean")

        # 2. Machine Learning Anomaly Detection (Isolation Forest & XGBoost)
        if ml_result.get("ml_available"):
            if ml_result.get("if_pred") == -1 or ml_result.get("if_score", 0.0) < 0.0:
                score_pen = min(35.0, abs(ml_result.get("if_score", 0.0)) * 120.0 + 20.0)
                base_score += score_pen
                reasons.append(
                    f"Unsupervised Isolation Forest detected anomalous syscall sequence (score: {ml_result.get('if_score')})"
                )

            if ml_result.get("xgb_attack"):
                xgb_prob = ml_result.get("xgb_prob", 0.0)
                base_score += min(45.0, xgb_prob * 45.0)
                reasons.append(
                    f"XGBoost attack classifier detected malicious telemetry signature (confidence: {xgb_prob * 100:.1f}%)"
                )

        # 3. Contextual OS Security Heuristics
        for flag in heuristic_flags:
            if flag == "interactive_shell_from_daemon":
                base_score += 75.0
                reasons.append(f"Unauthorized interactive shell spawned from daemon '{comm}'")
            elif flag == "crypto_mining":
                base_score += 70.0
                reasons.append("Sustained high compute threads with abnormal hash/math execution pattern")
            elif flag == "mass_file_traversal":
                base_score += 75.0
                reasons.append("Rapid mass file traversal with potential encryption intent (ransomware indicator)")
            elif flag == "reverse_shell_socket":
                base_score += 75.0
                reasons.append("Anomalous outbound socket connection initiated by background system utility")
            elif flag == "privilege_escalation":
                base_score += 70.0
                reasons.append("Unusual setuid/sudo invocation attempting privilege escalation")

        # Bound score between 5 (nominal jitter) and 99
        risk_score = int(min(99, max(5, round(base_score))))
        
        # Determine status
        if risk_score >= 70:
            status = "ANOMALOUS"
        elif risk_score >= 40:
            status = "SUSPICIOUS"
        else:
            status = "SAFE"

        # Rationale string
        if not reasons:
            anomaly_details = "Kernel telemetry conforms to rolling historical baseline envelope (±1.5σ). No anomalies detected."
        else:
            anomaly_details = " • ".join(reasons)

        # Determine category
        category = "EXECUTION"
        if "crypto" in "".join(reasons).lower():
            category = "RESOURCE_HIJACK"
        elif "socket" in "".join(reasons).lower() or "network" in "".join(reasons).lower():
            category = "COMMAND_AND_CONTROL"
        elif "file" in "".join(reasons).lower():
            category = "IMPACT"
        elif "privilege" in "".join(reasons).lower() or "shell" in "".join(reasons).lower():
            category = "PRIVILEGE_ESCALATION"

        return {
            "risk_score": risk_score,
            "status": status,
            "category": category,
            "reasons": reasons,
            "anomaly_details": anomaly_details,
        }

    @staticmethod
    def create_alert(
        comm: str,
        pid: int,
        risk_score: int,
        category: str,
        reasons: List[str],
        description: str = "",
    ) -> Dict[str, Any]:
        alert_id = f"ALT-{uuid.uuid4().hex[:6].upper()}"
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
        desc = description or (f"High-risk behavioral anomaly detected in process {comm} (PID: {pid})" if risk_score >= 70 else f"Suspicious deviation flagged in process {comm} (PID: {pid})")
        return {
            "id": alert_id,
            "timestamp": ts,
            "pid": pid,
            "comm": comm,
            "riskScore": risk_score,
            "category": category,
            "description": desc,
            "reasons": reasons,
            "status": "ACTIVE",
        }
