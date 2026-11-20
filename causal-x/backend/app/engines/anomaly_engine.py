from dataclasses import dataclass
from typing import Dict, List, Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sqlalchemy.orm import Session

from app.models.models import Anomaly, TelemetryRecord, TenantThreshold


@dataclass
class DetectedAnomalySpec:
    metric_name: str
    metric_value: float
    baseline_mean: Optional[float]
    baseline_std: Optional[float]
    detection_method: str  # rule | baseline | ml | combined
    severity: str
    description: str
    contributing_signals: Dict[str, float]


def detect_anomalies_for_record(
    db: Session,
    record: TelemetryRecord,
    thresholds: TenantThreshold,
) -> List[Anomaly]:
    """
    Two-layer AIOps anomaly detection:
    Layer 1: Configurable threshold & security-signal rules.
    Layer 2: Pandas/NumPy rolling baseline statistics + Scikit-learn IsolationForest
             (applied only once sufficient historical telemetry exists).
    """
    recent = (
        db.query(TelemetryRecord)
        .filter(
            TelemetryRecord.tenant_id == record.tenant_id,
            TelemetryRecord.id != record.id,
        )
        .order_by(TelemetryRecord.event_timestamp_utc.desc())
        .limit(120)
        .all()
    )

    df = pd.DataFrame(
        [
            {
                "cpu_usage": r.cpu_usage,
                "memory_usage": r.memory_usage,
                "disk_usage": r.disk_usage,
                "network_latency_ms": r.network_latency_ms,
                "packet_loss_pct": r.packet_loss_pct,
            }
            for r in recent
        ]
    )

    baseline_stats: Dict[str, tuple[Optional[float], Optional[float]]] = {}
    if len(df) >= 5:
        for col in ("cpu_usage", "memory_usage", "network_latency_ms", "packet_loss_pct"):
            mean_val = float(df[col].mean())
            std_val = float(df[col].std(ddof=0))
            baseline_stats[col] = (round(mean_val, 2), round(std_val, 2))
    else:
        for col in ("cpu_usage", "memory_usage", "network_latency_ms", "packet_loss_pct"):
            baseline_stats[col] = (None, None)

    # Layer 2B: IsolationForest multivariate anomaly check after sufficient samples (>= 15)
    ml_flagged = False
    ml_score = 0.0
    if len(df) >= 15:
        features = ["cpu_usage", "memory_usage", "disk_usage", "network_latency_ms", "packet_loss_pct"]
        train_x = df[features].to_numpy(dtype=float)
        current_x = np.array(
            [
                [
                    record.cpu_usage,
                    record.memory_usage,
                    record.disk_usage,
                    record.network_latency_ms,
                    record.packet_loss_pct,
                ]
            ],
            dtype=float,
        )
        model = IsolationForest(contamination=0.1, random_state=42)
        model.fit(train_x)
        pred = int(model.predict(current_x)[0])
        ml_score = round(float(model.decision_function(current_x)[0]), 4)
        ml_flagged = pred == -1

    specs: List[DetectedAnomalySpec] = []
    signals = {
        "cpu_usage": round(record.cpu_usage, 2),
        "memory_usage": round(record.memory_usage, 2),
        "network_latency_ms": round(record.network_latency_ms, 2),
        "packet_loss_pct": round(record.packet_loss_pct, 2),
        "failed_login_count": float(record.failed_login_count),
    }

    def check_metric(
        metric_name: str,
        value: float,
        threshold: float,
        unit: str,
        label: str,
    ) -> None:
        b_mean, b_std = baseline_stats[metric_name]
        rule_hit = value > threshold
        baseline_hit = (
            b_mean is not None
            and b_std is not None
            and b_std > 0.5
            and (value - b_mean) / b_std > 2.5
        )
        if not (rule_hit or baseline_hit):
            return

        if rule_hit and (baseline_hit or ml_flagged):
            method = "combined"
        elif rule_hit:
            method = "rule"
        elif baseline_hit and ml_flagged:
            method = "combined"
        else:
            method = "baseline"

        sev = "Critical" if value >= threshold * 1.08 else "High" if rule_hit else "Medium"
        specs.append(
            DetectedAnomalySpec(
                metric_name=metric_name,
                metric_value=round(value, 2),
                baseline_mean=b_mean,
                baseline_std=b_std,
                detection_method=method,
                severity=sev,
                description=(
                    f"{label} reached {value:.1f}{unit} "
                    f"(threshold {threshold:.1f}{unit}"
                    + (f", baseline mean {b_mean:.1f}{unit}" if b_mean is not None else "")
                    + ")"
                ),
                contributing_signals=signals,
            )
        )

    check_metric("cpu_usage", record.cpu_usage, thresholds.cpu_threshold, "%", "CPU utilization")
    check_metric(
        "memory_usage", record.memory_usage, thresholds.memory_threshold, "%", "Memory utilization"
    )
    check_metric(
        "network_latency_ms",
        record.network_latency_ms,
        thresholds.latency_threshold_ms,
        " ms",
        "Network latency",
    )
    check_metric(
        "packet_loss_pct",
        record.packet_loss_pct,
        thresholds.packet_loss_threshold_pct,
        "%",
        "Packet loss",
    )

    if str(record.service_status).lower() in ("unavailable", "down", "critical"):
        specs.append(
            DetectedAnomalySpec(
                metric_name="service_status",
                metric_value=0.0,
                baseline_mean=None,
                baseline_std=None,
                detection_method="combined" if ml_flagged else "rule",
                severity="Critical",
                description=f"Critical service '{record.component}' reported status '{record.service_status}'.",
                contributing_signals=signals,
            )
        )

    if record.failed_login_count >= 10:
        specs.append(
            DetectedAnomalySpec(
                metric_name="failed_login_count",
                metric_value=float(record.failed_login_count),
                baseline_mean=None,
                baseline_std=None,
                detection_method="rule",
                severity="High",
                description=(
                    f"Locally aggregated authentication failures reached {record.failed_login_count} "
                    f"events on '{record.component}' (raw credentials retained locally)."
                ),
                contributing_signals=signals,
            )
        )

    if not specs and ml_flagged:
        specs.append(
            DetectedAnomalySpec(
                metric_name="multivariate_drift",
                metric_value=ml_score,
                baseline_mean=baseline_stats["cpu_usage"][0],
                baseline_std=baseline_stats["cpu_usage"][1],
                detection_method="ml",
                severity="Medium",
                description=(
                    f"IsolationForest detected multivariate telemetry deviation "
                    f"(decision_score={ml_score}) across CPU, memory, disk, latency, and packet loss."
                ),
                contributing_signals={**signals, "isolation_forest_score": ml_score},
            )
        )

    created: List[Anomaly] = []
    for spec in specs:
        anomaly = Anomaly(
            tenant_id=record.tenant_id,
            collector_id=record.collector_id,
            telemetry_id=record.id,
            source_id=record.source_id,
            component=record.component,
            metric_name=spec.metric_name,
            metric_value=spec.metric_value,
            baseline_mean=spec.baseline_mean,
            baseline_std=spec.baseline_std,
            detection_method=spec.detection_method,
            severity=spec.severity,
            description=spec.description,
            contributing_signals_json=spec.contributing_signals,
            detected_at_utc=record.event_timestamp_utc,
        )
        db.add(anomaly)
        created.append(anomaly)

    if created:
        db.flush()
    return created
