from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import (
    canonical_json,
    compute_sha256_hex,
    utc_now,
    verify_hmac_hex,
)
from app.engines.anomaly_engine import detect_anomalies_for_record
from app.engines.correlation_engine import correlate_anomalies_into_incident
from app.engines.rca_engine import regenerate_hypotheses_and_passport
from app.models.models import (
    Anomaly,
    Collector,
    CollectorHealth,
    EgressProof,
    Incident,
    PrivacyAudit,
    TelemetryRecord,
    TenantThreshold,
)
from app.schemas.telemetry import (
    HeartbeatRequest,
    TelemetryIngestEnvelope,
    TelemetryIngestResponse,
)

FORBIDDEN_CENTRAL_KEYS = {
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "bearer_token",
    "private_key",
    "ssh_key",
    "raw_log",
    "raw_payload",
    "credentials",
    "username",
    "hostname",
    "internal_ip",
}


def _parse_utc_timestamp(raw_ts: Any) -> datetime:
    if isinstance(raw_ts, datetime):
        dt = raw_ts
    elif isinstance(raw_ts, str) and raw_ts.strip():
        dt = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
    else:
        return utc_now()
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _ensure_no_restricted_fields(metadata: Dict[str, Any]) -> None:
    present_forbidden = sorted(
        k for k in metadata.keys() if k.strip().lower() in FORBIDDEN_CENTRAL_KEYS
    )
    if present_forbidden:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Central ingestion rejected restricted/sensitive field(s): {present_forbidden}. "
                "Privacy filtering must occur inside the Tier 1 local collector."
            ),
        )


def get_or_create_thresholds(db: Session, tenant_id: str) -> TenantThreshold:
    thresholds = (
        db.query(TenantThreshold).filter(TenantThreshold.tenant_id == tenant_id).first()
    )
    if thresholds:
        return thresholds
    settings = get_settings()
    thresholds = TenantThreshold(
        tenant_id=tenant_id,
        cpu_threshold=settings.threshold_cpu_percent,
        memory_threshold=settings.threshold_memory_percent,
        latency_threshold_ms=settings.threshold_latency_ms,
        packet_loss_threshold_pct=settings.threshold_packet_loss_percent,
        offline_timeout_seconds=settings.collector_offline_timeout_seconds,
        updated_at_utc=utc_now(),
    )
    db.add(thresholds)
    db.flush()
    return thresholds


def ingest_telemetry_envelope(
    db: Session,
    tenant_id: str,
    envelope: TelemetryIngestEnvelope,
) -> Tuple[TelemetryIngestResponse, Dict[str, Any] | None]:
    """
    Validate, cryptographically verify, deduplicate (idempotency), store, and run AIOps pipeline.
    Returns (response, websocket_broadcast_payload_or_none).
    """
    settings = get_settings()
    meta = envelope.approved_metadata

    # 1. Central privacy defense-in-depth: never accept raw secrets or sensitive identifiers
    _ensure_no_restricted_fields(meta)

    if envelope.approval_decision != "APPROVED" or envelope.privacy_risk_score >= 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Blocked or high-risk payload cannot be accepted by central ingestion.",
        )

    # 2. Verify SHA-256 and HMAC-SHA256 integrity
    canonical_str = canonical_json(meta)
    computed_hash = compute_sha256_hex(meta)
    if computed_hash != envelope.payload_hash_sha256:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload integrity failure: SHA-256 hash mismatch.",
        )

    if not verify_hmac_hex(settings.collector_hmac_secret, canonical_str, envelope.hmac_signature):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload authenticity failure: HMAC-SHA256 signature invalid.",
        )

    # 3. Idempotency check on (tenant_id, payload_id)
    existing = (
        db.query(TelemetryRecord)
        .filter(
            TelemetryRecord.tenant_id == tenant_id,
            TelemetryRecord.payload_id == envelope.payload_id,
        )
        .first()
    )
    if existing:
        return (
            TelemetryIngestResponse(
                status="duplicate_ignored",
                payload_id=envelope.payload_id,
                verification_status="VERIFIED",
                anomalies_detected=0,
                incident_code=None,
            ),
            None,
        )

    event_time_utc = _parse_utc_timestamp(meta.get("event_timestamp_utc"))
    source_id = str(meta.get("source_id", f"src_{envelope.collector_id}"))
    source_tz = str(meta.get("source_timezone", "UTC"))
    component = str(meta.get("component", "host-system"))

    # 4. Update collector last_seen & health state
    collector = (
        db.query(Collector)
        .filter(
            Collector.tenant_id == tenant_id,
            Collector.collector_id == envelope.collector_id,
        )
        .first()
    )
    now_utc = utc_now()
    cpu_proc = float(meta.get("collector_cpu_pct", 0.0) or 0.0)
    mem_proc = float(meta.get("collector_rss_mb", 0.0) or 0.0)
    if collector:
        collector.status = "ONLINE"
        collector.last_seen_utc = now_utc
        collector.source_timezone = source_tz
        if cpu_proc:
            collector.last_cpu_pct = cpu_proc
        if mem_proc:
            collector.last_mem_mb = mem_proc

    # 5. Persist approved telemetry metadata
    record = TelemetryRecord(
        tenant_id=tenant_id,
        collector_id=envelope.collector_id,
        payload_id=envelope.payload_id,
        source_id=source_id,
        component=component,
        event_category=str(meta.get("event_category", "infrastructure")),
        event_timestamp_utc=event_time_utc,
        ingested_at_utc=now_utc,
        source_timezone=source_tz,
        cpu_usage=float(meta.get("cpu_usage", 0.0) or 0.0),
        memory_usage=float(meta.get("memory_usage", 0.0) or 0.0),
        disk_usage=float(meta.get("disk_usage", 0.0) or 0.0),
        network_latency_ms=float(meta.get("network_latency_ms", 0.0) or 0.0),
        packet_loss_pct=float(meta.get("packet_loss_pct", 0.0) or 0.0),
        service_status=str(meta.get("service_status", "healthy")),
        failed_login_count=int(meta.get("failed_login_count", 0) or 0),
        uptime_seconds=float(meta.get("uptime_seconds", 0.0) or 0.0),
        severity=str(meta.get("severity", "LOW")),
        is_simulation=bool(meta.get("is_simulation", False)),
        extra_metadata_json={
            k: v
            for k, v in meta.items()
            if k
            not in {
                "source_id",
                "collector_id",
                "component",
                "event_category",
                "event_timestamp_utc",
                "source_timezone",
                "cpu_usage",
                "memory_usage",
                "disk_usage",
                "network_latency_ms",
                "packet_loss_pct",
                "service_status",
                "failed_login_count",
                "uptime_seconds",
                "severity",
                "is_simulation",
            }
        },
    )
    db.add(record)
    db.flush()

    # 6. Persist EgressProof & PrivacyAudit
    proof = EgressProof(
        tenant_id=tenant_id,
        collector_id=envelope.collector_id,
        payload_id=envelope.payload_id,
        source_id=source_id,
        event_timestamp_utc=event_time_utc,
        approved_metadata_json=meta,
        allowed_fields_json=envelope.allowed_fields or sorted(meta.keys()),
        blocked_fields_json=envelope.blocked_fields,
        policy_version=envelope.policy_version,
        privacy_risk_score=envelope.privacy_risk_score,
        payload_hash_sha256=envelope.payload_hash_sha256,
        hmac_signature=envelope.hmac_signature,
        verification_status="VERIFIED",
        approval_decision=envelope.approval_decision,
        delivery_status="DELIVERED",
        created_at_utc=now_utc,
    )
    db.add(proof)

    audit = PrivacyAudit(
        tenant_id=tenant_id,
        collector_id=envelope.collector_id,
        payload_id=envelope.payload_id,
        classification_summary_json=envelope.classification_summary,
        risk_score=envelope.privacy_risk_score,
        decision=envelope.approval_decision,
        policy_version=envelope.policy_version,
        recorded_at_utc=now_utc,
    )
    db.add(audit)

    # 7. AIOps Pipeline: Anomaly Detection -> Correlation -> Root-Cause & Incident Passport
    thresholds = get_or_create_thresholds(db, tenant_id)
    anomalies = detect_anomalies_for_record(db, record, thresholds)
    incident, _ = correlate_anomalies_into_incident(db, record, anomalies)
    if incident:
        regenerate_hypotheses_and_passport(db, incident)

    db.commit()

    broadcast = {
        "payload_id": envelope.payload_id,
        "collector_id": envelope.collector_id,
        "source_id": source_id,
        "event_timestamp_utc": event_time_utc.isoformat(),
        "cpu_usage": record.cpu_usage,
        "memory_usage": record.memory_usage,
        "network_latency_ms": record.network_latency_ms,
        "packet_loss_pct": record.packet_loss_pct,
        "anomalies_detected": len(anomalies),
        "incident_code": incident.incident_code if incident else None,
    }

    return (
        TelemetryIngestResponse(
            status="accepted",
            payload_id=envelope.payload_id,
            verification_status="VERIFIED",
            anomalies_detected=len(anomalies),
            incident_code=incident.incident_code if incident else None,
        ),
        broadcast,
    )


def record_collector_heartbeat(
    db: Session,
    tenant_id: str,
    heartbeat: HeartbeatRequest,
) -> Collector:
    now_utc = utc_now()
    collector = (
        db.query(Collector)
        .filter(
            Collector.tenant_id == tenant_id,
            Collector.collector_id == heartbeat.collector_id,
        )
        .first()
    )
    if not collector:
        collector = Collector(
            tenant_id=tenant_id,
            collector_id=heartbeat.collector_id,
            display_name=heartbeat.collector_id,
            api_key_hash="registered-via-jwt",
            version=heartbeat.version,
            source_timezone=heartbeat.source_timezone,
            status="ONLINE",
            last_seen_utc=now_utc,
            last_cpu_pct=heartbeat.cpu_pct,
            last_mem_mb=heartbeat.memory_mb,
            config_json={"pending_outbox": heartbeat.pending_outbox},
        )
        db.add(collector)
    else:
        collector.status = "ONLINE"
        collector.version = heartbeat.version
        collector.source_timezone = heartbeat.source_timezone
        collector.last_seen_utc = now_utc
        collector.last_cpu_pct = heartbeat.cpu_pct
        collector.last_mem_mb = heartbeat.memory_mb
        collector.config_json = {
            **(collector.config_json or {}),
            "pending_outbox": heartbeat.pending_outbox,
        }

    db.add(
        CollectorHealth(
            tenant_id=tenant_id,
            collector_id=heartbeat.collector_id,
            health_state="Excellent",
            reason=f"Heartbeat received (pending_outbox={heartbeat.pending_outbox})",
            cpu_pct=heartbeat.cpu_pct,
            memory_mb=heartbeat.memory_mb,
            recorded_at_utc=now_utc,
        )
    )
    db.commit()
    db.refresh(collector)
    return collector


def evaluate_offline_collectors(db: Session, now: datetime | None = None) -> List[Collector]:
    """
    Detect collectors whose last_seen_utc exceeded tenant offline_timeout_seconds.
    Marks them OFFLINE and appends Poor CollectorHealth transition.
    """
    current_utc = now or utc_now()
    default_timeout = get_settings().collector_offline_timeout_seconds
    collectors = db.query(Collector).filter(Collector.status == "ONLINE").all()
    marked_offline: List[Collector] = []

    for col in collectors:
        if col.last_seen_utc is None:
            continue
        last_seen = col.last_seen_utc
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)

        thresholds = (
            db.query(TenantThreshold).filter(TenantThreshold.tenant_id == col.tenant_id).first()
        )
        timeout_sec = thresholds.offline_timeout_seconds if thresholds else default_timeout
        if current_utc - last_seen > timedelta(seconds=timeout_sec):
            col.status = "OFFLINE"
            db.add(
                CollectorHealth(
                    tenant_id=col.tenant_id,
                    collector_id=col.collector_id,
                    health_state="Poor",
                    reason=f"Collector offline: no heartbeat within {timeout_sec}s.",
                    cpu_pct=col.last_cpu_pct,
                    memory_mb=col.last_mem_mb,
                    recorded_at_utc=current_utc,
                )
            )
            marked_offline.append(col)

    if marked_offline:
        db.commit()
    return marked_offline


def evaluate_tenant_health(db: Session, tenant_id: str) -> tuple[str, str]:
    """
    Four-state health evaluation: Excellent, Good, Fair, Poor.
    Stale or offline collectors downgrade health instead of showing last good values.
    """
    collectors = db.query(Collector).filter(Collector.tenant_id == tenant_id).all()
    online_collectors = [c for c in collectors if c.status == "ONLINE"]
    if collectors and not online_collectors:
        return "Poor", "All registered collectors are currently OFFLINE or stale."

    open_incidents = (
        db.query(Incident)
        .filter(Incident.tenant_id == tenant_id, Incident.status.in_(["OPEN", "INVESTIGATING"]))
        .all()
    )
    if any(inc.severity == "Critical" for inc in open_incidents):
        return "Poor", "Critical severity incident active."
    if any(inc.severity == "High" for inc in open_incidents):
        return "Fair", "High severity incident requires operator attention."

    latest = (
        db.query(TelemetryRecord)
        .filter(TelemetryRecord.tenant_id == tenant_id)
        .order_by(TelemetryRecord.event_timestamp_utc.desc())
        .first()
    )
    if not latest:
        return "Fair", "Waiting for telemetry stream from local collector."

    last_ts = latest.event_timestamp_utc
    if last_ts.tzinfo is None:
        last_ts = last_ts.replace(tzinfo=timezone.utc)
    if utc_now() - last_ts > timedelta(seconds=120):
        return "Poor", "Telemetry is stale (>120s since last event timestamp)."

    recent_anomalies = (
        db.query(Anomaly)
        .filter(
            Anomaly.tenant_id == tenant_id,
            Anomaly.detected_at_utc >= utc_now() - timedelta(minutes=10),
        )
        .count()
    )
    if recent_anomalies > 0:
        return "Fair", f"{recent_anomalies} anomaly signal(s) detected in the last 10 minutes."

    if latest.cpu_usage > 75 or latest.memory_usage > 75 or latest.network_latency_ms > 120:
        return "Good", "Minor resource or latency variance within operational norms."

    return "Excellent", "Collectors reporting cleanly; metrics within expected baselines."
