from typing import Any, Dict, List
from fastapi import APIRouter, Depends, Query
from sqlalchemy import distinct, func
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import canonical_json, compute_sha256_hex, utc_now, verify_hmac_hex
from app.db.session import get_db
from app.models.models import (
    Anomaly,
    Collector,
    EgressProof,
    Incident,
    TelemetryRecord,
    Tenant,
)
from app.schemas.telemetry import (
    EgressVerifyRequest,
    EgressVerifyResponse,
    HeartbeatRequest,
    TelemetryIngestEnvelope,
    TelemetryIngestResponse,
    ThresholdUpdateRequest,
)
from app.services.auth_service import AuthenticatedPrincipal, get_current_principal
from app.services.ingestion_service import (
    evaluate_tenant_health,
    get_or_create_thresholds,
    ingest_telemetry_envelope,
    record_collector_heartbeat,
)
from app.services.ws_manager import ws_manager

router = APIRouter(tags=["telemetry"])


@router.post("/telemetry", response_model=TelemetryIngestResponse)
async def post_telemetry(
    envelope: TelemetryIngestEnvelope,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> TelemetryIngestResponse:
    response, broadcast = ingest_telemetry_envelope(db, principal.tenant_id, envelope)
    if broadcast:
        await ws_manager.broadcast_to_tenant(principal.tenant_id, "telemetry:ingested", broadcast)
        if broadcast.get("incident_code"):
            await ws_manager.broadcast_to_tenant(
                principal.tenant_id,
                "incident:updated",
                {"incident_code": broadcast["incident_code"], "source_id": broadcast["source_id"]},
            )
    return response


@router.get("/telemetry")
def list_telemetry(
    limit: int = Query(default=100, ge=1, le=500),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    rows = (
        db.query(TelemetryRecord)
        .filter(TelemetryRecord.tenant_id == principal.tenant_id)
        .order_by(TelemetryRecord.event_timestamp_utc.asc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": r.id,
            "payload_id": r.payload_id,
            "collector_id": r.collector_id,
            "source_id": r.source_id,
            "component": r.component,
            "event_category": r.event_category,
            "event_timestamp_utc": r.event_timestamp_utc.isoformat(),
            "ingested_at_utc": r.ingested_at_utc.isoformat(),
            "source_timezone": r.source_timezone,
            "cpu_usage": r.cpu_usage,
            "memory_usage": r.memory_usage,
            "disk_usage": r.disk_usage,
            "network_latency_ms": r.network_latency_ms,
            "packet_loss_pct": r.packet_loss_pct,
            "service_status": r.service_status,
            "failed_login_count": r.failed_login_count,
            "uptime_seconds": r.uptime_seconds,
            "severity": r.severity,
            "is_simulation": r.is_simulation,
        }
        for r in rows
    ]


@router.get("/dashboard/overview")
def get_dashboard_overview(
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    tid = principal.tenant_id
    tenant = db.query(Tenant).filter(Tenant.id == tid).first()
    health_state, health_reason = evaluate_tenant_health(db, tid)

    active_sources = (
        db.query(func.count(distinct(TelemetryRecord.source_id)))
        .filter(TelemetryRecord.tenant_id == tid)
        .scalar()
        or 0
    )
    collectors = db.query(Collector).filter(Collector.tenant_id == tid).all()
    online_collectors = [c for c in collectors if c.status == "ONLINE"]

    active_incidents = (
        db.query(Incident)
        .filter(Incident.tenant_id == tid, Incident.status.in_(["OPEN", "INVESTIGATING"]))
        .count()
    )
    critical_alerts = (
        db.query(Anomaly)
        .filter(Anomaly.tenant_id == tid, Anomaly.severity.in_(["Critical", "High"]))
        .count()
    )
    proofs = db.query(EgressProof).filter(EgressProof.tenant_id == tid).all()
    blocked_fields_total = sum(len(p.blocked_fields_json or []) for p in proofs)
    verified_payloads_count = sum(1 for p in proofs if p.verification_status == "VERIFIED")
    max_risk = max((p.privacy_risk_score for p in proofs), default=0)

    latest_telemetry = (
        db.query(TelemetryRecord)
        .filter(TelemetryRecord.tenant_id == tid)
        .order_by(TelemetryRecord.event_timestamp_utc.desc())
        .limit(40)
        .all()
    )
    latest_telemetry_asc = list(reversed(latest_telemetry))

    recent_incidents = (
        db.query(Incident)
        .filter(Incident.tenant_id == tid)
        .order_by(Incident.detected_at_utc.desc())
        .limit(5)
        .all()
    )

    last_sync = (
        max(
            (c.last_seen_utc for c in collectors if c.last_seen_utc is not None),
            default=None,
        )
    )

    return {
        "tenant": {
            "id": tid,
            "slug": tenant.slug if tenant else principal.tenant_slug,
            "name": tenant.name if tenant else principal.tenant_slug,
            "region": tenant.region if tenant else "us-east-1",
            "residency_policy": tenant.residency_policy if tenant else "strict",
        },
        "health_state": health_state,
        "health_reason": health_reason,
        "kpis": {
            "active_sources": active_sources,
            "online_collectors": len(online_collectors),
            "total_collectors": len(collectors),
            "active_incidents": active_incidents,
            "critical_alerts": critical_alerts,
            "blocked_fields_count": blocked_fields_total,
            "verified_payloads_count": verified_payloads_count,
            "privacy_risk_score": max_risk,
            "last_sync_utc": last_sync.isoformat() if last_sync else None,
        },
        "telemetry_series": [
            {
                "event_timestamp_utc": r.event_timestamp_utc.isoformat(),
                "source_id": r.source_id,
                "component": r.component,
                "cpu_usage": r.cpu_usage,
                "memory_usage": r.memory_usage,
                "network_latency_ms": r.network_latency_ms,
                "packet_loss_pct": r.packet_loss_pct,
                "severity": r.severity,
            }
            for r in latest_telemetry_asc
        ],
        "recent_incidents": [
            {
                "id": inc.id,
                "incident_code": inc.incident_code,
                "title": inc.title,
                "severity": inc.severity,
                "status": inc.status,
                "detected_at_utc": inc.detected_at_utc.isoformat(),
                "primary_source_id": inc.primary_source_id,
            }
            for inc in recent_incidents
        ],
    }


@router.get("/collectors")
def list_collectors(
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    collectors = (
        db.query(Collector)
        .filter(Collector.tenant_id == principal.tenant_id)
        .order_by(Collector.collector_id.asc())
        .all()
    )
    return [
        {
            "id": c.id,
            "collector_id": c.collector_id,
            "display_name": c.display_name,
            "status": c.status,
            "version": c.version,
            "region": c.region,
            "source_timezone": c.source_timezone,
            "last_seen_utc": c.last_seen_utc.isoformat() if c.last_seen_utc else None,
            "last_cpu_pct": c.last_cpu_pct,
            "last_mem_mb": c.last_mem_mb,
            "config": c.config_json,
        }
        for c in collectors
    ]


@router.post("/collectors/heartbeat")
async def post_collector_heartbeat(
    heartbeat: HeartbeatRequest,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    col = record_collector_heartbeat(db, principal.tenant_id, heartbeat)
    await ws_manager.broadcast_to_tenant(
        principal.tenant_id,
        "collector:status",
        {
            "collector_id": col.collector_id,
            "status": col.status,
            "last_seen_utc": col.last_seen_utc.isoformat() if col.last_seen_utc else None,
        },
    )
    return {
        "collector_id": col.collector_id,
        "status": col.status,
        "last_seen_utc": col.last_seen_utc.isoformat() if col.last_seen_utc else None,
    }


@router.get("/egress/audit")
def list_egress_audit(
    limit: int = Query(default=50, ge=1, le=200),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    proofs = (
        db.query(EgressProof)
        .filter(EgressProof.tenant_id == principal.tenant_id)
        .order_by(EgressProof.created_at_utc.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": p.id,
            "payload_id": p.payload_id,
            "tenant_id": p.tenant_id,
            "collector_id": p.collector_id,
            "source_id": p.source_id,
            "event_timestamp_utc": p.event_timestamp_utc.isoformat(),
            "approved_metadata": p.approved_metadata_json,
            "allowed_fields": p.allowed_fields_json,
            "blocked_fields": p.blocked_fields_json,
            "policy_version": p.policy_version,
            "privacy_risk_score": p.privacy_risk_score,
            "payload_hash_sha256": p.payload_hash_sha256,
            "hmac_signature": p.hmac_signature,
            "verification_status": p.verification_status,
            "approval_decision": p.approval_decision,
            "delivery_status": p.delivery_status,
            "created_at_utc": p.created_at_utc.isoformat(),
        }
        for p in proofs
    ]


@router.post("/egress/verify", response_model=EgressVerifyResponse)
def verify_egress_payload(
    request: EgressVerifyRequest,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> EgressVerifyResponse:
    settings = get_settings()
    canonical_str = canonical_json(request.approved_metadata)
    computed_sha = compute_sha256_hex(request.approved_metadata)
    hash_ok = computed_sha == request.payload_hash_sha256
    hmac_ok = (
        verify_hmac_hex(settings.collector_hmac_secret, canonical_str, request.hmac_signature)
        if request.hmac_signature
        else None
    )
    all_ok = hash_ok and (hmac_ok is not False)
    return EgressVerifyResponse(
        payload_id=request.payload_id,
        hash_valid=hash_ok,
        hmac_valid=hmac_ok,
        computed_sha256=computed_sha,
        verification_status="VERIFIED" if all_ok else "TAMPER_DETECTED",
        checked_at_utc=utc_now(),
    )


@router.get("/settings/thresholds")
def get_tenant_thresholds(
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    t = get_or_create_thresholds(db, principal.tenant_id)
    db.commit()
    return {
        "cpu_threshold": t.cpu_threshold,
        "memory_threshold": t.memory_threshold,
        "latency_threshold_ms": t.latency_threshold_ms,
        "packet_loss_threshold_pct": t.packet_loss_threshold_pct,
        "offline_timeout_seconds": t.offline_timeout_seconds,
        "updated_at_utc": t.updated_at_utc.isoformat(),
    }


@router.patch("/settings/thresholds")
def update_tenant_thresholds(
    payload: ThresholdUpdateRequest,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    t = get_or_create_thresholds(db, principal.tenant_id)
    t.cpu_threshold = payload.cpu_threshold
    t.memory_threshold = payload.memory_threshold
    t.latency_threshold_ms = payload.latency_threshold_ms
    t.packet_loss_threshold_pct = payload.packet_loss_threshold_pct
    t.offline_timeout_seconds = payload.offline_timeout_seconds
    t.updated_at_utc = utc_now()
    db.commit()
    db.refresh(t)
    return {
        "cpu_threshold": t.cpu_threshold,
        "memory_threshold": t.memory_threshold,
        "latency_threshold_ms": t.latency_threshold_ms,
        "packet_loss_threshold_pct": t.packet_loss_threshold_pct,
        "offline_timeout_seconds": t.offline_timeout_seconds,
        "updated_at_utc": t.updated_at_utc.isoformat(),
    }


@router.post("/collector/simulate")
async def trigger_controlled_simulation(
    body: Dict[str, Any],
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    import hashlib
    import hmac as hmac_mod
    import uuid

    scenario = str(body.get("scenario", "cpu_spike")).strip().lower()
    settings = get_settings()
    now_iso = utc_now().isoformat()

    raw_templates: Dict[str, Dict[str, Any]] = {
        "cpu_spike": {
            "component": "api-gateway",
            "event_category": "compute_saturation",
            "cpu_usage": 96.4,
            "memory_usage": 72.1,
            "disk_usage": 58.0,
            "network_latency_ms": 84.0,
            "packet_loss_pct": 0.4,
            "service_status": "healthy",
            "severity": "Critical",
        },
        "memory_leak": {
            "component": "payment-worker",
            "event_category": "memory_exhaustion",
            "cpu_usage": 67.5,
            "memory_usage": 95.8,
            "disk_usage": 61.2,
            "network_latency_ms": 112.0,
            "packet_loss_pct": 0.6,
            "service_status": "degraded",
            "severity": "Critical",
        },
        "network_drop": {
            "component": "edge-ingress",
            "event_category": "network_degradation",
            "cpu_usage": 44.0,
            "memory_usage": 56.3,
            "disk_usage": 48.0,
            "network_latency_ms": 285.0,
            "packet_loss_pct": 9.4,
            "service_status": "degraded",
            "severity": "High",
        },
        "db_lock": {
            "component": "postgres-primary",
            "event_category": "database_contention",
            "cpu_usage": 91.2,
            "memory_usage": 88.6,
            "disk_usage": 74.0,
            "network_latency_ms": 265.0,
            "packet_loss_pct": 2.1,
            "service_status": "unavailable",
            "severity": "Critical",
        },
        "secret_leak_test": {
            "component": "auth-service",
            "event_category": "privacy_shield_verification",
            "cpu_usage": 41.2,
            "memory_usage": 53.0,
            "disk_usage": 42.0,
            "network_latency_ms": 38.0,
            "packet_loss_pct": 0.1,
            "service_status": "healthy",
            "severity": "Medium",
            "password": "REDACTED_DO_NOT_TRANSMIT",
            "api_key": "sk-sim-blocked-local",
            "bearer_token": "eyJ-sim-blocked-local",
            "username": "local-admin",
            "hostname": "prod-db-internal.local",
            "internal_ip": "10.0.4.22",
        },
    }
    raw = raw_templates.get(scenario, raw_templates["cpu_spike"])
    blocked = sorted(k for k in raw.keys() if k in FORBIDDEN_CENTRAL_KEYS)

    source_digest = hmac_mod.new(
        settings.pseudonym_salt.encode("utf-8"),
        f"{principal.tenant_slug}:sim-host".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:16]

    approved_meta = {
        "source_id": f"src_{source_digest}",
        "collector_id": f"collector-{principal.tenant_slug[:6]}-sim",
        "component": raw["component"],
        "event_category": raw["event_category"],
        "event_timestamp_utc": now_iso,
        "source_timezone": "UTC",
        "cpu_usage": raw["cpu_usage"],
        "memory_usage": raw["memory_usage"],
        "disk_usage": raw["disk_usage"],
        "network_latency_ms": raw["network_latency_ms"],
        "packet_loss_pct": raw["packet_loss_pct"],
        "service_status": raw["service_status"],
        "failed_login_count": 0,
        "uptime_seconds": 3600.0,
        "severity": raw["severity"],
        "is_simulation": True,
    }
    canonical_str = canonical_json(approved_meta)
    payload_hash = compute_sha256_hex(approved_meta)
    sig = hmac_mod.new(
        settings.collector_hmac_secret.encode("utf-8"),
        canonical_str.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    pid = str(uuid.uuid4())

    envelope = TelemetryIngestEnvelope(
        payload_id=pid,
        collector_id=approved_meta["collector_id"],
        tenant_id=principal.tenant_id,
        event_timestamp_utc=now_iso,
        approved_metadata=approved_meta,
        allowed_fields=sorted(approved_meta.keys()),
        blocked_fields=blocked,
        classification_summary={"safe": len(approved_meta), "blocked": len(blocked)},
        policy_version="1.0.0",
        privacy_risk_score=0,
        payload_hash_sha256=payload_hash,
        hmac_signature=sig,
        approval_decision="APPROVED",
    )
    resp, broadcast = ingest_telemetry_envelope(db, principal.tenant_id, envelope)
    if broadcast:
        await ws_manager.broadcast_to_tenant(principal.tenant_id, "telemetry:ingested", broadcast)
        if broadcast.get("incident_code"):
            await ws_manager.broadcast_to_tenant(
                principal.tenant_id,
                "incident:updated",
                {"incident_code": broadcast["incident_code"], "source_id": broadcast["source_id"]},
            )
    return {
        "status": resp.status,
        "scenario": scenario,
        "payload_id": pid,
        "blocked_fields": blocked,
        "anomalies_detected": resp.anomalies_detected,
        "incident_code": resp.incident_code,
    }

