from typing import Any, Dict, List
from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from sqlalchemy.orm import Session

from app.core.security import decode_access_token, utc_now
from app.db.session import get_db
from app.engines.rca_engine import regenerate_hypotheses_and_passport
from app.models.models import (
    Anomaly,
    Incident,
    IncidentEvent,
    IncidentPassport,
    Recommendation,
    RootCauseHypothesis,
)
from app.schemas.telemetry import IncidentStatusUpdateRequest
from app.services.auth_service import AuthenticatedPrincipal, get_current_principal
from app.services.ws_manager import ws_manager

router = APIRouter(tags=["incidents"])


def _get_tenant_incident(db: Session, tenant_id: str, incident_id_or_code: str) -> Incident:
    incident = (
        db.query(Incident)
        .filter(
            Incident.tenant_id == tenant_id,
            (Incident.id == incident_id_or_code) | (Incident.incident_code == incident_id_or_code),
        )
        .first()
    )
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found for authenticated tenant.",
        )
    return incident


@router.get("/anomalies")
def list_anomalies(
    limit: int = Query(default=100, ge=1, le=500),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    rows = (
        db.query(Anomaly)
        .filter(Anomaly.tenant_id == principal.tenant_id)
        .order_by(Anomaly.detected_at_utc.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": a.id,
            "collector_id": a.collector_id,
            "telemetry_id": a.telemetry_id,
            "source_id": a.source_id,
            "component": a.component,
            "metric_name": a.metric_name,
            "metric_value": a.metric_value,
            "baseline_mean": a.baseline_mean,
            "baseline_std": a.baseline_std,
            "detection_method": a.detection_method,
            "severity": a.severity,
            "description": a.description,
            "contributing_signals": a.contributing_signals_json,
            "detected_at_utc": a.detected_at_utc.isoformat(),
        }
        for a in rows
    ]


@router.get("/incidents")
def list_incidents(
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    incidents = (
        db.query(Incident)
        .filter(Incident.tenant_id == principal.tenant_id)
        .order_by(Incident.detected_at_utc.desc())
        .all()
    )
    results: List[Dict[str, Any]] = []
    for inc in incidents:
        top_hyp = (
            db.query(RootCauseHypothesis)
            .filter(
                RootCauseHypothesis.tenant_id == principal.tenant_id,
                RootCauseHypothesis.incident_id == inc.id,
            )
            .order_by(RootCauseHypothesis.rank.asc())
            .first()
        )
        results.append(
            {
                "id": inc.id,
                "incident_code": inc.incident_code,
                "title": inc.title,
                "status": inc.status,
                "severity": inc.severity,
                "primary_source_id": inc.primary_source_id,
                "affected_components": inc.affected_components_json,
                "evidence_count": len(inc.evidence_ids_json or []),
                "correlation_score": inc.correlation_score,
                "leading_hypothesis": top_hyp.title if top_hyp else "Pending synthesis",
                "leading_confidence": top_hyp.confidence_score if top_hyp else 0.0,
                "detected_at_utc": inc.detected_at_utc.isoformat(),
                "updated_at_utc": inc.updated_at_utc.isoformat(),
            }
        )
    return results


@router.get("/incidents/{incident_id}")
def get_incident_detail(
    incident_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    inc = _get_tenant_incident(db, principal.tenant_id, incident_id)
    return {
        "id": inc.id,
        "incident_code": inc.incident_code,
        "title": inc.title,
        "status": inc.status,
        "severity": inc.severity,
        "primary_source_id": inc.primary_source_id,
        "affected_components": inc.affected_components_json,
        "evidence_ids": inc.evidence_ids_json,
        "correlation_score": inc.correlation_score,
        "detected_at_utc": inc.detected_at_utc.isoformat(),
        "updated_at_utc": inc.updated_at_utc.isoformat(),
    }


@router.get("/incidents/{incident_id}/timeline")
def get_incident_timeline(
    incident_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    inc = _get_tenant_incident(db, principal.tenant_id, incident_id)
    events = (
        db.query(IncidentEvent)
        .filter(
            IncidentEvent.tenant_id == principal.tenant_id,
            IncidentEvent.incident_id == inc.id,
        )
        .order_by(IncidentEvent.event_timestamp_utc.asc())
        .all()
    )
    return [
        {
            "id": e.id,
            "event_timestamp_utc": e.event_timestamp_utc.isoformat(),
            "event_type": e.event_type,
            "description": e.description,
            "severity": e.severity,
            "component": e.component,
            "evidence_ref": e.evidence_ref,
        }
        for e in events
    ]


@router.get("/incidents/{incident_id}/hypotheses")
def get_incident_hypotheses(
    incident_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    inc = _get_tenant_incident(db, principal.tenant_id, incident_id)
    hyps = (
        db.query(RootCauseHypothesis)
        .filter(
            RootCauseHypothesis.tenant_id == principal.tenant_id,
            RootCauseHypothesis.incident_id == inc.id,
        )
        .order_by(RootCauseHypothesis.rank.asc())
        .all()
    )
    recs = (
        db.query(Recommendation)
        .filter(
            Recommendation.tenant_id == principal.tenant_id,
            Recommendation.incident_id == inc.id,
        )
        .order_by(Recommendation.priority.asc())
        .all()
    )
    return {
        "incident_id": inc.id,
        "incident_code": inc.incident_code,
        "hypotheses": [
            {
                "rank": h.rank,
                "hypothesis_type": h.hypothesis_type,
                "title": h.title,
                "explanation": h.explanation,
                "confidence_score": h.confidence_score,
                "confidence_method": h.confidence_method,
                "uncertainty_note": h.uncertainty_note,
                "supporting_evidence": h.supporting_evidence_json,
            }
            for h in hyps
        ],
        "recommendations": [
            {
                "priority": r.priority,
                "action_title": r.action_title,
                "rationale": r.rationale,
                "safety_note": r.safety_note,
                "requires_approval": r.requires_approval,
            }
            for r in recs
        ],
    }


@router.get("/incidents/{incident_id}/passport")
def get_incident_passport(
    incident_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    inc = _get_tenant_incident(db, principal.tenant_id, incident_id)
    passport = (
        db.query(IncidentPassport)
        .filter(
            IncidentPassport.tenant_id == principal.tenant_id,
            IncidentPassport.incident_id == inc.id,
        )
        .first()
    )
    if not passport:
        passport = regenerate_hypotheses_and_passport(db, inc)
        db.commit()
    return passport.passport_json


@router.post("/incidents/{incident_id}/status")
async def update_incident_status(
    incident_id: str,
    body: IncidentStatusUpdateRequest,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    allowed = {"OPEN", "INVESTIGATING", "RESOLVED"}
    new_status = body.status.strip().upper()
    if new_status not in allowed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Status must be one of {sorted(allowed)}",
        )
    inc = _get_tenant_incident(db, principal.tenant_id, incident_id)
    prev_status = inc.status
    inc.status = new_status
    inc.updated_at_utc = utc_now()

    passport = (
        db.query(IncidentPassport)
        .filter(
            IncidentPassport.tenant_id == principal.tenant_id,
            IncidentPassport.incident_id == inc.id,
        )
        .first()
    )
    if passport:
        history = list(passport.audit_history_json or [])
        history.append(
            {
                "timestamp_utc": utc_now().isoformat(),
                "action": "STATUS_UPDATED",
                "actor": principal.subject,
                "details": f"{prev_status} -> {new_status}" + (f" ({body.note})" if body.note else ""),
            }
        )
        passport.audit_history_json = history
        updated_json = dict(passport.passport_json)
        updated_json["status"] = new_status
        updated_json["audit_history"] = history
        passport.passport_json = updated_json

    db.commit()
    await ws_manager.broadcast_to_tenant(
        principal.tenant_id,
        "incident:updated",
        {"id": inc.id, "incident_code": inc.incident_code, "status": inc.status},
    )
    return {"id": inc.id, "incident_code": inc.incident_code, "status": inc.status}


@router.websocket("/ws/updates")
async def websocket_updates(
    websocket: WebSocket,
    token: str = Query(default=""),
) -> None:
    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    try:
        claims = decode_access_token(token)
        tenant_id = str(claims["tenant_id"])
    except Exception:  # noqa: BLE001
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await ws_manager.connect(tenant_id, websocket)
    try:
        await websocket.send_json(
            {"type": "ws:connected", "data": {"tenant_id": tenant_id, "timestamp_utc": utc_now().isoformat()}}
        )
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await ws_manager.disconnect(tenant_id, websocket)
