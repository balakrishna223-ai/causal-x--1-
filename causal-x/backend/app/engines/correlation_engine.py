from datetime import timedelta
from typing import List, Tuple

import networkx as nx
from sqlalchemy.orm import Session

from app.core.security import utc_now
from app.models.models import Anomaly, Incident, IncidentEvent, TelemetryRecord


COMPONENT_DEPENDENCY_GRAPH = nx.DiGraph()
COMPONENT_DEPENDENCY_GRAPH.add_edges_from(
    [
        ("ingress-network", "api-gateway"),
        ("identity-gateway", "auth-service"),
        ("api-gateway", "auth-service"),
        ("api-gateway", "analytics-worker"),
        ("api-gateway", "database-cluster"),
        ("analytics-worker", "database-cluster"),
        ("host-system", "api-gateway"),
        ("host-system", "database-cluster"),
    ]
)


def _severity_rank(sev: str) -> int:
    return {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}.get(sev, 2)


def _components_related(comp_a: str, comp_b: str) -> bool:
    if comp_a == comp_b:
        return True
    undirected = COMPONENT_DEPENDENCY_GRAPH.to_undirected()
    if comp_a in undirected and comp_b in undirected:
        return nx.has_path(undirected, comp_a, comp_b)
    return False


def _next_incident_code(db: Session, tenant_id: str) -> str:
    count = db.query(Incident).filter(Incident.tenant_id == tenant_id).count()
    return f"INC-{1001 + count}"


def _derive_incident_title(anomalies: List[Anomaly]) -> str:
    metrics = {a.metric_name for a in anomalies}
    if "service_status" in metrics and ({"cpu_usage", "memory_usage"} & metrics):
        return "Cascading Compute & Service Degradation"
    if "service_status" in metrics:
        return "Critical Service Degradation"
    if "failed_login_count" in metrics:
        return "Repeated Authentication Failure Signal"
    if {"cpu_usage", "memory_usage"}.issubset(metrics):
        return "Compute Resource Bottleneck"
    if {"network_latency_ms", "packet_loss_pct"} & metrics:
        return "Network Congestion & Latency Degradation"
    return "Operational Performance Anomaly"


def correlate_anomalies_into_incident(
    db: Session,
    record: TelemetryRecord,
    new_anomalies: List[Anomaly],
) -> Tuple[Incident | None, bool]:
    """
    Group related anomalies by tenant, source, component dependency graph, category,
    and 10-minute sliding time window. Prevents duplicate incidents for ongoing problems.
    Returns (incident, created_new_bool).
    """
    if not new_anomalies:
        return None, False

    window_start = record.event_timestamp_utc - timedelta(minutes=10)
    window_end = record.event_timestamp_utc + timedelta(minutes=10)

    open_incidents = (
        db.query(Incident)
        .filter(
            Incident.tenant_id == record.tenant_id,
            Incident.status.in_(["OPEN", "INVESTIGATING"]),
            Incident.detected_at_utc >= window_start,
            Incident.detected_at_utc <= window_end,
        )
        .order_by(Incident.detected_at_utc.desc())
        .all()
    )

    matched_incident: Incident | None = None
    for candidate in open_incidents:
        existing_components = candidate.affected_components_json or []
        same_source = candidate.primary_source_id == record.source_id
        related_component = any(
            _components_related(record.component, c) for c in existing_components
        )
        if same_source or related_component:
            matched_incident = candidate
            break

    max_sev = max(new_anomalies, key=lambda a: _severity_rank(a.severity)).severity
    created_new = False

    if matched_incident is None:
        matched_incident = Incident(
            tenant_id=record.tenant_id,
            incident_code=_next_incident_code(db, record.tenant_id),
            title=_derive_incident_title(new_anomalies),
            status="OPEN",
            severity=max_sev,
            primary_source_id=record.source_id,
            affected_components_json=[record.component],
            evidence_ids_json=[record.payload_id] + [a.id for a in new_anomalies],
            correlation_score=round(min(0.98, 0.68 + 0.08 * len(new_anomalies)), 2),
            detected_at_utc=record.event_timestamp_utc,
            updated_at_utc=utc_now(),
        )
        db.add(matched_incident)
        db.flush()
        created_new = True

        db.add(
            IncidentEvent(
                tenant_id=record.tenant_id,
                incident_id=matched_incident.id,
                event_timestamp_utc=record.event_timestamp_utc,
                event_type="INCIDENT_CREATED",
                description=f"Correlated incident {matched_incident.incident_code} opened from {len(new_anomalies)} anomaly signal(s).",
                severity=max_sev,
                component=record.component,
                evidence_ref=record.payload_id,
            )
        )
    else:
        components = set(matched_incident.affected_components_json or [])
        components.add(record.component)
        matched_incident.affected_components_json = sorted(components)

        evidence = list(matched_incident.evidence_ids_json or [])
        for ev_id in [record.payload_id] + [a.id for a in new_anomalies]:
            if ev_id not in evidence:
                evidence.append(ev_id)
        matched_incident.evidence_ids_json = evidence

        if _severity_rank(max_sev) > _severity_rank(matched_incident.severity):
            matched_incident.severity = max_sev
        matched_incident.correlation_score = round(
            min(0.99, matched_incident.correlation_score + 0.05 * len(new_anomalies)), 2
        )
        matched_incident.updated_at_utc = utc_now()

        # Re-evaluate title across all incident anomalies
        all_anomalies = (
            db.query(Anomaly)
            .filter(
                Anomaly.tenant_id == record.tenant_id,
                Anomaly.id.in_(evidence),
            )
            .all()
        )
        if all_anomalies:
            matched_incident.title = _derive_incident_title(all_anomalies)

    for anomaly in new_anomalies:
        db.add(
            IncidentEvent(
                tenant_id=record.tenant_id,
                incident_id=matched_incident.id,
                event_timestamp_utc=anomaly.detected_at_utc,
                event_type=f"ANOMALY_{anomaly.detection_method.upper()}",
                description=anomaly.description,
                severity=anomaly.severity,
                component=anomaly.component,
                evidence_ref=anomaly.id,
            )
        )

    db.flush()
    return matched_incident, created_new
