from typing import Any, Dict, List

import networkx as nx
from sqlalchemy.orm import Session

from app.core.security import utc_now
from app.engines.correlation_engine import COMPONENT_DEPENDENCY_GRAPH
from app.models.models import (
    Anomaly,
    Incident,
    IncidentEvent,
    IncidentPassport,
    Recommendation,
    RootCauseHypothesis,
)


def estimate_downstream_impact(components: List[str]) -> Dict[str, Any]:
    impacted = set(components)
    dependency_paths: List[str] = []

    for comp in components:
        if comp in COMPONENT_DEPENDENCY_GRAPH:
            descendants = nx.descendants(COMPONENT_DEPENDENCY_GRAPH, comp)
            for desc in sorted(descendants):
                impacted.add(desc)
                dependency_paths.append(f"{comp} -> {desc}")

    return {
        "estimated_affected_components": sorted(impacted),
        "dependency_paths": sorted(set(dependency_paths)),
        "impact_disclaimer": (
            "Estimated via static component dependency graph; downstream impact is probabilistic "
            "and requires operator verification."
        ),
    }


def regenerate_hypotheses_and_passport(db: Session, incident: Incident) -> IncidentPassport:
    """
    Deterministic explainable root-cause hypothesis ranking and Incident Passport generator.
    Never claims a root cause is confirmed; always cites evidence IDs and uncertainty.
    """
    evidence_ids = incident.evidence_ids_json or []
    anomalies = (
        db.query(Anomaly)
        .filter(Anomaly.tenant_id == incident.tenant_id, Anomaly.id.in_(evidence_ids))
        .all()
    )
    metrics_seen = {a.metric_name: a for a in anomalies}

    # Clear existing hypotheses & recommendations for fresh deterministic ranking
    db.query(RootCauseHypothesis).filter(
        RootCauseHypothesis.tenant_id == incident.tenant_id,
        RootCauseHypothesis.incident_id == incident.id,
    ).delete()
    db.query(Recommendation).filter(
        Recommendation.tenant_id == incident.tenant_id,
        Recommendation.incident_id == incident.id,
    ).delete()

    candidates: List[Dict[str, Any]] = []

    # 1. Resource bottleneck: high CPU + high memory (or strong single compute spike)
    if "cpu_usage" in metrics_seen or "memory_usage" in metrics_seen:
        both = "cpu_usage" in metrics_seen and "memory_usage" in metrics_seen
        ev = [
            metrics_seen[m].id
            for m in ("cpu_usage", "memory_usage")
            if m in metrics_seen
        ]
        score = 0.84 if both else 0.66
        candidates.append(
            {
                "hypothesis_type": "resource_bottleneck",
                "title": "Possible Compute Resource Bottleneck",
                "explanation": (
                    "Observed elevated CPU and memory utilization within the correlated incident "
                    "window. These measurements support a possible resource exhaustion bottleneck, "
                    "though local host process profiling is required before confirming root cause."
                ),
                "confidence_score": score,
                "confidence_method": "Deterministic weighted evidence scoring (CPU + Memory rule/baseline correlation)",
                "uncertainty_note": (
                    "Uncertain whether contention originates from traffic surge or runaway local process; "
                    "raw process lists stay local and are not inspected centrally."
                ),
                "supporting_evidence": ev,
                "recommendation": (
                    "Inspect local process CPU/memory allocation on affected host",
                    "Verify whether worker threads or database queries saturated compute capacity.",
                    "Read-only local inspection; no automated process termination is executed.",
                ),
            }
        )

    # 2. Network congestion: latency + packet loss
    if "network_latency_ms" in metrics_seen or "packet_loss_pct" in metrics_seen:
        both = "network_latency_ms" in metrics_seen and "packet_loss_pct" in metrics_seen
        ev = [
            metrics_seen[m].id
            for m in ("network_latency_ms", "packet_loss_pct")
            if m in metrics_seen
        ]
        score = 0.82 if both else 0.64
        candidates.append(
            {
                "hypothesis_type": "network_congestion",
                "title": "Possible Network Congestion or Link Loss",
                "explanation": (
                    "Elevated round-trip latency and/or packet loss were recorded across the "
                    "correlated window. Signals suggest network path congestion, but physical "
                    "link diagnostics are required to confirm."
                ),
                "confidence_score": score,
                "confidence_method": "Deterministic weighted evidence scoring (Latency + Packet-loss joint signal)",
                "uncertainty_note": (
                    "Central SaaS observes anonymized latency/loss metadata only; packet captures "
                    "and internal routing tables remain inside the customer boundary."
                ),
                "supporting_evidence": ev,
                "recommendation": (
                    "Check ingress interface saturation and upstream routing health",
                    "Validate switch/VPC packet drops and retry backpressure on ingress-network.",
                    "Safe diagnostic check; reversible traffic shaping requires human approval.",
                ),
            }
        )

    # 3. Service degradation: unavailable service / database
    if "service_status" in metrics_seen:
        ev = [metrics_seen["service_status"].id]
        candidates.append(
            {
                "hypothesis_type": "service_degradation",
                "title": "Possible Critical Service or Database Degradation",
                "explanation": (
                    "A monitored service reported unavailable/degraded status alongside correlated "
                    "telemetry shifts. Additional service health probes are needed to confirm whether "
                    "this is a primary failure or downstream symptom."
                ),
                "confidence_score": 0.78,
                "confidence_method": "Deterministic availability state correlation + dependency graph traversal",
                "uncertainty_note": (
                    "Cannot confirm root cause from availability metadata alone; application error "
                    "logs remain retained locally on the Tier 1 collector."
                ),
                "supporting_evidence": ev,
                "recommendation": (
                    "Verify dependent service readiness and connection pool saturation",
                    "Check database-cluster and upstream API health checks inside the local environment.",
                    "Requires operator approval prior to any service restart.",
                ),
            }
        )

    # 4. Security authentication anomaly
    if "failed_login_count" in metrics_seen:
        ev = [metrics_seen["failed_login_count"].id]
        candidates.append(
            {
                "hypothesis_type": "authentication_anomaly",
                "title": "Possible Repeated Authentication Failure Burst",
                "explanation": (
                    "Locally aggregated authentication failure counts exceeded policy thresholds. "
                    "This points to a possible credential stuffing or misconfigured service account, "
                    "requiring local identity-log review to confirm."
                ),
                "confidence_score": 0.76,
                "confidence_method": "Deterministic local security-signal threshold scoring",
                "uncertainty_note": (
                    "Usernames, source IPs, and raw auth logs never leave the local collector; "
                    "identity verification must occur locally."
                ),
                "supporting_evidence": ev,
                "recommendation": (
                    "Audit local identity-gateway logs for repeated failures",
                    "Review blocked/redacted local authentication events in Tier 1 SQLite store.",
                    "Policy-bounded alert only; account lockout requires human approval.",
                ),
            }
        )

    if not candidates:
        candidates.append(
            {
                "hypothesis_type": "multivariate_drift",
                "title": "Possible Multivariate Telemetry Deviation",
                "explanation": (
                    "IsolationForest flagged an unusual combination of resource and network metrics "
                    "relative to historical baselines. Further investigation is needed to confirm cause."
                ),
                "confidence_score": 0.58,
                "confidence_method": "IsolationForest multivariate anomaly score + baseline deviation",
                "uncertainty_note": (
                    "Unsupervised ML outliers indicate statistical novelty rather than a confirmed fault."
                ),
                "supporting_evidence": [a.id for a in anomalies],
                "recommendation": (
                    "Compare current telemetry window against 24-hour baseline",
                    "Review host resource changes and recent deployment schedules.",
                    "Advisory investigation step only.",
                ),
            }
        )

    candidates.sort(key=lambda c: c["confidence_score"], reverse=True)

    saved_hypotheses: List[Dict[str, Any]] = []
    saved_recommendations: List[Dict[str, Any]] = []

    for idx, cand in enumerate(candidates, start=1):
        hyp = RootCauseHypothesis(
            tenant_id=incident.tenant_id,
            incident_id=incident.id,
            rank=idx,
            hypothesis_type=cand["hypothesis_type"],
            title=cand["title"],
            explanation=cand["explanation"],
            confidence_score=cand["confidence_score"],
            confidence_method=cand["confidence_method"],
            uncertainty_note=cand["uncertainty_note"],
            supporting_evidence_json=cand["supporting_evidence"],
        )
        db.add(hyp)
        saved_hypotheses.append(
            {
                "rank": idx,
                "hypothesis_type": cand["hypothesis_type"],
                "title": cand["title"],
                "explanation": cand["explanation"],
                "confidence_score": cand["confidence_score"],
                "confidence_method": cand["confidence_method"],
                "uncertainty_note": cand["uncertainty_note"],
                "supporting_evidence": cand["supporting_evidence"],
            }
        )

        act_title, rationale, safety = cand["recommendation"]
        rec = Recommendation(
            tenant_id=incident.tenant_id,
            incident_id=incident.id,
            priority=idx,
            action_title=act_title,
            rationale=rationale,
            safety_note=safety,
            requires_approval=True,
        )
        db.add(rec)
        saved_recommendations.append(
            {
                "priority": idx,
                "action_title": act_title,
                "rationale": rationale,
                "safety_note": safety,
                "requires_approval": True,
            }
        )

    impact = estimate_downstream_impact(incident.affected_components_json or [])
    timeline_rows = (
        db.query(IncidentEvent)
        .filter(
            IncidentEvent.tenant_id == incident.tenant_id,
            IncidentEvent.incident_id == incident.id,
        )
        .order_by(IncidentEvent.event_timestamp_utc.asc())
        .all()
    )
    timeline_list = [
        {
            "event_timestamp_utc": ev.event_timestamp_utc.isoformat(),
            "event_type": ev.event_type,
            "description": ev.description,
            "severity": ev.severity,
            "component": ev.component,
            "evidence_ref": ev.evidence_ref,
        }
        for ev in timeline_rows
    ]

    existing_passport = (
        db.query(IncidentPassport)
        .filter(
            IncidentPassport.tenant_id == incident.tenant_id,
            IncidentPassport.incident_id == incident.id,
        )
        .first()
    )
    now_iso = utc_now().isoformat()
    audit_entry = {
        "timestamp_utc": now_iso,
        "action": "PASSPORT_SYNTHESIZED",
        "details": f"Generated {len(saved_hypotheses)} ranked hypothesis(es) from {len(evidence_ids)} evidence item(s).",
    }

    passport_payload = {
        "incident_id": incident.id,
        "incident_code": incident.incident_code,
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "detection_time_utc": incident.detected_at_utc.isoformat(),
        "source": incident.primary_source_id,
        "affected_components": incident.affected_components_json,
        "evidence_ids": evidence_ids,
        "timeline": timeline_list,
        "hypotheses": saved_hypotheses,
        "confidence": saved_hypotheses[0]["confidence_score"] if saved_hypotheses else 0.0,
        "confidence_method": saved_hypotheses[0]["confidence_method"] if saved_hypotheses else "N/A",
        "uncertainty": saved_hypotheses[0]["uncertainty_note"] if saved_hypotheses else "",
        "estimated_impact": impact,
        "recommendations": saved_recommendations,
    }

    if existing_passport:
        history = list(existing_passport.audit_history_json or [])
        history.append(audit_entry)
        passport_payload["audit_history"] = history
        existing_passport.passport_json = passport_payload
        existing_passport.estimated_impact_json = impact
        existing_passport.audit_history_json = history
        existing_passport.generated_at_utc = utc_now()
        db.flush()
        return existing_passport

    history = [audit_entry]
    passport_payload["audit_history"] = history
    passport = IncidentPassport(
        tenant_id=incident.tenant_id,
        incident_id=incident.id,
        passport_json=passport_payload,
        estimated_impact_json=impact,
        audit_history_json=history,
        generated_at_utc=utc_now(),
    )
    db.add(passport)
    db.flush()
    return passport
