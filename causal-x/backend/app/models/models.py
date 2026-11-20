from datetime import datetime, timezone
import uuid
from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    return str(uuid.uuid4())


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    region: Mapped[str] = mapped_column(String(64), nullable=False, default="us-east-1")
    residency_policy: Mapped[str] = mapped_column(
        String(128), nullable=False, default="strict-regional-pinning"
    )
    created_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    users: Mapped[list["User"]] = relationship(back_populates="tenant", cascade="all, delete-orphan")
    collectors: Mapped[list["Collector"]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan"
    )


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(String(190), unique=True, nullable=False, index=True)
    full_name: Mapped[str] = mapped_column(String(128), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="operator")
    hashed_password: Mapped[str] = mapped_column(String(256), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    tenant: Mapped["Tenant"] = relationship(back_populates="users")


class Collector(Base):
    __tablename__ = "collectors"
    __table_args__ = (
        UniqueConstraint("tenant_id", "collector_id", name="uq_tenant_collector"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    collector_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    api_key_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    region: Mapped[str] = mapped_column(String(64), nullable=False, default="us-east-1")
    source_timezone: Mapped[str] = mapped_column(String(64), nullable=False, default="UTC")
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="ONLINE")
    last_seen_utc: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_cpu_pct: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    last_mem_mb: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    config_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    tenant: Mapped["Tenant"] = relationship(back_populates="collectors")


class CollectorHealth(Base):
    __tablename__ = "collector_health"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    collector_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    health_state: Mapped[str] = mapped_column(String(24), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    cpu_pct: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    memory_mb: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    recorded_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )


class TelemetryRecord(Base):
    __tablename__ = "telemetry"
    __table_args__ = (
        UniqueConstraint("tenant_id", "payload_id", name="uq_telemetry_tenant_payload"),
        Index("ix_telemetry_tenant_event_time", "tenant_id", "event_timestamp_utc"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    collector_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    payload_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    component: Mapped[str] = mapped_column(String(128), nullable=False, default="host-system")
    event_category: Mapped[str] = mapped_column(String(64), nullable=False, default="infrastructure")
    event_timestamp_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    ingested_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    source_timezone: Mapped[str] = mapped_column(String(64), nullable=False, default="UTC")
    cpu_usage: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    memory_usage: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    disk_usage: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    network_latency_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    packet_loss_pct: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    service_status: Mapped[str] = mapped_column(String(32), nullable=False, default="healthy")
    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    uptime_seconds: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    severity: Mapped[str] = mapped_column(String(24), nullable=False, default="LOW")
    is_simulation: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    extra_metadata_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class EgressProof(Base):
    __tablename__ = "egress_proofs"
    __table_args__ = (
        UniqueConstraint("tenant_id", "payload_id", name="uq_egress_tenant_payload"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    collector_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    payload_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source_id: Mapped[str] = mapped_column(String(128), nullable=False)
    event_timestamp_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    approved_metadata_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    allowed_fields_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    blocked_fields_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    policy_version: Mapped[str] = mapped_column(String(32), nullable=False)
    privacy_risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    payload_hash_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    hmac_signature: Mapped[str] = mapped_column(String(128), nullable=False)
    verification_status: Mapped[str] = mapped_column(String(24), nullable=False, default="VERIFIED")
    approval_decision: Mapped[str] = mapped_column(String(24), nullable=False, default="APPROVED")
    delivery_status: Mapped[str] = mapped_column(String(32), nullable=False, default="DELIVERED")
    created_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class PrivacyAudit(Base):
    __tablename__ = "privacy_audits"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    collector_id: Mapped[str] = mapped_column(String(128), nullable=False)
    payload_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    classification_summary_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    decision: Mapped[str] = mapped_column(String(24), nullable=False, default="APPROVED")
    policy_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    recorded_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )


class Anomaly(Base):
    __tablename__ = "anomalies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    collector_id: Mapped[str] = mapped_column(String(128), nullable=False)
    telemetry_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("telemetry.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source_id: Mapped[str] = mapped_column(String(128), nullable=False)
    component: Mapped[str] = mapped_column(String(128), nullable=False)
    metric_name: Mapped[str] = mapped_column(String(64), nullable=False)
    metric_value: Mapped[float] = mapped_column(Float, nullable=False)
    baseline_mean: Mapped[float | None] = mapped_column(Float, nullable=True)
    baseline_std: Mapped[float | None] = mapped_column(Float, nullable=True)
    detection_method: Mapped[str] = mapped_column(String(24), nullable=False)
    severity: Mapped[str] = mapped_column(String(24), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    contributing_signals_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    detected_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    incident_code: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="OPEN")
    severity: Mapped[str] = mapped_column(String(24), nullable=False, default="Medium")
    primary_source_id: Mapped[str] = mapped_column(String(128), nullable=False)
    affected_components_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    evidence_ids_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    correlation_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    detected_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    updated_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    incident_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_timestamp_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(24), nullable=False)
    component: Mapped[str] = mapped_column(String(128), nullable=False)
    evidence_ref: Mapped[str] = mapped_column(String(128), nullable=False)


class RootCauseHypothesis(Base):
    __tablename__ = "root_cause_hypotheses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    incident_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    rank: Mapped[int] = mapped_column(Integer, nullable=False)
    hypothesis_type: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(190), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False)
    confidence_method: Mapped[str] = mapped_column(String(128), nullable=False)
    uncertainty_note: Mapped[str] = mapped_column(Text, nullable=False)
    supporting_evidence_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)


class Recommendation(Base):
    __tablename__ = "recommendations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    incident_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    action_title: Mapped[str] = mapped_column(String(190), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    safety_note: Mapped[str] = mapped_column(Text, nullable=False)
    requires_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class IncidentPassport(Base):
    __tablename__ = "incident_passports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    incident_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    passport_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    estimated_impact_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    audit_history_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    generated_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class TenantThreshold(Base):
    __tablename__ = "tenant_thresholds"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    cpu_threshold: Mapped[float] = mapped_column(Float, nullable=False, default=90.0)
    memory_threshold: Mapped[float] = mapped_column(Float, nullable=False, default=90.0)
    latency_threshold_ms: Mapped[float] = mapped_column(Float, nullable=False, default=200.0)
    packet_loss_threshold_pct: Mapped[float] = mapped_column(Float, nullable=False, default=5.0)
    offline_timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    updated_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class PasswordlessCode(Base):
    __tablename__ = "passwordless_codes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(String(190), nullable=False, index=True)
    code_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    expires_at_utc: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at_utc: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

