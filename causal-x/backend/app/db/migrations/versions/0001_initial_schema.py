"""Initial CAUSAL-X central schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-11-20 00:00:00.000000+00:00
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("slug", sa.String(64), nullable=False, unique=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("region", sa.String(64), nullable=False),
        sa.Column("residency_policy", sa.String(128), nullable=False),
        sa.Column("created_at_utc", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_tenants_slug", "tenants", ["slug"])

    op.create_table(
        "users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("email", sa.String(190), nullable=False, unique=True),
        sa.Column("full_name", sa.String(128), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("hashed_password", sa.String(256), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at_utc", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_users_tenant_id", "users", ["tenant_id"])
    op.create_index("ix_users_email", "users", ["email"])

    op.create_table(
        "collectors",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("collector_id", sa.String(128), nullable=False),
        sa.Column("display_name", sa.String(128), nullable=False),
        sa.Column("api_key_hash", sa.String(256), nullable=False),
        sa.Column("version", sa.String(32), nullable=False),
        sa.Column("region", sa.String(64), nullable=False),
        sa.Column("source_timezone", sa.String(64), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("last_seen_utc", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_cpu_pct", sa.Float(), nullable=False),
        sa.Column("last_mem_mb", sa.Float(), nullable=False),
        sa.Column("config_json", sa.JSON(), nullable=False),
        sa.Column("created_at_utc", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "collector_id", name="uq_tenant_collector"),
    )
    op.create_index("ix_collectors_tenant_id", "collectors", ["tenant_id"])
    op.create_index("ix_collectors_collector_id", "collectors", ["collector_id"])

    op.create_table(
        "collector_health",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("collector_id", sa.String(128), nullable=False),
        sa.Column("health_state", sa.String(24), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("cpu_pct", sa.Float(), nullable=False),
        sa.Column("memory_mb", sa.Float(), nullable=False),
        sa.Column("recorded_at_utc", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_collector_health_tenant_id", "collector_health", ["tenant_id"])

    op.create_table(
        "telemetry",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("collector_id", sa.String(128), nullable=False),
        sa.Column("payload_id", sa.String(64), nullable=False),
        sa.Column("source_id", sa.String(128), nullable=False),
        sa.Column("component", sa.String(128), nullable=False),
        sa.Column("event_category", sa.String(64), nullable=False),
        sa.Column("event_timestamp_utc", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ingested_at_utc", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_timezone", sa.String(64), nullable=False),
        sa.Column("cpu_usage", sa.Float(), nullable=False),
        sa.Column("memory_usage", sa.Float(), nullable=False),
        sa.Column("disk_usage", sa.Float(), nullable=False),
        sa.Column("network_latency_ms", sa.Float(), nullable=False),
        sa.Column("packet_loss_pct", sa.Float(), nullable=False),
        sa.Column("service_status", sa.String(32), nullable=False),
        sa.Column("failed_login_count", sa.Integer(), nullable=False),
        sa.Column("uptime_seconds", sa.Float(), nullable=False),
        sa.Column("severity", sa.String(24), nullable=False),
        sa.Column("is_simulation", sa.Boolean(), nullable=False),
        sa.Column("extra_metadata_json", sa.JSON(), nullable=False),
        sa.UniqueConstraint("tenant_id", "payload_id", name="uq_telemetry_tenant_payload"),
    )
    op.create_index("ix_telemetry_tenant_event_time", "telemetry", ["tenant_id", "event_timestamp_utc"])

    op.create_table(
        "egress_proofs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("collector_id", sa.String(128), nullable=False),
        sa.Column("payload_id", sa.String(64), nullable=False),
        sa.Column("source_id", sa.String(128), nullable=False),
        sa.Column("event_timestamp_utc", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_metadata_json", sa.JSON(), nullable=False),
        sa.Column("allowed_fields_json", sa.JSON(), nullable=False),
        sa.Column("blocked_fields_json", sa.JSON(), nullable=False),
        sa.Column("policy_version", sa.String(32), nullable=False),
        sa.Column("privacy_risk_score", sa.Integer(), nullable=False),
        sa.Column("payload_hash_sha256", sa.String(64), nullable=False),
        sa.Column("hmac_signature", sa.String(128), nullable=False),
        sa.Column("verification_status", sa.String(24), nullable=False),
        sa.Column("approval_decision", sa.String(24), nullable=False),
        sa.Column("delivery_status", sa.String(32), nullable=False),
        sa.Column("created_at_utc", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "payload_id", name="uq_egress_tenant_payload"),
    )
    op.create_index("ix_egress_proofs_tenant_id", "egress_proofs", ["tenant_id"])

    op.create_table(
        "privacy_audits",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("collector_id", sa.String(128), nullable=False),
        sa.Column("payload_id", sa.String(64), nullable=False),
        sa.Column("classification_summary_json", sa.JSON(), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("decision", sa.String(24), nullable=False),
        sa.Column("policy_version", sa.String(32), nullable=False),
        sa.Column("recorded_at_utc", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "anomalies",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("collector_id", sa.String(128), nullable=False),
        sa.Column("telemetry_id", sa.String(36), sa.ForeignKey("telemetry.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_id", sa.String(128), nullable=False),
        sa.Column("component", sa.String(128), nullable=False),
        sa.Column("metric_name", sa.String(64), nullable=False),
        sa.Column("metric_value", sa.Float(), nullable=False),
        sa.Column("baseline_mean", sa.Float(), nullable=True),
        sa.Column("baseline_std", sa.Float(), nullable=True),
        sa.Column("detection_method", sa.String(24), nullable=False),
        sa.Column("severity", sa.String(24), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("contributing_signals_json", sa.JSON(), nullable=False),
        sa.Column("detected_at_utc", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_anomalies_tenant_id", "anomalies", ["tenant_id"])

    op.create_table(
        "incidents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("incident_code", sa.String(32), nullable=False),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("severity", sa.String(24), nullable=False),
        sa.Column("primary_source_id", sa.String(128), nullable=False),
        sa.Column("affected_components_json", sa.JSON(), nullable=False),
        sa.Column("evidence_ids_json", sa.JSON(), nullable=False),
        sa.Column("correlation_score", sa.Float(), nullable=False),
        sa.Column("detected_at_utc", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at_utc", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_incidents_tenant_id", "incidents", ["tenant_id"])

    op.create_table(
        "incident_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("incident_id", sa.String(36), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_timestamp_utc", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(24), nullable=False),
        sa.Column("component", sa.String(128), nullable=False),
        sa.Column("evidence_ref", sa.String(128), nullable=False),
    )

    op.create_table(
        "root_cause_hypotheses",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("incident_id", sa.String(36), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("rank", sa.Integer(), nullable=False),
        sa.Column("hypothesis_type", sa.String(64), nullable=False),
        sa.Column("title", sa.String(190), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("confidence_score", sa.Float(), nullable=False),
        sa.Column("confidence_method", sa.String(128), nullable=False),
        sa.Column("uncertainty_note", sa.Text(), nullable=False),
        sa.Column("supporting_evidence_json", sa.JSON(), nullable=False),
    )

    op.create_table(
        "recommendations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("incident_id", sa.String(36), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("action_title", sa.String(190), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("safety_note", sa.Text(), nullable=False),
        sa.Column("requires_approval", sa.Boolean(), nullable=False),
    )

    op.create_table(
        "incident_passports",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("incident_id", sa.String(36), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("passport_json", sa.JSON(), nullable=False),
        sa.Column("estimated_impact_json", sa.JSON(), nullable=False),
        sa.Column("audit_history_json", sa.JSON(), nullable=False),
        sa.Column("generated_at_utc", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "tenant_thresholds",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("cpu_threshold", sa.Float(), nullable=False),
        sa.Column("memory_threshold", sa.Float(), nullable=False),
        sa.Column("latency_threshold_ms", sa.Float(), nullable=False),
        sa.Column("packet_loss_threshold_pct", sa.Float(), nullable=False),
        sa.Column("offline_timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("updated_at_utc", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "passwordless_codes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("email", sa.String(190), nullable=False),
        sa.Column("code_hash", sa.String(128), nullable=False),
        sa.Column("expires_at_utc", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used", sa.Boolean(), nullable=False),
        sa.Column("created_at_utc", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_passwordless_codes_email", "passwordless_codes", ["email"])


def downgrade() -> None:
    for table in [
        "passwordless_codes",
        "tenant_thresholds",
        "incident_passports",
        "recommendations",
        "root_cause_hypotheses",
        "incident_events",
        "incidents",
        "anomalies",
        "privacy_audits",
        "egress_proofs",
        "telemetry",
        "collector_health",
        "collectors",
        "users",
        "tenants",
    ]:
        op.drop_table(table)
