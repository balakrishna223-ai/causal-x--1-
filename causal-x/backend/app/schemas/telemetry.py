from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TelemetryIngestEnvelope(BaseModel):
    payload_id: str
    collector_id: str
    tenant_slug: Optional[str] = None
    policy_version: str = "1.0.0"
    approved_metadata: Dict[str, Any]
    allowed_fields: List[str] = Field(default_factory=list)
    blocked_fields: List[str] = Field(default_factory=list)
    redacted_fields: List[str] = Field(default_factory=list)
    privacy_risk_score: int = 0
    raw_risk_score: int = 0
    classification_summary: Dict[str, str] = Field(default_factory=dict)
    payload_hash_sha256: str
    hmac_signature: str
    approval_decision: str = "APPROVED"
    created_at_utc: Optional[datetime] = None


class TelemetryIngestResponse(BaseModel):
    status: str  # accepted | duplicate_ignored
    payload_id: str
    verification_status: str
    anomalies_detected: int
    incident_code: Optional[str] = None


class HeartbeatRequest(BaseModel):
    collector_id: str
    version: str = "1.0.0"
    source_timezone: str = "UTC"
    cpu_pct: float = 0.0
    memory_mb: float = 0.0
    pending_outbox: int = 0


class EgressVerifyRequest(BaseModel):
    payload_id: Optional[str] = None
    approved_metadata: Dict[str, Any]
    payload_hash_sha256: str
    hmac_signature: Optional[str] = None


class EgressVerifyResponse(BaseModel):
    payload_id: Optional[str] = None
    hash_valid: bool
    hmac_valid: Optional[bool] = None
    computed_sha256: str
    verification_status: str
    checked_at_utc: datetime


class ThresholdUpdateRequest(BaseModel):
    cpu_threshold: float = Field(ge=10.0, le=100.0)
    memory_threshold: float = Field(ge=10.0, le=100.0)
    latency_threshold_ms: float = Field(ge=10.0, le=10000.0)
    packet_loss_threshold_pct: float = Field(ge=0.1, le=100.0)
    offline_timeout_seconds: int = Field(ge=15, le=600)


class IncidentStatusUpdateRequest(BaseModel):
    status: str  # OPEN | INVESTIGATING | RESOLVED
    note: Optional[str] = None
