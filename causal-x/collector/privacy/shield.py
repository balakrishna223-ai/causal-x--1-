from dataclasses import dataclass
import hashlib
import hmac
from typing import Any, Dict, List

from privacy.classifier import (
    ClassificationLevel,
    SAFE_ALLOW_LIST,
    classify_record,
)


def pseudonymize_identifier(raw_identifier: str, salt: str) -> str:
    """Deterministic salted HMAC-SHA256 pseudonymization (never Python hash())."""
    digest = hmac.new(
        salt.encode("utf-8"),
        raw_identifier.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"src_{digest[:16]}"


@dataclass
class ShieldResult:
    approved_metadata: Dict[str, Any]
    allowed_fields: List[str]
    blocked_fields: List[str]
    redacted_fields: List[str]
    raw_risk_score: int
    egress_risk_score: int
    approval_decision: str  # APPROVED or BLOCKED
    classification_summary: Dict[str, str]


class PrivacyShield:
    """
    Tier 1 Privacy Shield. Runs strictly inside the local collector BEFORE any
    outbound HTTP request is constructed.
    """

    def __init__(self, pseudonym_salt: str, policy_version: str = "1.0.0") -> None:
        self.pseudonym_salt = pseudonym_salt
        self.policy_version = policy_version

    def _derive_severity(self, record: Dict[str, Any]) -> str:
        cpu = float(record.get("cpu_usage", 0.0) or 0.0)
        mem = float(record.get("memory_usage", 0.0) or 0.0)
        lat = float(record.get("network_latency_ms", 0.0) or 0.0)
        loss = float(record.get("packet_loss_pct", 0.0) or 0.0)
        status = str(record.get("service_status", "healthy")).lower()
        failed_logins = int(record.get("failed_login_count", 0) or 0)

        if status in ("unavailable", "down", "critical") or cpu >= 95 or mem >= 95:
            return "CRITICAL"
        if cpu > 90 or mem > 90 or lat > 200 or loss > 5 or failed_logins >= 10:
            return "HIGH"
        if cpu > 75 or mem > 75 or lat > 120 or loss > 2:
            return "MEDIUM"
        return "LOW"

    def apply(self, raw_record: Dict[str, Any], collector_id: str) -> ShieldResult:
        classifications, raw_risk_score = classify_record(raw_record)

        blocked_fields: List[str] = []
        redacted_fields: List[str] = []
        classification_summary: Dict[str, str] = {}
        candidate_metadata: Dict[str, Any] = {}

        # Pseudonymize source identifier deterministically
        raw_source = (
            raw_record.get("hostname")
            or raw_record.get("server_id")
            or raw_record.get("source_id")
            or collector_id
        )
        if str(raw_source).startswith("src_"):
            candidate_metadata["source_id"] = str(raw_source)
        else:
            candidate_metadata["source_id"] = pseudonymize_identifier(
                str(raw_source), self.pseudonym_salt
            )

        for item in classifications:
            classification_summary[item.field_name] = item.level.value
            if item.level == ClassificationLevel.RESTRICTED:
                blocked_fields.append(item.field_name)
                continue
            if item.level == ClassificationLevel.SENSITIVE:
                redacted_fields.append(item.field_name)
                continue
            if item.level == ClassificationLevel.UNAPPROVED:
                blocked_fields.append(item.field_name)
                continue
            if item.field_name in SAFE_ALLOW_LIST and item.field_name != "source_id":
                candidate_metadata[item.field_name] = raw_record[item.field_name]

        # Ensure essential metadata fields are normalized
        candidate_metadata["collector_id"] = collector_id
        candidate_metadata.setdefault("component", str(raw_record.get("component", "host-system")))
        candidate_metadata.setdefault(
            "event_category", str(raw_record.get("event_category", "infrastructure"))
        )
        candidate_metadata.setdefault("source_timezone", str(raw_record.get("source_timezone", "UTC")))
        candidate_metadata.setdefault("severity", self._derive_severity(raw_record))
        candidate_metadata.setdefault("is_simulation", bool(raw_record.get("is_simulation", False)))

        # Final egress gate verification: outbound payload itself MUST score 0
        _, egress_risk_score = classify_record(candidate_metadata)
        approval_decision = "APPROVED" if egress_risk_score < 100 and egress_risk_score == 0 else "BLOCKED"

        if approval_decision == "BLOCKED":
            candidate_metadata = {}

        return ShieldResult(
            approved_metadata=candidate_metadata,
            allowed_fields=sorted(candidate_metadata.keys()),
            blocked_fields=sorted(set(blocked_fields)),
            redacted_fields=sorted(set(redacted_fields)),
            raw_risk_score=raw_risk_score,
            egress_risk_score=egress_risk_score,
            approval_decision=approval_decision,
            classification_summary=classification_summary,
        )

    @staticmethod
    def evaluate_outbound_candidate(payload: Dict[str, Any]) -> tuple[bool, int]:
        """
        Strict outbound check: if an un-sanitized payload with RESTRICTED fields
        is evaluated directly, risk score is 100 and transmission is BLOCKED.
        """
        _, risk = classify_record(payload)
        return (risk < 100 and risk == 0), risk
