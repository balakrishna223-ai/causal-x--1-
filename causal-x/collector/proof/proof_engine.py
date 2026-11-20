from datetime import datetime, timezone
import hashlib
import hmac
import json
from typing import Any, Dict
import uuid

from privacy.shield import ShieldResult


def canonicalize_json(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_sha256(canonical_str: str) -> str:
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


def compute_hmac(secret: str, canonical_str: str) -> str:
    return hmac.new(
        secret.encode("utf-8"),
        canonical_str.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


class ProofEngine:
    """
    Generates UUID payload IDs, canonical JSON, SHA-256 payload hashes,
    and HMAC-SHA256 signatures before local proof persistence and transmission.
    """

    def __init__(self, hmac_secret: str, policy_version: str = "1.0.0") -> None:
        self.hmac_secret = hmac_secret
        self.policy_version = policy_version

    def build_proof_envelope(
        self,
        collector_id: str,
        tenant_slug: str,
        shield_result: ShieldResult,
        payload_id: str | None = None,
    ) -> Dict[str, Any]:
        pid = payload_id or str(uuid.uuid4())
        canonical_str = canonicalize_json(shield_result.approved_metadata)
        payload_hash = compute_sha256(canonical_str)
        hmac_sig = compute_hmac(self.hmac_secret, canonical_str)
        created_at = datetime.now(timezone.utc).isoformat()

        return {
            "payload_id": pid,
            "collector_id": collector_id,
            "tenant_slug": tenant_slug,
            "policy_version": self.policy_version,
            "approved_metadata": shield_result.approved_metadata,
            "allowed_fields": shield_result.allowed_fields,
            "blocked_fields": shield_result.blocked_fields,
            "redacted_fields": shield_result.redacted_fields,
            "privacy_risk_score": shield_result.egress_risk_score,
            "raw_risk_score": shield_result.raw_risk_score,
            "classification_summary": shield_result.classification_summary,
            "payload_hash_sha256": payload_hash,
            "hmac_signature": hmac_sig,
            "approval_decision": shield_result.approval_decision,
            "created_at_utc": created_at,
        }
