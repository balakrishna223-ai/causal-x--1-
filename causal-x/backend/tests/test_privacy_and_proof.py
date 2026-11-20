from fastapi.testclient import TestClient

from app.core.config import get_settings
from privacy.classifier import ClassificationLevel, classify_record
from privacy.shield import PrivacyShield
from proof.proof_engine import ProofEngine


def _login_collector(client: TestClient, tenant_slug: str, collector_id: str, api_key: str) -> str:
    resp = client.post(
        "/api/v1/auth/login",
        json={
            "tenant_slug": tenant_slug,
            "collector_id": collector_id,
            "collector_api_key": api_key,
        },
    )
    assert resp.status_code == 200
    return resp.json()["access_token"]


def test_restricted_data_blocked_locally_and_never_in_outbound_payload() -> None:
    shield = PrivacyShield(pseudonym_salt="test-salt", policy_version="1.0.0")
    raw_event = {
        "event_id": "evt-001",
        "hostname": "prod-secret-host.internal",
        "username": "root_admin",
        "password": "SUPER_SECRET_PASSWORD_123",
        "api_key": "sk_live_TESTKEY9999999999",
        "raw_log": "Bearer eyJhbGciOiJIUzI1NiJ9.secretpayload",
        "cpu_usage": 88.5,
        "memory_usage": 79.2,
        "event_timestamp_utc": "2026-11-20T10:30:00Z",
        "source_timezone": "UTC",
    }

    _, raw_risk = classify_record(raw_event)
    assert raw_risk == 100

    # Direct un-sanitized outbound candidate MUST be blocked with score 100
    allowed, direct_risk = PrivacyShield.evaluate_outbound_candidate(raw_event)
    assert allowed is False
    assert direct_risk == 100

    # Sanitized egress payload strips restricted/sensitive fields completely
    result = shield.apply(raw_event, collector_id="collector-local-01")
    assert result.approval_decision == "APPROVED"
    assert result.egress_risk_score == 0
    assert "password" in result.blocked_fields
    assert "api_key" in result.blocked_fields
    assert "raw_log" in result.blocked_fields
    assert "username" in result.redacted_fields
    assert "hostname" in result.redacted_fields

    outbound_keys = set(result.approved_metadata.keys())
    assert not (outbound_keys & {"password", "api_key", "raw_log", "username", "hostname"})
    assert result.approved_metadata["source_id"].startswith("src_")


def test_central_backend_rejects_restricted_fields_and_verifies_hmac(client: TestClient) -> None:
    settings = get_settings()
    token = _login_collector(
        client, "acme-cloud", "collector-local-01", "change-me-dev-collector-token"
    )
    proof_engine = ProofEngine(hmac_secret=settings.collector_hmac_secret, policy_version="1.0.0")
    shield = PrivacyShield(pseudonym_salt=settings.pseudonym_salt, policy_version="1.0.0")

    raw_event = {
        "hostname": "db-01.internal",
        "password": "MUST_NOT_REACH_BACKEND",
        "cpu_usage": 55.0,
        "memory_usage": 60.0,
        "event_timestamp_utc": "2026-11-20T10:35:00Z",
    }
    shield_result = shield.apply(raw_event, "collector-local-01")
    envelope = proof_engine.build_proof_envelope("collector-local-01", "acme-cloud", shield_result)

    # 1. Valid proof succeeds
    ok_resp = client.post(
        "/api/v1/telemetry",
        headers={"Authorization": f"Bearer {token}"},
        json=envelope,
    )
    assert ok_resp.status_code == 200
    assert ok_resp.json()["verification_status"] == "VERIFIED"

    # 2. Tampered payload fails hash/HMAC verification
    tampered = dict(envelope)
    tampered["payload_id"] = "tampered-id-001"
    tampered["approved_metadata"] = {**envelope["approved_metadata"], "cpu_usage": 99.9}
    bad_resp = client.post(
        "/api/v1/telemetry",
        headers={"Authorization": f"Bearer {token}"},
        json=tampered,
    )
    assert bad_resp.status_code == 400

    # 3. Direct restricted field injection is rejected with 422
    rogue = dict(envelope)
    rogue["payload_id"] = "rogue-id-002"
    rogue["approved_metadata"] = {**envelope["approved_metadata"], "password": "leak"}
    rogue_resp = client.post(
        "/api/v1/telemetry",
        headers={"Authorization": f"Bearer {token}"},
        json=rogue,
    )
    assert rogue_resp.status_code == 422

    # 4. Egress verify endpoint confirms original integrity
    verify_resp = client.post(
        "/api/v1/egress/verify",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "payload_id": envelope["payload_id"],
            "approved_metadata": envelope["approved_metadata"],
            "payload_hash_sha256": envelope["payload_hash_sha256"],
            "hmac_signature": envelope["hmac_signature"],
        },
    )
    assert verify_resp.status_code == 200
    assert verify_resp.json()["hash_valid"] is True
    assert verify_resp.json()["hmac_valid"] is True
