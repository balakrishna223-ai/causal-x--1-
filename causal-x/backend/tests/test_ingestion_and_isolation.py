from fastapi.testclient import TestClient

from app.core.config import get_settings
from privacy.shield import PrivacyShield
from proof.proof_engine import ProofEngine


def _auth_user(client: TestClient, email: str, password: str) -> str:
    resp = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200
    return resp.json()["access_token"]


def _auth_collector(client: TestClient, slug: str, cid: str, key: str) -> str:
    resp = client.post(
        "/api/v1/auth/login",
        json={"tenant_slug": slug, "collector_id": cid, "collector_api_key": key},
    )
    assert resp.status_code == 200
    return resp.json()["access_token"]


def test_idempotent_ingestion_and_event_time_ordering(client: TestClient) -> None:
    settings = get_settings()
    col_token = _auth_collector(
        client, "acme-cloud", "collector-local-01", "change-me-dev-collector-token"
    )
    user_token = _auth_user(client, "ops@acme-cloud.dev", "DevAcmePass!2026")
    shield = PrivacyShield(pseudonym_salt=settings.pseudonym_salt)
    proof = ProofEngine(hmac_secret=settings.collector_hmac_secret)

    # Send later timestamp first, earlier timestamp second (out-of-order)
    late_res = shield.apply(
        {"cpu_usage": 40.0, "memory_usage": 50.0, "event_timestamp_utc": "2026-11-20T12:05:00Z"},
        "collector-local-01",
    )
    late_env = proof.build_proof_envelope("collector-local-01", "acme-cloud", late_res, "pid-late")

    early_res = shield.apply(
        {"cpu_usage": 30.0, "memory_usage": 45.0, "event_timestamp_utc": "2026-11-20T12:00:00Z"},
        "collector-local-01",
    )
    early_env = proof.build_proof_envelope("collector-local-01", "acme-cloud", early_res, "pid-early")

    assert client.post(
        "/api/v1/telemetry", headers={"Authorization": f"Bearer {col_token}"}, json=late_env
    ).json()["status"] == "accepted"

    # Duplicate delivery of pid-late MUST be ignored idempotently
    dup_resp = client.post(
        "/api/v1/telemetry", headers={"Authorization": f"Bearer {col_token}"}, json=late_env
    )
    assert dup_resp.status_code == 200
    assert dup_resp.json()["status"] == "duplicate_ignored"

    assert client.post(
        "/api/v1/telemetry", headers={"Authorization": f"Bearer {col_token}"}, json=early_env
    ).json()["status"] == "accepted"

    rows = client.get(
        "/api/v1/telemetry", headers={"Authorization": f"Bearer {user_token}"}
    ).json()
    assert len(rows) == 2
    assert rows[0]["payload_id"] == "pid-early"
    assert rows[1]["payload_id"] == "pid-late"


def test_tenant_isolation_blocks_cross_tenant_access(client: TestClient) -> None:
    settings = get_settings()
    acme_col_token = _auth_collector(
        client, "acme-cloud", "collector-local-01", "change-me-dev-collector-token"
    )
    acme_user_token = _auth_user(client, "ops@acme-cloud.dev", "DevAcmePass!2026")
    globex_user_token = _auth_user(client, "ops@globex-fin.dev", "DevGlobexPass!2026")

    shield = PrivacyShield(pseudonym_salt=settings.pseudonym_salt)
    proof = ProofEngine(hmac_secret=settings.collector_hmac_secret)
    res = shield.apply(
        {
            "cpu_usage": 96.0,
            "memory_usage": 93.0,
            "component": "api-gateway",
            "event_timestamp_utc": "2026-11-20T12:10:00Z",
        },
        "collector-local-01",
    )
    env = proof.build_proof_envelope("collector-local-01", "acme-cloud", res, "acme-only-pid")
    ingest = client.post(
        "/api/v1/telemetry", headers={"Authorization": f"Bearer {acme_col_token}"}, json=env
    )
    assert ingest.status_code == 200

    acme_telemetry = client.get(
        "/api/v1/telemetry", headers={"Authorization": f"Bearer {acme_user_token}"}
    ).json()
    globex_telemetry = client.get(
        "/api/v1/telemetry", headers={"Authorization": f"Bearer {globex_user_token}"}
    ).json()
    assert len(acme_telemetry) == 1
    assert len(globex_telemetry) == 0

    acme_incidents = client.get(
        "/api/v1/incidents", headers={"Authorization": f"Bearer {acme_user_token}"}
    ).json()
    assert len(acme_incidents) == 1
    acme_inc_id = acme_incidents[0]["id"]

    # Tenant B (Globex) cannot read Tenant A's incident or passport
    globex_incidents = client.get(
        "/api/v1/incidents", headers={"Authorization": f"Bearer {globex_user_token}"}
    ).json()
    assert len(globex_incidents) == 0

    cross_resp = client.get(
        f"/api/v1/incidents/{acme_inc_id}/passport",
        headers={"Authorization": f"Bearer {globex_user_token}"},
    )
    assert cross_resp.status_code == 404


def test_gmail_registration_and_passwordless_login(client: TestClient) -> None:
    # 1. Register a Gmail operator with password and authenticate
    reg_resp = client.post(
        "/api/v1/auth/register",
        json={
            "email": "operator.demo@gmail.com",
            "password": "GmailOperator!2026",
            "full_name": "Demo Operator",
            "tenant_slug": "acme-cloud",
        },
    )
    assert reg_resp.status_code == 200
    reg_data = reg_resp.json()
    assert reg_data["tenant_slug"] == "acme-cloud"
    assert reg_data["subject"] == "operator.demo@gmail.com"

    # Standard Gmail + password login succeeds
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": "operator.demo@gmail.com", "password": "GmailOperator!2026"},
    )
    assert login_resp.status_code == 200

    # 2. Passwordless OTP flow (no password needed)
    otp_req = client.post(
        "/api/v1/auth/passwordless/request",
        json={"email": "nopass.operator@gmail.com", "tenant_slug": "globex-fin"},
    )
    assert otp_req.status_code == 200
    code = otp_req.json()["dev_verification_code"]
    assert code and len(code) == 6

    otp_verify = client.post(
        "/api/v1/auth/passwordless/verify",
        json={
            "email": "nopass.operator@gmail.com",
            "tenant_slug": "globex-fin",
            "code": code,
        },
    )
    assert otp_verify.status_code == 200
    assert otp_verify.json()["tenant_slug"] == "globex-fin"

    # 3. Instant passwordless sign-in (dev mode)
    instant_resp = client.post(
        "/api/v1/auth/passwordless/verify",
        json={
            "email": "instant.user@gmail.com",
            "tenant_slug": "acme-cloud",
            "instant": True,
        },
    )
    assert instant_resp.status_code == 200
    assert instant_resp.json()["access_token"]

