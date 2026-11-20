from datetime import timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import utc_now
from app.models.models import Collector
from app.services.ingestion_service import evaluate_offline_collectors
from buffer.sqlite_store import SQLiteCollectorStore
from privacy.shield import PrivacyShield
from proof.proof_engine import ProofEngine


def _auth_collector(client: TestClient) -> str:
    resp = client.post(
        "/api/v1/auth/login",
        json={
            "tenant_slug": "acme-cloud",
            "collector_id": "collector-local-01",
            "collector_api_key": "change-me-dev-collector-token",
        },
    )
    assert resp.status_code == 200
    return resp.json()["access_token"]


def _auth_user(client: TestClient) -> str:
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "ops@acme-cloud.dev", "password": "DevAcmePass!2026"},
    )
    assert resp.status_code == 200
    return resp.json()["access_token"]


def test_anomaly_correlation_and_incident_passport(client: TestClient) -> None:
    settings = get_settings()
    col_token = _auth_collector(client)
    user_token = _auth_user(client)
    shield = PrivacyShield(pseudonym_salt=settings.pseudonym_salt)
    proof = ProofEngine(hmac_secret=settings.collector_hmac_secret)

    # First spike: high CPU + memory on api-gateway
    ev1 = shield.apply(
        {
            "hostname": "node-1.internal",
            "component": "api-gateway",
            "cpu_usage": 95.5,
            "memory_usage": 93.1,
            "network_latency_ms": 25.0,
            "packet_loss_pct": 0.0,
            "event_timestamp_utc": "2026-11-20T14:00:00Z",
        },
        "collector-local-01",
    )
    r1 = client.post(
        "/api/v1/telemetry",
        headers={"Authorization": f"Bearer {col_token}"},
        json=proof.build_proof_envelope("collector-local-01", "acme-cloud", ev1, "corr-1"),
    )
    assert r1.status_code == 200
    assert r1.json()["anomalies_detected"] >= 2
    inc_code_1 = r1.json()["incident_code"]

    # Second related spike 2 minutes later on downstream database-cluster -> must correlate, NOT duplicate
    ev2 = shield.apply(
        {
            "hostname": "node-1.internal",
            "component": "database-cluster",
            "cpu_usage": 91.0,
            "memory_usage": 92.0,
            "network_latency_ms": 290.0,
            "packet_loss_pct": 7.5,
            "service_status": "unavailable",
            "event_timestamp_utc": "2026-11-20T14:02:00Z",
        },
        "collector-local-01",
    )
    r2 = client.post(
        "/api/v1/telemetry",
        headers={"Authorization": f"Bearer {col_token}"},
        json=proof.build_proof_envelope("collector-local-01", "acme-cloud", ev2, "corr-2"),
    )
    assert r2.status_code == 200
    assert r2.json()["incident_code"] == inc_code_1

    incidents = client.get(
        "/api/v1/incidents", headers={"Authorization": f"Bearer {user_token}"}
    ).json()
    assert len(incidents) == 1

    passport = client.get(
        f"/api/v1/incidents/{incidents[0]['id']}/passport",
        headers={"Authorization": f"Bearer {user_token}"},
    ).json()
    assert passport["incident_code"] == inc_code_1
    assert len(passport["hypotheses"]) >= 2
    assert "uncertainty" in passport
    assert "confirmed" not in passport["hypotheses"][0]["title"].lower()
    assert len(passport["timeline"]) >= 3
    assert len(passport["estimated_impact"]["estimated_affected_components"]) >= 2


def test_collector_sqlite_outbox_buffering_and_recovery(client: TestClient, tmp_path) -> None:
    settings = get_settings()
    col_token = _auth_collector(client)
    user_token = _auth_user(client)

    store = SQLiteCollectorStore(str(tmp_path / "outbox_test.db"))
    shield = PrivacyShield(pseudonym_salt=settings.pseudonym_salt)
    proof = ProofEngine(hmac_secret=settings.collector_hmac_secret)

    # Simulate backend unavailable -> enqueue 3 approved records in SQLite outbox
    for idx in range(3):
        res = shield.apply(
            {
                "cpu_usage": 42.0 + idx,
                "memory_usage": 51.0 + idx,
                "event_timestamp_utc": f"2026-11-20T15:0{idx}:00Z",
            },
            "collector-local-01",
        )
        env = proof.build_proof_envelope("collector-local-01", "acme-cloud", res, f"buf-{idx}")
        store.save_local_proof_and_enqueue(env)

    assert store.count_pending() == 3
    assert store.count_delivered() == 0

    # Simulate failed delivery attempt -> backoff scheduled
    due = store.get_due_outbox_items()
    assert len(due) == 3
    store.schedule_retry(due[0]["payload_id"], due[0]["retry_count"])

    # Simulate backend recovery -> flush pending items (plus duplicate test)
    for item in due:
        resp = client.post(
            "/api/v1/telemetry",
            headers={"Authorization": f"Bearer {col_token}"},
            json=item["envelope"],
        )
        assert resp.status_code == 200
        store.mark_delivered(item["payload_id"])

        # Re-sending same payload after reconnect does not create duplicates
        dup = client.post(
            "/api/v1/telemetry",
            headers={"Authorization": f"Bearer {col_token}"},
            json=item["envelope"],
        )
        assert dup.json()["status"] == "duplicate_ignored"

    assert store.count_pending() == 0
    assert store.count_delivered() == 3
    telemetry = client.get(
        "/api/v1/telemetry", headers={"Authorization": f"Bearer {user_token}"}
    ).json()
    assert len(telemetry) == 3


def test_collector_offline_detection(client: TestClient, db_session: Session) -> None:
    col_token = _auth_collector(client)
    hb_resp = client.post(
        "/api/v1/collectors/heartbeat",
        headers={"Authorization": f"Bearer {col_token}"},
        json={"collector_id": "collector-local-01", "version": "1.0.0", "cpu_pct": 1.2, "memory_mb": 42.0},
    )
    assert hb_resp.status_code == 200
    assert hb_resp.json()["status"] == "ONLINE"

    # Advance evaluation clock past 60s timeout
    future = utc_now() + timedelta(seconds=90)
    marked = evaluate_offline_collectors(db_session, now=future)
    assert len(marked) == 1
    assert marked[0].collector_id == "collector-local-01"
    assert marked[0].status == "OFFLINE"
