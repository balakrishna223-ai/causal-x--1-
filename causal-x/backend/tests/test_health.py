from fastapi.testclient import TestClient

from app.api import routes_health
from app.main import app


def test_health_endpoint_returns_utc_and_status(monkeypatch) -> None:
    monkeypatch.setattr(routes_health, "check_db_connection", lambda: (True, "connected"))
    client = TestClient(app)
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "CAUSAL-X"
    assert body["database"] == "connected"
    assert "timestamp_utc" in body


def test_health_endpoint_reports_degraded_when_db_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(
        routes_health,
        "check_db_connection",
        lambda: (False, "disconnected: OperationalError"),
    )
    client = TestClient(app)
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert body["database"].startswith("disconnected")
