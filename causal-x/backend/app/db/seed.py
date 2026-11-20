import os
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import hash_secret, utc_now
from app.models.models import Collector, Tenant, TenantThreshold, User


def seed_initial_data(db: Session) -> None:
    """
    Seed two isolated development tenants (Acme Cloud & Globex Fin) with
    operator accounts and collector registrations for tenant-isolation validation.
    """
    settings = get_settings()

    acme = db.query(Tenant).filter(Tenant.slug == "acme-cloud").first()
    if not acme:
        acme = Tenant(
            slug="acme-cloud",
            name="Acme Cloud Operations",
            region="us-east-1",
            residency_policy="us-east-1-strict",
        )
        db.add(acme)
        db.flush()

        db.add(
            User(
                tenant_id=acme.id,
                email="ops@acme-cloud.dev",
                full_name="Acme Site Reliability Lead",
                role="admin",
                hashed_password=hash_secret(
                    os.getenv("DEV_ACME_USER_PASS", "DevAcmePass!2026")
                ),
            )
        )
        db.add(
            Collector(
                tenant_id=acme.id,
                collector_id="collector-local-01",
                display_name="Primary Local Collector (Acme)",
                api_key_hash=hash_secret(
                    os.getenv("CAUSALX_COLLECTOR_API_KEY", "change-me-dev-collector-token")
                ),
                version="1.0.0",
                region="us-east-1",
                source_timezone="UTC",
                status="OFFLINE",
                last_seen_utc=None,
                config_json={"poll_seconds": 5, "policy_version": "1.0.0"},
            )
        )
        db.add(
            TenantThreshold(
                tenant_id=acme.id,
                cpu_threshold=settings.threshold_cpu_percent,
                memory_threshold=settings.threshold_memory_percent,
                latency_threshold_ms=settings.threshold_latency_ms,
                packet_loss_threshold_pct=settings.threshold_packet_loss_percent,
                offline_timeout_seconds=settings.collector_offline_timeout_seconds,
                updated_at_utc=utc_now(),
            )
        )

    globex = db.query(Tenant).filter(Tenant.slug == "globex-fin").first()
    if not globex:
        globex = Tenant(
            slug="globex-fin",
            name="Globex Financial Systems",
            region="eu-central-1",
            residency_policy="eu-central-1-gdpr",
        )
        db.add(globex)
        db.flush()

        db.add(
            User(
                tenant_id=globex.id,
                email="ops@globex-fin.dev",
                full_name="Globex Security Operations",
                role="admin",
                hashed_password=hash_secret(
                    os.getenv("DEV_GLOBEX_USER_PASS", "DevGlobexPass!2026")
                ),
            )
        )
        db.add(
            Collector(
                tenant_id=globex.id,
                collector_id="collector-globex-01",
                display_name="Frankfurt Edge Collector (Globex)",
                api_key_hash=hash_secret(
                    os.getenv("DEV_GLOBEX_COLLECTOR_KEY", "change-me-dev-globex-token")
                ),
                version="1.0.0",
                region="eu-central-1",
                source_timezone="Europe/Berlin",
                status="OFFLINE",
                last_seen_utc=None,
                config_json={"poll_seconds": 5, "policy_version": "1.0.0"},
            )
        )
        db.add(
            TenantThreshold(
                tenant_id=globex.id,
                cpu_threshold=settings.threshold_cpu_percent,
                memory_threshold=settings.threshold_memory_percent,
                latency_threshold_ms=settings.threshold_latency_ms,
                packet_loss_threshold_pct=settings.threshold_packet_loss_percent,
                offline_timeout_seconds=settings.collector_offline_timeout_seconds,
                updated_at_utc=utc_now(),
            )
        )

    db.commit()
