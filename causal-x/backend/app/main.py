import asyncio
from contextlib import asynccontextmanager, suppress
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes_auth import router as auth_router
from app.api.routes_health import router as health_router
from app.api.routes_incidents import router as incidents_router
from app.api.routes_telemetry import router as telemetry_router
from app.core.config import get_settings
from app.db.seed import seed_initial_data
from app.db.session import Base, SessionLocal, engine
import app.models  # noqa: F401
from app.services.ingestion_service import evaluate_offline_collectors
from app.services.ws_manager import ws_manager

settings = get_settings()


async def _collector_offline_monitor_loop() -> None:
    while True:
        await asyncio.sleep(15)
        db = SessionLocal()
        try:
            marked = evaluate_offline_collectors(db)
            for col in marked:
                await ws_manager.broadcast_to_tenant(
                    col.tenant_id,
                    "collector:status",
                    {
                        "collector_id": col.collector_id,
                        "status": "OFFLINE",
                        "last_seen_utc": col.last_seen_utc.isoformat() if col.last_seen_utc else None,
                    },
                )
        except Exception:  # noqa: BLE001
            pass
        finally:
            db.close()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    try:
        Base.metadata.create_all(bind=engine)
        db = SessionLocal()
        try:
            seed_initial_data(db)
        finally:
            db.close()
    except Exception:  # noqa: BLE001
        pass

    monitor_task = asyncio.create_task(_collector_offline_monitor_loop())
    try:
        yield
    finally:
        monitor_task.cancel()
        with suppress(asyncio.CancelledError):
            await monitor_task


app = FastAPI(
    title="CAUSAL-X Central Backend",
    description=(
        "Privacy-first, proof-carrying AIOps central SaaS API. "
        "Receives only allow-listed metadata and cryptographic proofs."
    ),
    version=settings.app_version,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router, prefix="/api/v1")
app.include_router(auth_router, prefix="/api/v1")
app.include_router(telemetry_router, prefix="/api/v1")
app.include_router(incidents_router, prefix="/api/v1")
