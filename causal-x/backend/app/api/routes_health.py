from fastapi import APIRouter

from app.core.config import get_settings
from app.core.security import utc_now
from app.db.session import check_db_connection
from app.schemas.health import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    settings = get_settings()
    db_ok, db_state = check_db_connection()
    return HealthResponse(
        status="ok" if db_ok else "degraded",
        service=settings.app_name,
        version=settings.app_version,
        environment=settings.app_env,
        region=settings.default_region,
        database=db_state,
        timestamp_utc=utc_now(),
    )
