from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class CollectorSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    causalx_backend_url: str = "http://localhost:8000"
    causalx_collector_id: str = "collector-local-01"
    causalx_tenant_slug: str = "acme-cloud"
    causalx_collector_api_key: str = "change-me-dev-collector-token"
    causalx_collector_poll_seconds: float = 5.0
    causalx_heartbeat_seconds: float = 15.0
    causalx_sqlite_path: str = "./collector_local.db"
    causalx_telemetry_mode: str = "real"
    causalx_source_timezone: str = "UTC"
    causalx_policy_version: str = "1.0.0"

    collector_hmac_secret: str = "change-me-dev-collector-hmac-secret"
    pseudonym_salt: str = "change-me-dev-pseudonym-salt"


@lru_cache
def get_collector_settings() -> CollectorSettings:
    return CollectorSettings()
