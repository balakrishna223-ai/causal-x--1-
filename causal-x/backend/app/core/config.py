from functools import lru_cache
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "CAUSAL-X"
    app_version: str = "0.1.0"
    app_env: str = "development"
    default_region: str = "us-east-1"

    database_url: str = (
        "postgresql+psycopg://causalx:change-me-postgres-password@localhost:5432/causalx_db"
    )

    jwt_secret_key: str = "change-me-dev-jwt-secret-key-min-32-chars"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 480

    collector_hmac_secret: str = "change-me-dev-collector-hmac-secret"
    pseudonym_salt: str = "change-me-dev-pseudonym-salt"

    cors_origins: str = "http://localhost:5173,http://localhost:3000"
    collector_offline_timeout_seconds: int = 60

    # Configurable AIOps threshold defaults
    threshold_cpu_percent: float = 90.0
    threshold_memory_percent: float = 90.0
    threshold_latency_ms: float = 200.0
    threshold_packet_loss_percent: float = 5.0

    @property
    def cors_origin_list(self) -> List[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
