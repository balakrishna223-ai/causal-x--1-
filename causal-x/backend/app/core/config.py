from functools import lru_cache
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import model_validator


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

    @model_validator(mode="after")
    def require_production_secrets(self) -> "Settings":
        if self.app_env.strip().lower() == "production":
            secrets = {
                "JWT_SECRET_KEY": self.jwt_secret_key,
                "COLLECTOR_HMAC_SECRET": self.collector_hmac_secret,
                "PSEUDONYM_SALT": self.pseudonym_salt,
            }
            invalid = [
                name
                for name, value in secrets.items()
                if len(value) < 32 or value.lower().startswith("change-me")
            ]
            if len(set(secrets.values())) != len(secrets):
                invalid.append("secrets must be distinct")
            if invalid:
                raise ValueError(
                    "Production requires strong, unique values for: " + ", ".join(invalid)
                )
            if not self.database_url.startswith(
                ("postgres://", "postgresql://", "postgresql+psycopg://")
            ):
                raise ValueError("Production requires a PostgreSQL database URL")
            if "localhost" in self.database_url.lower() or "change-me" in self.database_url.lower():
                raise ValueError("Production requires a configured non-local database URL")
        return self

    @property
    def cors_origin_list(self) -> List[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
