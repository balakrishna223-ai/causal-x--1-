import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.db.session import normalize_database_url


def _production_settings(**overrides: str) -> dict[str, str]:
    values = {
        "app_env": "production",
        "database_url": "postgresql://causalx:secret@db.example/causalx",
        "jwt_secret_key": "j" * 40,
        "collector_hmac_secret": "h" * 40,
        "pseudonym_salt": "s" * 40,
    }
    return {**values, **overrides}


def test_production_settings_reject_placeholder_secrets() -> None:
    with pytest.raises(ValidationError, match="JWT_SECRET_KEY"):
        Settings(**_production_settings(jwt_secret_key="change-me-in-production"))


def test_production_settings_reject_local_database() -> None:
    with pytest.raises(ValidationError, match="PostgreSQL database URL"):
        Settings(**_production_settings(database_url="sqlite:///local.db"))


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("postgres://user:pass@host/db", "postgresql+psycopg://user:pass@host/db"),
        ("postgresql://user:pass@host/db", "postgresql+psycopg://user:pass@host/db"),
        ("sqlite:///local.db", "sqlite:///local.db"),
    ],
)
def test_database_url_driver_normalization(url: str, expected: str) -> None:
    assert normalize_database_url(url) == expected
