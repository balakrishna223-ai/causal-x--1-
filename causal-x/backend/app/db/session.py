from typing import Generator
from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import get_settings


class Base(DeclarativeBase):
    """Declarative SQLAlchemy base class for CAUSAL-X central models."""


settings = get_settings()

engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    future=True,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    class_=Session,
)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_db_connection() -> tuple[bool, str]:
    """Execute a real SQL probe against PostgreSQL to report accurate health status."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True, "connected"
    except Exception as exc:  # noqa: BLE001
        return False, f"disconnected: {type(exc).__name__}"
