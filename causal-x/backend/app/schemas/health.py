from datetime import datetime
from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    environment: str
    region: str
    database: str
    timestamp_utc: datetime
