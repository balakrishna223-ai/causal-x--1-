from typing import Optional
from pydantic import BaseModel


class LoginRequest(BaseModel):
    # User login fields (supports Gmail or any operator email)
    email: Optional[str] = None
    password: Optional[str] = None
    # Collector login fields
    collector_id: Optional[str] = None
    collector_api_key: Optional[str] = None
    tenant_slug: Optional[str] = None


class RegisterRequest(BaseModel):
    email: str
    password: str
    full_name: Optional[str] = None
    tenant_slug: str = "acme-cloud"


class PasswordlessRequest(BaseModel):
    email: str
    tenant_slug: str = "acme-cloud"


class PasswordlessRequestResponse(BaseModel):
    status: str
    email: str
    tenant_slug: str
    expires_in_seconds: int
    dev_verification_code: Optional[str] = None


class PasswordlessVerifyRequest(BaseModel):
    email: str
    tenant_slug: str = "acme-cloud"
    code: Optional[str] = None
    instant: bool = False


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    principal_type: str
    tenant_id: str
    tenant_slug: str
    tenant_name: str
    region: str
    role: str
    subject: str
