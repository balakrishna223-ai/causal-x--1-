from dataclasses import dataclass
from datetime import timedelta, timezone
import hashlib
import secrets
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import create_access_token, decode_access_token, hash_secret, utc_now, verify_secret
from app.db.session import get_db
from app.models.models import Collector, PasswordlessCode, Tenant, User
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    PasswordlessRequest,
    PasswordlessRequestResponse,
    PasswordlessVerifyRequest,
    RegisterRequest,
)

bearer_scheme = HTTPBearer(auto_error=False)


@dataclass
class AuthenticatedPrincipal:
    subject: str
    tenant_id: str
    tenant_slug: str
    role: str
    principal_type: str


def _normalize_email(raw_email: str) -> str:
    email = raw_email.strip().lower()
    if "@" not in email or "." not in email.split("@", 1)[1]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provide a valid email or Gmail address",
        )
    return email


def _build_user_login_response(user: User, tenant: Tenant) -> LoginResponse:
    token = create_access_token(
        subject=user.email,
        tenant_id=tenant.id,
        tenant_slug=tenant.slug,
        role=user.role,
        principal_type="user",
    )
    return LoginResponse(
        access_token=token,
        principal_type="user",
        tenant_id=tenant.id,
        tenant_slug=tenant.slug,
        tenant_name=tenant.name,
        region=tenant.region,
        role=user.role,
        subject=user.email,
    )


def _hash_otp(email: str, code: str) -> str:
    return hashlib.sha256(f"{email}:{code}".encode("utf-8")).hexdigest()


def authenticate_principal(db: Session, payload: LoginRequest) -> LoginResponse:
    if payload.email and payload.password:
        email = _normalize_email(payload.email)
        user = db.query(User).filter(User.email == email).first()
        if not user or not user.is_active or not verify_secret(payload.password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )
        tenant = db.query(Tenant).filter(Tenant.id == user.tenant_id).first()
        if not tenant:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Tenant not found")

        return _build_user_login_response(user, tenant)

    if payload.collector_id and payload.collector_api_key and payload.tenant_slug:
        tenant = db.query(Tenant).filter(Tenant.slug == payload.tenant_slug.strip()).first()
        if not tenant:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid tenant or collector credentials",
            )
        collector = (
            db.query(Collector)
            .filter(
                Collector.tenant_id == tenant.id,
                Collector.collector_id == payload.collector_id.strip(),
            )
            .first()
        )
        if not collector or not verify_secret(payload.collector_api_key, collector.api_key_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid tenant or collector credentials",
            )
        token = create_access_token(
            subject=collector.collector_id,
            tenant_id=tenant.id,
            tenant_slug=tenant.slug,
            role="collector",
            principal_type="collector",
        )
        return LoginResponse(
            access_token=token,
            principal_type="collector",
            tenant_id=tenant.id,
            tenant_slug=tenant.slug,
            tenant_name=tenant.name,
            region=tenant.region,
            role="collector",
            subject=collector.collector_id,
        )

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Provide either email/password or collector_id/collector_api_key/tenant_slug",
    )


def register_operator(db: Session, payload: RegisterRequest) -> LoginResponse:
    email = _normalize_email(payload.email)
    if len(payload.password) < 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 6 characters",
        )
    tenant = db.query(Tenant).filter(Tenant.slug == payload.tenant_slug.strip()).first()
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant '{payload.tenant_slug}' not found",
        )
    existing = db.query(User).filter(User.email == email).first()
    if existing:
        if not verify_secret(payload.password, existing.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Operator email already exists with a different password",
            )
        existing_tenant = db.query(Tenant).filter(Tenant.id == existing.tenant_id).first() or tenant
        return _build_user_login_response(existing, existing_tenant)

    display_name = (payload.full_name or email.split("@", 1)[0]).strip()
    user = User(
        tenant_id=tenant.id,
        email=email,
        full_name=display_name,
        role="operator",
        hashed_password=hash_secret(payload.password),
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return _build_user_login_response(user, tenant)


def request_passwordless_login(
    db: Session, payload: PasswordlessRequest
) -> PasswordlessRequestResponse:
    email = _normalize_email(payload.email)
    tenant = db.query(Tenant).filter(Tenant.slug == payload.tenant_slug.strip()).first()
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant '{payload.tenant_slug}' not found",
        )

    code = f"{secrets.randbelow(900000) + 100000}"
    expires_at = utc_now() + timedelta(minutes=10)
    db.add(
        PasswordlessCode(
            tenant_id=tenant.id,
            email=email,
            code_hash=_hash_otp(email, code),
            expires_at_utc=expires_at,
            used=False,
        )
    )
    db.commit()

    settings = get_settings()
    return PasswordlessRequestResponse(
        status="code_issued",
        email=email,
        tenant_slug=tenant.slug,
        expires_in_seconds=600,
        dev_verification_code=code if settings.app_env != "production" else None,
    )


def verify_passwordless_login(db: Session, payload: PasswordlessVerifyRequest) -> LoginResponse:
    email = _normalize_email(payload.email)
    tenant = db.query(Tenant).filter(Tenant.slug == payload.tenant_slug.strip()).first()
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant '{payload.tenant_slug}' not found",
        )

    settings = get_settings()
    if payload.instant:
        if settings.app_env == "production":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Instant passwordless login is disabled in production; use one-time code.",
            )
    else:
        if not payload.code or len(payload.code.strip()) < 6:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Enter the 6-digit passwordless verification code",
            )
        record = (
            db.query(PasswordlessCode)
            .filter(
                PasswordlessCode.tenant_id == tenant.id,
                PasswordlessCode.email == email,
                PasswordlessCode.used.is_(False),
            )
            .order_by(PasswordlessCode.created_at_utc.desc())
            .first()
        )
        if not record:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No active passwordless code found for this email",
            )
        exp = record.expires_at_utc
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp < utc_now() or not secrets.compare_digest(
            record.code_hash, _hash_otp(email, payload.code.strip())
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired verification code",
            )
        record.used = True

    user = db.query(User).filter(User.email == email).first()
    if not user:
        user = User(
            tenant_id=tenant.id,
            email=email,
            full_name=email.split("@", 1)[0],
            role="operator",
            hashed_password=hash_secret(secrets.token_urlsafe(24)),
            is_active=True,
        )
        db.add(user)
        db.flush()

    user_tenant = db.query(Tenant).filter(Tenant.id == user.tenant_id).first() or tenant
    db.commit()
    db.refresh(user)
    return _build_user_login_response(user, user_tenant)


def get_current_principal(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> AuthenticatedPrincipal:
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Bearer authentication token",
        )
    try:
        claims = decode_access_token(credentials.credentials)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc

    tenant_id = claims.get("tenant_id")
    tenant_slug = claims.get("tenant_slug")
    subject = claims.get("sub")
    if not tenant_id or not subject:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token claims",
        )

    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Tenant no longer exists",
        )

    return AuthenticatedPrincipal(
        subject=str(subject),
        tenant_id=str(tenant_id),
        tenant_slug=str(tenant_slug or tenant.slug),
        role=str(claims.get("role", "operator")),
        principal_type=str(claims.get("principal_type", "user")),
    )
