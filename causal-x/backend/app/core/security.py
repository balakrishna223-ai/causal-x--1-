from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from typing import Any, Dict, Optional

from jose import JWTError, jwt

from app.core.config import get_settings


def utc_now() -> datetime:
    """Return timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def canonical_json(payload: Dict[str, Any]) -> str:
    """Serialize payload deterministically for SHA-256 and HMAC proof verification."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_sha256_hex(payload: Dict[str, Any]) -> str:
    """Compute SHA-256 hex digest of canonicalized payload JSON."""
    encoded = canonical_json(payload).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def compute_hmac_hex(secret: str, message: str) -> str:
    """Compute deterministic salted HMAC-SHA256 hex digest. Never uses Python hash()."""
    return hmac.new(
        secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_hmac_hex(secret: str, message: str, expected_hex: str) -> bool:
    """Constant-time verification of HMAC-SHA256 signature."""
    computed = compute_hmac_hex(secret, message)
    return hmac.compare_digest(computed, expected_hex)


def hash_secret(plain_secret: str) -> str:
    """Hash a user password or collector API key using PBKDF2-HMAC-SHA256 with random salt."""
    salt = os.urandom(16).hex()
    dk = hashlib.pbkdf2_hmac("sha256", plain_secret.encode("utf-8"), salt.encode("utf-8"), 120_000)
    return f"pbkdf2_sha256${salt}${dk.hex()}"


def verify_secret(plain_secret: str, stored_hash: str) -> bool:
    """Constant-time verification of PBKDF2-HMAC-SHA256 secret hash."""
    try:
        algo, salt, expected_hex = stored_hash.split("$", 2)
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", plain_secret.encode("utf-8"), salt.encode("utf-8"), 120_000
        )
        return hmac.compare_digest(dk.hex(), expected_hex)
    except ValueError:
        return False


def create_access_token(
    subject: str,
    tenant_id: str,
    tenant_slug: str,
    role: str,
    principal_type: str = "user",
    expires_minutes: Optional[int] = None,
) -> str:
    settings = get_settings()
    expire_delta = timedelta(
        minutes=expires_minutes or settings.jwt_access_token_expire_minutes
    )
    now = utc_now()
    claims = {
        "sub": subject,
        "tenant_id": tenant_id,
        "tenant_slug": tenant_slug,
        "role": role,
        "principal_type": principal_type,
        "iat": int(now.timestamp()),
        "exp": int((now + expire_delta).timestamp()),
    }
    return jwt.encode(claims, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> Dict[str, Any]:
    settings = get_settings()
    try:
        return jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )
    except JWTError as exc:
        raise ValueError("Invalid or expired authentication token") from exc
