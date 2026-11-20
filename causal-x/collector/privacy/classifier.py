from dataclasses import dataclass
from enum import Enum
import re
from typing import Any, Dict, List, Tuple


class ClassificationLevel(str, Enum):
    SAFE = "SAFE"
    SENSITIVE = "SENSITIVE"
    RESTRICTED = "RESTRICTED"
    UNAPPROVED = "UNAPPROVED"


SAFE_ALLOW_LIST = {
    "event_id",
    "source_id",
    "collector_id",
    "component",
    "event_category",
    "event_timestamp_utc",
    "source_timezone",
    "cpu_usage",
    "memory_usage",
    "disk_usage",
    "network_latency_ms",
    "packet_loss_pct",
    "net_bytes_sent",
    "net_bytes_recv",
    "service_status",
    "failed_login_count",
    "uptime_seconds",
    "collector_rss_mb",
    "collector_cpu_pct",
    "severity",
    "is_simulation",
}

SENSITIVE_FIELDS = {
    "username",
    "user",
    "hostname",
    "server_id",
    "internal_ip",
    "ip_address",
    "email",
    "operator_email",
    "account_name",
}

RESTRICTED_FIELDS = {
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "bearer_token",
    "token",
    "private_key",
    "ssh_key",
    "raw_log",
    "raw_payload",
    "credentials",
    "auth_header",
}

UNNECESSARY_IDENTIFIER_FIELDS = {
    "pid",
    "process_name",
    "cmdline",
    "mac_address",
    "device_serial",
}

RESTRICTED_VALUE_PATTERNS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),
    re.compile(r"(api[_-]?key|secret|password|token)\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"-----BEGIN\s+(RSA|EC|OPENSSH|PRIVATE)\s+KEY-----", re.IGNORECASE),
    re.compile(r"\b(sk|pk)_(live|test)_[A-Za-z0-9]{10,}\b"),
)

SENSITIVE_VALUE_PATTERNS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
)

RESTRICTED_KEY_KEYWORDS = ("password", "secret", "token", "private_key", "api_key", "credential")
SENSITIVE_KEY_KEYWORDS = ("user", "host", "email", "internal_ip")


@dataclass
class FieldClassification:
    field_name: str
    level: ClassificationLevel
    reason: str
    risk_points: int


def classify_field(field_name: str, value: Any) -> FieldClassification:
    key_lower = field_name.strip().lower()
    str_val = str(value) if value is not None else ""

    # 1. Explicit block-list & keyword check for RESTRICTED
    if key_lower in RESTRICTED_FIELDS or any(kw in key_lower for kw in RESTRICTED_KEY_KEYWORDS):
        return FieldClassification(
            field_name=field_name,
            level=ClassificationLevel.RESTRICTED,
            reason="Restricted field name or credential keyword",
            risk_points=100,
        )

    # 2. Regex check for secrets embedded in values
    for pattern in RESTRICTED_VALUE_PATTERNS:
        if pattern.search(str_val):
            return FieldClassification(
                field_name=field_name,
                level=ClassificationLevel.RESTRICTED,
                reason="Value matches restricted secret/token regex pattern",
                risk_points=100,
            )

    # 3. Sensitive fields & sensitive value patterns
    if key_lower in SENSITIVE_FIELDS or any(kw in key_lower for kw in SENSITIVE_KEY_KEYWORDS):
        return FieldClassification(
            field_name=field_name,
            level=ClassificationLevel.SENSITIVE,
            reason="Sensitive operational identifier",
            risk_points=40,
        )

    for pattern in SENSITIVE_VALUE_PATTERNS:
        if pattern.search(str_val):
            return FieldClassification(
                field_name=field_name,
                level=ClassificationLevel.SENSITIVE,
                reason="Value matches internal IP or email pattern",
                risk_points=40,
            )

    # 4. Unnecessary identifiers
    if key_lower in UNNECESSARY_IDENTIFIER_FIELDS:
        return FieldClassification(
            field_name=field_name,
            level=ClassificationLevel.UNAPPROVED,
            reason="Unnecessary host/process identifier",
            risk_points=20,
        )

    # 5. Strict allow-list check
    if key_lower in SAFE_ALLOW_LIST:
        return FieldClassification(
            field_name=field_name,
            level=ClassificationLevel.SAFE,
            reason="Allow-listed telemetry metadata",
            risk_points=0,
        )

    return FieldClassification(
        field_name=field_name,
        level=ClassificationLevel.UNAPPROVED,
        reason="Field is not on approved metadata allow-list",
        risk_points=60,
    )


def classify_record(record: Dict[str, Any]) -> Tuple[List[FieldClassification], int]:
    """
    Classify every field in a record and calculate privacy risk using the
    highest applicable rule (never blind summation).
    """
    classifications = [classify_field(k, v) for k, v in record.items()]
    max_risk = max((c.risk_points for c in classifications), default=0)
    return classifications, max_risk
