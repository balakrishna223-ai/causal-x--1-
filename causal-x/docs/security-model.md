# CAUSAL-X Privacy & Security Model

## Non-Negotiable Privacy Guarantees

1. **Local-Only Raw Retention**: Raw system logs, process arguments, environment variables, usernames, internal hostnames, internal IP addresses, passwords, API keys, and tokens never leave the Tier 1 collector environment.
2. **Pre-Egress Enforcement**: Classification, redaction, allow-listing, and risk scoring execute locally before any outbound HTTP payload is built.
3. **Zero Central Exposure**: The Tier 2 PostgreSQL database and FastAPI API never accept, store, log, or return raw secrets or raw logs.

## Data Classification Tiers

| Tier | Examples | Policy Action |
| :--- | :--- | :--- |
| `SAFE` | `cpu_usage`, `memory_usage`, `disk_usage`, `network_latency_ms`, `packet_loss_pct`, `service_status`, `uptime_seconds` | Permitted if explicitly on allow-list |
| `SENSITIVE` | `username`, `hostname`, `internal_ip`, `email` | Pseudonymized via salted HMAC-SHA256 (`source_id`) or redacted before egress |
| `RESTRICTED` | `password`, `secret`, `api_key`, `access_token`, `bearer_token`, `private_key`, regex secret patterns | Blocked completely from egress; retained locally only for audit |

## Privacy Risk Scoring Heuristic

Risk score uses the **highest applicable rule** (never blind summation):

- `100` — Restricted field or secret pattern detected (transmission **BLOCKED**)
- `60` — Unapproved field not present on allow-list
- `40` — Sensitive field detected (must be redacted/pseudonymized before approval)
- `20` — Unnecessary identifying metadata
- `0` — Approved allow-listed metadata only

## Cryptographic Integrity & Pseudonymization

- **Pseudonymous Source IDs**: Computed using `HMAC-SHA256(PSEUDONYM_SALT, raw_source_identifier)`. Python's built-in `hash()` is strictly forbidden.
- **Canonical Proof**: Outgoing metadata JSON is canonicalized (`json.dumps(..., sort_keys=True, separators=(",", ":"))`), hashed with `SHA-256`, and signed with `HMAC-SHA256(COLLECTOR_HMAC_SECRET, canonical_bytes)`.
- **Tenant Isolation**: Every PostgreSQL table containing operational data carries `tenant_id`. All queries derive `tenant_id` exclusively from the verified JWT token—never from unverified client parameters.
