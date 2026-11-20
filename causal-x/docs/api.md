# CAUSAL-X API Contract

Base path: `/api/v1`

All tenant-scoped endpoints require `Authorization: Bearer <jwt_token>` and enforce `tenant_id` filtering in PostgreSQL queries.

## Authentication & Health

| Method | Endpoint | Purpose |
| :--- | :--- | :--- |
| `POST` | `/api/v1/auth/login` | Authenticate user or collector and return JWT access token + tenant context |
| `GET` | `/api/v1/health` | Check backend service and PostgreSQL connectivity status |

## Telemetry Ingestion & Queries

| Method | Endpoint | Purpose |
| :--- | :--- | :--- |
| `POST` | `/api/v1/telemetry` | Ingest approved metadata + proof record; verify SHA-256/HMAC; idempotent by `payload_id` |
| `GET` | `/api/v1/telemetry` | Query tenant-scoped approved telemetry ordered by UTC `event_timestamp` |
| `GET` | `/api/v1/dashboard/overview` | Aggregated tenant KPIs, 4-state health evaluation, recent anomalies & incidents |
| `GET` | `/api/v1/collectors` | List tenant collectors with heartbeat, last-seen UTC time, version, and online/offline status |

## Egress Proof & Verification

| Method | Endpoint | Purpose |
| :--- | :--- | :--- |
| `GET` | `/api/v1/egress/audit` | Retrieve tenant egress proof records (approved fields, blocked field names, policy version, hash, verification state) |
| `POST` | `/api/v1/egress/verify` | Cryptographically verify a canonicalized payload against its recorded SHA-256 hash and HMAC signature |

## AIOps, Incidents & Incident Passports

| Method | Endpoint | Purpose |
| :--- | :--- | :--- |
| `GET` | `/api/v1/anomalies` | List detected anomalies labelled `rule`, `baseline`, `ml`, or `combined` |
| `GET` | `/api/v1/incidents` | List correlated incidents for the authenticated tenant |
| `GET` | `/api/v1/incidents/{id}` | Retrieve full incident detail and linked evidence IDs |
| `GET` | `/api/v1/incidents/{id}/timeline` | Retrieve chronological UTC timeline events for an incident |
| `GET` | `/api/v1/incidents/{id}/hypotheses` | Retrieve ranked root-cause hypotheses with confidence method and uncertainty |
| `GET` | `/api/v1/incidents/{id}/passport` | Retrieve complete Incident Passport (evidence, timeline, hypotheses, impact, recommendations, audit history) |

## Real-Time Streaming

| Protocol | Endpoint | Purpose |
| :--- | :--- | :--- |
| `WS` | `/api/v1/ws/updates` | Authenticated tenant-scoped live stream for telemetry, anomalies, incidents, and collector status changes |
