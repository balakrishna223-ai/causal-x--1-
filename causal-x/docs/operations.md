# CAUSAL-X Operations & Recovery Runbook

## Four-State Health Classification

| State | Meaning | Trigger Conditions |
| :--- | :--- | :--- |
| `Excellent` | Healthy | Collector heartbeat active; all metrics within rolling baseline |
| `Good` | Normal | Minor baseline variance with no threshold breach or service impact |
| `Fair` | Needs attention | Elevated latency/resource usage, packet loss, or warning-level anomaly |
| `Poor` | Critical | Collector offline (> 60s without heartbeat), service unavailable, or critical anomaly |

Stale or missing telemetry automatically downgrades health rather than masking an outage with the last known good value.

## Outage & Backlog Recovery Behavior

1. **Backend Unavailable**:
   - The local collector detects connection errors or HTTP 5xx responses when posting to `POST /api/v1/telemetry`.
   - Approved, proof-signed payloads are persisted in the local SQLite `outbox_queue` table with `status = 'PENDING'`.
   - Local `psutil` collection and privacy classification continue uninterrupted.
2. **Exponential Backoff**:
   - Delivery retries use exponential backoff (`2s`, `4s`, `8s`, `16s`, capped at `60s`) to avoid thundering-herd retries.
3. **Reconnect & Exactly-Once Replay**:
   - When the backend recovers, the collector replays `PENDING` outbox records in chronological order.
   - The backend checks `(tenant_id, payload_id)` uniqueness: duplicate deliveries return an idempotent `200/202` acknowledgement without inserting duplicate rows.
   - Out-of-order events are stored and queried by UTC `event_timestamp`, keeping historical charts accurate.

## Collector Offline Detection

- Collectors send periodic heartbeats (`CAUSALX_HEARTBEAT_SECONDS`, default 15s).
- A background evaluator in the backend marks any collector whose `last_seen_utc` exceeds `COLLECTOR_OFFLINE_TIMEOUT_SECONDS` (default 60s) as `OFFLINE`, downgrades health to `Poor`, and broadcasts the status change over `/api/v1/ws/updates`.
