# CAUSAL-X Live Demonstration Script

This runbook demonstrates real local `psutil` telemetry alongside **clearly labelled controlled fault-injection simulations** (`collector/simulator.py` and `collector/main.py --inject`) across all six operational validation scenarios.

## Prerequisites

1. Start the Docker Compose stack:
   ```bash
   cd causal-x
   cp .env.example .env
   docker compose up --build -d
   ```
2. Open the dashboard at `http://localhost:5173`, navigate to `/login`, and sign in with `ops@acme-cloud.dev` / `DevAcmePass!2026`.

---

## Scenario 1: Sensitive Information Detection & Egress Proof

1. Run a controlled simulation event containing sensitive and restricted fields (`username`, `password`, `api_key`, `raw_log`):
   ```bash
   docker compose exec collector python main.py --inject sensitive_secret
   ```
2. Inspect the collector logs: `password`, `api_key`, and `raw_log` are classified `RESTRICTED` (raw risk `100`, stripped before egress), `username` and `hostname` are pseudonymized/redacted locally, and only allow-listed metadata (`cpu_usage`, `memory_usage`, `source_id`, `event_timestamp_utc`) is approved (`egress_risk_score = 0`).
3. Open **Privacy Proof (`/privacy/egress`)** in the dashboard and click **Verify Payload Integrity** to validate the SHA-256 hash and HMAC-SHA256 signature live against the backend.

## Scenario 2: Backend Connectivity Failure & Post-Outage Recovery

1. Stop the backend container to simulate a SaaS outage:
   ```bash
   docker compose stop backend
   ```
2. Observe the collector buffering approved payloads into local SQLite (`/var/lib/causalx/collector_local.db`) and the frontend displaying an honest disconnected state.
3. Restart the backend:
   ```bash
   docker compose start backend
   ```
4. Observe the collector replaying buffered outbox payloads with zero data loss and zero duplicates (`payload_id` idempotency).

## Scenario 3: Repeated Failed Login Security Signal

1. Inject a controlled authentication failure burst:
   ```bash
   docker compose exec collector python main.py --inject failed_logins
   ```
2. Verify local aggregation generates a `failed_login_count` anomaly without exporting raw usernames or authentication log lines.

## Scenario 4: Network Latency & Packet Loss Spike

1. Inject a controlled network congestion simulation:
   ```bash
   docker compose exec collector python main.py --inject network_latency
   ```
2. Inspect **Monitoring (`/monitoring`)** and **Incidents (`/incidents`)** to see threshold + anomaly detection and a ranked `Possible Network Congestion or Link Loss` hypothesis.

## Scenario 5: CPU & Memory Anomaly

1. Inject a controlled resource bottleneck simulation:
   ```bash
   docker compose exec collector python main.py --inject cpu_memory_spike
   ```
2. Verify anomaly detection, correlated incident creation, and `Possible Compute Resource Bottleneck` hypothesis with confidence and uncertainty.

## Scenario 6: Correlated Multi-Signal Incident & Incident Passport

1. Inject a cascading multi-signal scenario:
   ```bash
   docker compose exec collector python main.py --inject cascading_outage
   ```
2. Open the newly created incident (`/incidents/:id`) to inspect the full **Incident Passport**: chronological timeline, correlated evidence IDs, `NetworkX` downstream impact estimate, ranked hypotheses, recommendations, and audit history.
