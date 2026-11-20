# CAUSAL-X Architecture

## Overview

CAUSAL-X implements a strict **two-tier privacy-first AIOps architecture**:

1. **Tier 1 (Customer Environment / Local Collector)**: Collects live infrastructure metrics (`psutil`) and optional controlled fault-injection events, retains raw logs/records locally in SQLite, classifies every field, redacts or blocks sensitive and restricted content, computes a transparent privacy risk score, generates canonical JSON + SHA-256/HMAC egress proofs, and buffers approved metadata locally when the central backend is unreachable.
2. **Tier 2 (Central SaaS Backend & Dashboard)**: Authenticates collectors and users, enforces multi-tenant isolation in PostgreSQL, verifies payload hashes/HMACs, guarantees idempotent ingestion by `payload_id`, orders out-of-order events by UTC `event_time`, detects anomalies (configurable rules + rolling baseline + `IsolationForest`), correlates incidents (`NetworkX`), synthesizes explainable root-cause hypotheses and Incident Passports, and broadcasts live updates via WebSockets.

## System Architecture Diagram

```mermaid
flowchart TB
    subgraph T1["Tier 1: Customer Environment (Trust Boundary)"]
        SRC["Real Host Telemetry (psutil)<br/>CPU · Memory · Disk · Network · Process Health"]
        SIM["Controlled Fault Simulator<br/>(Explicitly Labelled Simulations)"]
        RAWDB[("Local SQLite<br/>Raw Event Store (Never Leaves)")]
        CLF["Intelligent Data Classifier<br/>SAFE · SENSITIVE · RESTRICTED"]
        SHIELD["Privacy Shield<br/>Allow-List · Redact · Block · Salted HMAC Pseudonym"]
        RISK["Privacy Risk Engine<br/>0 / 20 / 40 / 60 / 100"]
        PROOF["Proof-Carrying Telemetry<br/>UUID payload_id · Canonical JSON · SHA-256 + HMAC"]
        OUTBOX[("Local SQLite Outbox<br/>Durable Buffer + Exponential Backoff")]

        SRC --> CLF
        SIM --> CLF
        CLF --> RAWDB
        CLF --> SHIELD
        SHIELD --> RISK
        RISK -->|"Risk < 100 (Approved)"| PROOF
        RISK -->|"Risk = 100 (Blocked)"| RAWDB
        PROOF --> OUTBOX
    end

    subgraph T2["Tier 2: Central SaaS Platform (Metadata-Only)"]
        INGEST["FastAPI Ingestion Gateway<br/>JWT Auth · HMAC/SHA-256 Verify · Idempotency"]
        PG[("PostgreSQL<br/>Tenant-Isolated Metadata Store")]
        AIOPS["AIOps Engine<br/>Thresholds + Baseline + IsolationForest"]
        CORR["Incident Correlation (NetworkX)<br/>Time Window · Source · Component Graph"]
        RCA["Root-Cause & Passport Engine<br/>Ranked Hypotheses · Uncertainty · Evidence IDs"]
        WS["WebSocket Hub (/api/v1/ws/updates)"]
        UI["React + Vite + Tailwind Dashboard<br/>Overview · Monitoring · Incidents · Egress Proof"]

        INGEST --> PG
        INGEST --> AIOPS
        AIOPS --> CORR
        CORR --> RCA
        RCA --> PG
        INGEST --> WS
        RCA --> WS
        WS --> UI
        PG --> UI
    end

    OUTBOX -->|"Authenticated HTTPS/HTTP<br/>Approved Metadata + Proof Only"| INGEST
```

## Key Architectural Invariants

- **Trust Boundary Enforcement**: Privacy classification, redaction, and blocking occur exclusively inside Tier 1 before any outbound HTTP request object is constructed.
- **Event-Time Ordering**: Central storage indexes and queries by UTC `event_timestamp` while preserving `source_timezone` metadata, preventing out-of-order backlog replays from distorting metric charts.
- **Idempotency**: Every approved egress payload receives a deterministic/UUID `payload_id`; central ingestion deduplicates safely on `(tenant_id, payload_id)`.
