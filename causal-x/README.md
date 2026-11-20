# CAUSAL-X

**Beyond Alerts. Understand the Cause. Protect Every Signal.**

CAUSAL-X is a locally runnable, real-time, privacy-first, proof-carrying AIOps observability platform. A Tier 1 local collector gathers real system telemetry via `psutil`, keeps raw sensitive records and secrets strictly inside the customer environment (SQLite), applies local privacy classification, redaction, allow-listing, risk scoring, and cryptographic proof generation, and transmits only approved metadata to a multi-tenant Tier 2 FastAPI + PostgreSQL backend.

---

## Core Architecture

- **Tier 1 — Local Collector (`collector/`)**:
  - Real hardware & process metrics via `psutil` (CPU, memory, disk, network I/O, uptime, collector health) + optional clearly labelled controlled fault-injection simulations (`simulator.py`).
  - Field classification (`SAFE`, `SENSITIVE`, `RESTRICTED`), regex/keyword/allow-list/block-list enforcement, salted HMAC-SHA256 pseudonymization, and local risk scoring (`0 / 20 / 40 / 60 / 100`).
  - Canonical JSON, UUID payload IDs, SHA-256 + HMAC proof generation, SQLite durable outbox with exponential backoff retry.
- **Tier 2 — Central SaaS Backend (`backend/`)**:
  - FastAPI + SQLAlchemy + Alembic + PostgreSQL.
  - Strict tenant isolation, JWT authentication, idempotent ingestion, hash/HMAC verification, out-of-order event ordering by UTC event timestamp, collector heartbeat & offline detection.
  - Rule-based + rolling baseline + `IsolationForest` anomaly detection, `NetworkX` incident correlation, explainable root-cause hypotheses, Incident Passports, and WebSocket live broadcasts.
- **Dashboard & Egress Proof UI (`frontend/`)**:
  - React + TypeScript + Vite + Tailwind CSS + Recharts.
  - Real API-connected views only (never hardcoded fake metrics); honest disconnected/error states when the backend is offline.

---

## Quick Start (Docker Compose)

1. Copy the environment template and review values:

```bash
cd causal-x
cp .env.example .env
```

2. Build and start all services (`postgres`, `backend`, `collector`, `frontend`):

```bash
docker compose up --build
```

3. Access the platform:

- Frontend UI: `http://localhost:5173`
- Backend API Docs (Swagger): `http://localhost:8000/docs`
- Backend Health Check: `http://localhost:8000/api/v1/health`

---

## Local Development in VS Code (Without Docker for App Processes)

1. Open the project in VS Code:

```bash
code causal-x
```

2. Start PostgreSQL (via Docker or local Postgres service):

```bash
docker compose up -d postgres
```

3. Set up and run the **Backend** (Terminal 1):

```bash
cd causal-x/backend
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
export DATABASE_URL="postgresql+psycopg://causalx:change-me-postgres-password@localhost:5432/causalx_db"
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

4. Set up and run the **Local Collector** (Terminal 2):

```bash
cd causal-x/collector
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
export CAUSALX_BACKEND_URL="http://localhost:8000"
export CAUSALX_SQLITE_PATH="./collector_local.db"
python main.py
```

5. Set up and run the **Frontend** (Terminal 3):

```bash
cd causal-x/frontend
npm install
npm run dev
```

6. Run **Tests**:

```bash
cd causal-x/backend
pytest -v
```

---

## Documentation

- [Architecture & Data Flow](docs/architecture.md)
- [API Contract](docs/api.md)
- [Privacy & Security Model](docs/security-model.md)
- [Operations & Outage Recovery](docs/operations.md)
- [Live Demonstration Script](docs/demo-script.md)
