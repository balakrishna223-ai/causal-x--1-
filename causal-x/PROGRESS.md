# CAUSAL-X Progress Log

## All Phases Completed (Phases 1–8)

### Phase 1 — Foundation & Docker Setup
- Monorepo `causal-x/` with `.env.example`, `docker-compose.yml` (health checks on Postgres, Backend, Collector, Frontend), `README.md`, and `docs/`.

### Phase 2 — Database Models, Migrations, Auth & Tenant Isolation
- 14 SQLAlchemy ORM models in `backend/app/models/models.py` with `(tenant_id, payload_id)` uniqueness constraints.
- Alembic configuration and initial migration `0001_initial_schema.py`.
- PBKDF2-HMAC-SHA256 secret hashing, JWT issuance/verification (`POST /api/v1/auth/login`), and two seeded isolated tenants (`acme-cloud`, `globex-fin`).

### Phase 3 — Local Collector, Privacy Shield, Outbox & Proof Engine
- Real local `psutil` sampling (`collector/main.py`) + clearly labelled controlled simulator (`collector/simulator.py`).
- Field classification (`SAFE`, `SENSITIVE`, `RESTRICTED`, `UNAPPROVED`), regex/keyword/allow-list/block-list checks, highest-rule risk scoring (`0 / 20 / 40 / 60 / 100`), deterministic salted HMAC-SHA256 pseudonymization (`collector/privacy/`).
- Canonical JSON, UUID `payload_id`, SHA-256 + HMAC-SHA256 proof generation (`collector/proof/proof_engine.py`).
- Local SQLite raw retention + durable outbox with exponential backoff (`collector/buffer/sqlite_store.py`).

### Phase 4 & 6 — Backend Ingestion, Live WebSockets, AIOps & Incident Passport
- Privacy gate rejecting restricted keys, cryptographic hash/HMAC verification, idempotent ingestion (`POST /api/v1/telemetry`), UTC event-time ordering (`GET /api/v1/telemetry`), heartbeat & offline collector monitor (`60s` timeout).
- Two-layer anomaly detection: configurable thresholds + Pandas/NumPy rolling baseline + scikit-learn `IsolationForest` (`backend/app/engines/anomaly_engine.py`).
- NetworkX dependency graph correlation (`backend/app/engines/correlation_engine.py`) and explainable root-cause hypotheses + Incident Passport (`backend/app/engines/rca_engine.py`).
- Authenticated tenant-scoped WebSocket hub (`/api/v1/ws/updates`).

### Phase 5 & 7 — Frontend Dashboard & Sky/Sunshine Landing Page
- Complete React + TypeScript + Vite + Tailwind + Recharts app across all 9 routes (`/`, `/login`, `/overview`, `/monitoring`, `/incidents`, `/incidents/:id`, `/privacy/egress`, `/collectors`, `/settings`) and 12 reusable components.
- Zero hardcoded metrics; honest connected/disconnected backend states.

### Phase 8 — Tests & Verification
- `collector/test_collector_unit.py`: 3/3 tests passing via `python3 -m unittest`.
- `backend/tests/`: `test_health.py`, `test_privacy_and_proof.py`, `test_ingestion_and_isolation.py`, `test_aiops_and_offline.py`.
- Root AI Studio Vite applet compiled and linted cleanly (`tsc --noEmit` + `vite build`).
