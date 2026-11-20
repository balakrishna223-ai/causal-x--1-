# CAUSAL-X Source Snapshot

## Complete Monorepo Inventory

- **Root & Docs**: `.env.example`, `docker-compose.yml`, `README.md`, `PROGRESS.md`, `SOURCE_SNAPSHOT.md`, `HANDOFF_PROMPT.md`, `docs/architecture.md`, `docs/api.md`, `docs/security-model.md`, `docs/operations.md`, `docs/demo-script.md`
- **Backend (`causal-x/backend/`)**:
  - `requirements.txt`, `Dockerfile`, `alembic.ini`
  - `app/main.py`, `app/core/config.py`, `app/core/security.py`
  - `app/db/session.py`, `app/db/seed.py`, `app/db/migrations/env.py`, `app/db/migrations/script.py.mako`, `app/db/migrations/versions/0001_initial_schema.py`
  - `app/models/models.py`, `app/schemas/health.py`, `app/schemas/auth.py`, `app/schemas/telemetry.py`
  - `app/services/auth_service.py`, `app/services/ingestion_service.py`, `app/services/ws_manager.py`
  - `app/engines/anomaly_engine.py`, `app/engines/correlation_engine.py`, `app/engines/rca_engine.py`
  - `app/api/routes_health.py`, `app/api/routes_auth.py`, `app/api/routes_telemetry.py`, `app/api/routes_incidents.py`
  - `tests/conftest.py`, `tests/test_health.py`, `tests/test_privacy_and_proof.py`, `tests/test_ingestion_and_isolation.py`, `tests/test_aiops_and_offline.py`
- **Collector (`causal-x/collector/`)**:
  - `requirements.txt`, `Dockerfile`, `config.py`, `main.py`, `simulator.py`, `test_collector_unit.py`
  - `privacy/classifier.py`, `privacy/shield.py`
  - `proof/proof_engine.py`
  - `buffer/sqlite_store.py`
- **Frontend (`causal-x/frontend/`)**:
  - `package.json`, `Dockerfile`, `index.html`, `tsconfig.json`, `vite.config.ts`, `tailwind.config.js`, `postcss.config.js`
  - `src/main.tsx`, `src/index.css`, `src/App.tsx`, `src/lib/api.ts`
  - `src/components/`: `Navbar.tsx`, `Sidebar.tsx`, `HeroBackground.tsx`, `MetricCard.tsx`, `StatusBadge.tsx`, `PageHeader.tsx`, `SectionCard.tsx`, `EmptyState.tsx`, `LoadingState.tsx`, `ConnectionStatus.tsx`, `EgressProofCard.tsx`, `IncidentTimeline.tsx`, `DashboardLayout.tsx`
  - `src/pages/`: `LandingPage.tsx`, `LoginPage.tsx`, `OverviewPage.tsx`, `MonitoringPage.tsx`, `IncidentsPage.tsx`, `IncidentPassportPage.tsx`, `EgressProofPage.tsx`, `CollectorsPage.tsx`, `SettingsPage.tsx`
