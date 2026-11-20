# CAUSAL-X Handoff Prompt — Production & Demo Ready

All 8 delivery phases of **CAUSAL-X** are implemented.

## Verification & Presentation Commands
1. Copy `causal-x/` into VS Code (`code causal-x`).
2. `cd causal-x && cp .env.example .env && docker compose up --build -d`
3. Run backend pytest suite: `docker compose exec backend pytest -v` (or locally in a venv: `cd backend && pytest -v`).
4. Run collector unit tests: `cd collector && python -m unittest test_collector_unit.py -v`.
5. Follow `docs/demo-script.md` for all six live validation scenarios.
