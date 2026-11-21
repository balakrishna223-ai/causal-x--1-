# CAUSAL-X

**Beyond alerts. Understand the cause. Protect every signal.**

CAUSAL-X is a privacy-first AIOps observability platform. It checks telemetry locally, blocks sensitive fields before egress, verifies approved payloads, and presents operational health and incident insights in a dashboard.

## Run the VS Code preview

**Requirements:** Node.js and npm

From the project root, open a VS Code terminal and run:

```powershell
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser. This local address is available on your computer only; deploy the app to a hosting provider to share a public demo link.

No Gemini API key is required to run this preview.

## Full-stack application

The `causal-x/` folder contains the frontend, FastAPI backend, and local telemetry collector. See [causal-x/README.md](causal-x/README.md) for its setup and architecture.
## Deploy a public demo on Render

This repository includes a Render Blueprint in `render.yaml`. It builds the React frontend, serves it and the FastAPI API from one web service, and provisions PostgreSQL. The local collector remains in the customer environment and can send telemetry to the deployed API.

[Open the live evaluation demo](https://causal-x-demo.onrender.com). New users can create an account limited to the Acme Cloud sample workspace. Email verification is not configured; do not use sensitive credentials or connect production telemetry to this public demo.

The free web service may sleep when idle, and the free PostgreSQL plan has a limited lifetime and storage. This is suitable for evaluation, not continuous production availability.
