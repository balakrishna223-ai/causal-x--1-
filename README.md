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
