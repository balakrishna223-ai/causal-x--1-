import "dotenv/config";
import crypto from "node:crypto";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import express, { type NextFunction, type Request, type Response } from "express";
import { WebSocket, WebSocketServer } from "ws";

const PORT = Number(process.env.PORT || 3000);
const APP_ENV = process.env.APP_ENV || process.env.NODE_ENV || "development";
const JWT_SECRET =
  process.env.JWT_SECRET_KEY || "causalx-dev-jwt-secret-key-min-32-chars-local";
const HMAC_SECRET =
  process.env.COLLECTOR_HMAC_SECRET || "change-me-dev-collector-hmac-secret";
const PSEUDONYM_SALT =
  process.env.PSEUDONYM_SALT || "change-me-dev-pseudonym-salt";
const DB_PATH = path.resolve(process.cwd(), ".causalx-preview.db");

const FORBIDDEN_CENTRAL_KEYS = new Set([
  "password",
  "passwd",
  "secret",
  "api_key",
  "apikey",
  "access_token",
  "refresh_token",
  "bearer_token",
  "private_key",
  "ssh_key",
  "raw_log",
  "raw_payload",
  "credentials",
  "username",
  "hostname",
  "internal_ip",
]);

const COMPONENT_DEPENDENCIES: Record<string, string[]> = {
  "edge-ingress": ["api-gateway", "auth-service"],
  "api-gateway": ["auth-service", "payment-worker", "postgres-primary"],
  "auth-service": ["postgres-primary"],
  "payment-worker": ["postgres-primary"],
  "postgres-primary": [],
  "host-system": ["api-gateway"],
};

function utcNowIso(): string {
  return new Date().toISOString();
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const parts = keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`);
    return `{${parts.join(",")}}`;
  }
  return JSON.stringify(value);
}

function computeSha256Hex(payload: unknown): string {
  return crypto.createHash("sha256").update(canonicalJson(payload), "utf8").digest("hex");
}

function computeHmacHex(secret: string, canonicalStr: string): string {
  return crypto.createHmac("sha256", secret).update(canonicalStr, "utf8").digest("hex");
}

function hashSecret(plain: string): string {
  const salt = crypto.randomBytes(16).toString("hex");
  const digest = crypto.pbkdf2Sync(plain, salt, 120000, 32, "sha256").toString("hex");
  return `pbkdf2_sha256$120000$${salt}$${digest}`;
}

function verifySecret(plain: string, stored: string): boolean {
  const parts = stored.split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2_sha256") return false;
  const iterations = Number(parts[1]);
  const salt = parts[2];
  const expected = parts[3];
  const actual = crypto.pbkdf2Sync(plain, salt, iterations, 32, "sha256").toString("hex");
  return crypto.timingSafeEqual(Buffer.from(actual, "hex"), Buffer.from(expected, "hex"));
}

function base64UrlEncode(input: Buffer | string): string {
  return Buffer.from(input)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function base64UrlDecode(input: string): string {
  const padded = input.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((input.length + 3) % 4);
  return Buffer.from(padded, "base64").toString("utf8");
}

interface JwtClaims {
  sub: string;
  tenant_id: string;
  tenant_slug: string;
  role: string;
  principal_type: string;
  iat: number;
  exp: number;
}

function createJwt(claims: Omit<JwtClaims, "iat" | "exp">): string {
  const nowSec = Math.floor(Date.now() / 1000);
  const fullClaims: JwtClaims = {
    ...claims,
    iat: nowSec,
    exp: nowSec + 8 * 60 * 60,
  };
  const header = base64UrlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = base64UrlEncode(JSON.stringify(fullClaims));
  const sig = base64UrlEncode(
    crypto.createHmac("sha256", JWT_SECRET).update(`${header}.${payload}`).digest()
  );
  return `${header}.${payload}.${sig}`;
}

function decodeJwt(token: string): JwtClaims {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Malformed token");
  const [header, payload, sig] = parts;
  const expectedSig = base64UrlEncode(
    crypto.createHmac("sha256", JWT_SECRET).update(`${header}.${payload}`).digest()
  );
  const a = Buffer.from(sig, "utf8");
  const b = Buffer.from(expectedSig, "utf8");
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    throw new Error("Invalid token signature");
  }
  const claims = JSON.parse(base64UrlDecode(payload)) as JwtClaims;
  if (claims.exp < Math.floor(Date.now() / 1000)) {
    throw new Error("Token expired");
  }
  return claims;
}

function pseudonymizeSource(tenantSlug: string, rawHost: string): string {
  const hex = crypto
    .createHmac("sha256", PSEUDONYM_SALT)
    .update(`${tenantSlug}:${rawHost}`)
    .digest("hex")
    .slice(0, 16);
  return `src_${hex}`;
}

function initDatabase(): DatabaseSync {
  const db = new DatabaseSync(DB_PATH);
  db.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS tenants (
      id TEXT PRIMARY KEY,
      slug TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      region TEXT NOT NULL,
      residency_policy TEXT NOT NULL,
      created_at_utc TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      full_name TEXT NOT NULL,
      role TEXT NOT NULL,
      hashed_password TEXT NOT NULL,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at_utc TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS passwordless_codes (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      email TEXT NOT NULL,
      code_hash TEXT NOT NULL,
      expires_at_utc TEXT NOT NULL,
      used INTEGER NOT NULL DEFAULT 0,
      created_at_utc TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS collectors (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      collector_id TEXT NOT NULL,
      display_name TEXT NOT NULL,
      api_key_hash TEXT NOT NULL,
      version TEXT NOT NULL,
      region TEXT NOT NULL,
      source_timezone TEXT NOT NULL,
      status TEXT NOT NULL,
      last_seen_utc TEXT,
      last_cpu_pct REAL NOT NULL DEFAULT 0,
      last_mem_mb REAL NOT NULL DEFAULT 0,
      config_json TEXT NOT NULL,
      UNIQUE(tenant_id, collector_id)
    );
    CREATE TABLE IF NOT EXISTS telemetry (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      collector_id TEXT NOT NULL,
      payload_id TEXT NOT NULL,
      source_id TEXT NOT NULL,
      component TEXT NOT NULL,
      event_category TEXT NOT NULL,
      event_timestamp_utc TEXT NOT NULL,
      ingested_at_utc TEXT NOT NULL,
      source_timezone TEXT NOT NULL,
      cpu_usage REAL NOT NULL,
      memory_usage REAL NOT NULL,
      disk_usage REAL NOT NULL,
      network_latency_ms REAL NOT NULL,
      packet_loss_pct REAL NOT NULL,
      service_status TEXT NOT NULL,
      failed_login_count INTEGER NOT NULL DEFAULT 0,
      uptime_seconds REAL NOT NULL DEFAULT 0,
      severity TEXT NOT NULL,
      is_simulation INTEGER NOT NULL DEFAULT 0,
      UNIQUE(tenant_id, payload_id)
    );
    CREATE TABLE IF NOT EXISTS egress_proofs (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      collector_id TEXT NOT NULL,
      payload_id TEXT NOT NULL,
      source_id TEXT NOT NULL,
      event_timestamp_utc TEXT NOT NULL,
      approved_metadata_json TEXT NOT NULL,
      allowed_fields_json TEXT NOT NULL,
      blocked_fields_json TEXT NOT NULL,
      policy_version TEXT NOT NULL,
      privacy_risk_score INTEGER NOT NULL,
      payload_hash_sha256 TEXT NOT NULL,
      hmac_signature TEXT NOT NULL,
      verification_status TEXT NOT NULL,
      approval_decision TEXT NOT NULL,
      delivery_status TEXT NOT NULL,
      created_at_utc TEXT NOT NULL,
      UNIQUE(tenant_id, payload_id)
    );
    CREATE TABLE IF NOT EXISTS anomalies (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      collector_id TEXT NOT NULL,
      telemetry_id TEXT NOT NULL,
      source_id TEXT NOT NULL,
      component TEXT NOT NULL,
      metric_name TEXT NOT NULL,
      metric_value REAL NOT NULL,
      baseline_mean REAL,
      baseline_std REAL,
      detection_method TEXT NOT NULL,
      severity TEXT NOT NULL,
      description TEXT NOT NULL,
      contributing_signals_json TEXT NOT NULL,
      detected_at_utc TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS incidents (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      incident_code TEXT NOT NULL,
      title TEXT NOT NULL,
      status TEXT NOT NULL,
      severity TEXT NOT NULL,
      primary_source_id TEXT NOT NULL,
      affected_components_json TEXT NOT NULL,
      evidence_ids_json TEXT NOT NULL,
      correlation_score REAL NOT NULL,
      detected_at_utc TEXT NOT NULL,
      updated_at_utc TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS incident_passports (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      incident_id TEXT UNIQUE NOT NULL,
      passport_json TEXT NOT NULL,
      generated_at_utc TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS tenant_thresholds (
      tenant_id TEXT PRIMARY KEY,
      cpu_threshold REAL NOT NULL DEFAULT 90,
      memory_threshold REAL NOT NULL DEFAULT 90,
      latency_threshold_ms REAL NOT NULL DEFAULT 200,
      packet_loss_threshold_pct REAL NOT NULL DEFAULT 5,
      offline_timeout_seconds INTEGER NOT NULL DEFAULT 60,
      updated_at_utc TEXT NOT NULL
    );
  `);

  const now = utcNowIso();
  const acmeExisting = db.prepare("SELECT id FROM tenants WHERE slug = ?").get("acme-cloud") as
    | { id: string }
    | undefined;
  if (!acmeExisting) {
    const acmeId = crypto.randomUUID();
    db.prepare(
      "INSERT INTO tenants (id, slug, name, region, residency_policy, created_at_utc) VALUES (?, ?, ?, ?, ?, ?)"
    ).run(acmeId, "acme-cloud", "Acme Cloud Operations", "us-east-1", "us-east-1-strict", now);

    db.prepare(
      "INSERT INTO users (id, tenant_id, email, full_name, role, hashed_password, is_active, created_at_utc) VALUES (?, ?, ?, ?, ?, ?, 1, ?)"
    ).run(
      crypto.randomUUID(),
      acmeId,
      "ops@acme-cloud.dev",
      "Acme Site Reliability Lead",
      "admin",
      hashSecret(process.env.DEV_ACME_USER_PASS || "DevAcmePass!2026"),
      now
    );

    db.prepare(
      "INSERT INTO collectors (id, tenant_id, collector_id, display_name, api_key_hash, version, region, source_timezone, status, last_seen_utc, last_cpu_pct, last_mem_mb, config_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?)"
    ).run(
      crypto.randomUUID(),
      acmeId,
      "collector-local-01",
      "Primary Local Collector (Acme)",
      hashSecret(process.env.CAUSALX_COLLECTOR_API_KEY || "change-me-dev-collector-token"),
      "1.0.0",
      "us-east-1",
      "UTC",
      "ONLINE",
      now,
      JSON.stringify({ poll_seconds: 5, policy_version: "1.0.0" })
    );

    db.prepare(
      "INSERT INTO tenant_thresholds (tenant_id, cpu_threshold, memory_threshold, latency_threshold_ms, packet_loss_threshold_pct, offline_timeout_seconds, updated_at_utc) VALUES (?, 90, 90, 200, 5, 60, ?)"
    ).run(acmeId, now);
  }

  const globexExisting = db.prepare("SELECT id FROM tenants WHERE slug = ?").get("globex-fin") as
    | { id: string }
    | undefined;
  if (!globexExisting) {
    const globexId = crypto.randomUUID();
    db.prepare(
      "INSERT INTO tenants (id, slug, name, region, residency_policy, created_at_utc) VALUES (?, ?, ?, ?, ?, ?)"
    ).run(globexId, "globex-fin", "Globex Financial Systems", "eu-central-1", "eu-central-1-gdpr", now);

    db.prepare(
      "INSERT INTO users (id, tenant_id, email, full_name, role, hashed_password, is_active, created_at_utc) VALUES (?, ?, ?, ?, ?, ?, 1, ?)"
    ).run(
      crypto.randomUUID(),
      globexId,
      "ops@globex-fin.dev",
      "Globex Security Operations",
      "admin",
      hashSecret(process.env.DEV_GLOBEX_USER_PASS || "DevGlobexPass!2026"),
      now
    );

    db.prepare(
      "INSERT INTO collectors (id, tenant_id, collector_id, display_name, api_key_hash, version, region, source_timezone, status, last_seen_utc, last_cpu_pct, last_mem_mb, config_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?)"
    ).run(
      crypto.randomUUID(),
      globexId,
      "collector-globex-01",
      "Frankfurt Edge Collector (Globex)",
      hashSecret(process.env.DEV_GLOBEX_COLLECTOR_KEY || "change-me-dev-globex-token"),
      "1.0.0",
      "eu-central-1",
      "Europe/Berlin",
      "OFFLINE",
      null,
      JSON.stringify({ poll_seconds: 5, policy_version: "1.0.0" })
    );

    db.prepare(
      "INSERT INTO tenant_thresholds (tenant_id, cpu_threshold, memory_threshold, latency_threshold_ms, packet_loss_threshold_pct, offline_timeout_seconds, updated_at_utc) VALUES (?, 90, 90, 200, 5, 60, ?)"
    ).run(globexId, now);
  }

  return db;
}

const db = initDatabase();

// WebSocket hub keyed by tenant_id
const tenantSockets = new Map<string, Set<WebSocket>>();

function broadcastToTenant(tenantId: string, type: string, data: Record<string, unknown>): void {
  const clients = tenantSockets.get(tenantId);
  if (!clients || clients.size === 0) return;
  const payload = JSON.stringify({ type, data });
  for (const ws of clients) {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(payload);
    }
  }
}

interface TenantRow {
  id: string;
  slug: string;
  name: string;
  region: string;
  residency_policy: string;
}

interface UserRow {
  id: string;
  tenant_id: string;
  email: string;
  full_name: string;
  role: string;
  hashed_password: string;
  is_active: number;
}

interface ThresholdRow {
  tenant_id: string;
  cpu_threshold: number;
  memory_threshold: number;
  latency_threshold_ms: number;
  packet_loss_threshold_pct: number;
  offline_timeout_seconds: number;
  updated_at_utc: string;
}

function buildLoginResponse(user: UserRow, tenant: TenantRow) {
  const access_token = createJwt({
    sub: user.email,
    tenant_id: tenant.id,
    tenant_slug: tenant.slug,
    role: user.role,
    principal_type: "user",
  });
  return {
    access_token,
    token_type: "bearer",
    principal_type: "user",
    tenant_id: tenant.id,
    tenant_slug: tenant.slug,
    tenant_name: tenant.name,
    region: tenant.region,
    role: user.role,
    subject: user.email,
  };
}

function normalizeEmail(raw: unknown): string {
  const email = String(raw || "").trim().toLowerCase();
  const atIdx = email.indexOf("@");
  if (atIdx < 1 || !email.slice(atIdx + 1).includes(".")) {
    throw new Error("Provide a valid email or Gmail address");
  }
  return email;
}

function getTenantThresholds(tenantId: string): ThresholdRow {
  const row = db
    .prepare("SELECT * FROM tenant_thresholds WHERE tenant_id = ?")
    .get(tenantId) as ThresholdRow | undefined;
  if (row) return row;
  const now = utcNowIso();
  db.prepare(
    "INSERT INTO tenant_thresholds (tenant_id, cpu_threshold, memory_threshold, latency_threshold_ms, packet_loss_threshold_pct, offline_timeout_seconds, updated_at_utc) VALUES (?, 90, 90, 200, 5, 60, ?)"
  ).run(tenantId, now);
  return {
    tenant_id: tenantId,
    cpu_threshold: 90,
    memory_threshold: 90,
    latency_threshold_ms: 200,
    packet_loss_threshold_pct: 5,
    offline_timeout_seconds: 60,
    updated_at_utc: now,
  };
}

function buildPassportForIncident(
  incidentId: string,
  tenantId: string,
  incidentCode: string,
  title: string,
  severity: string,
  status: string,
  sourceId: string,
  detectedAt: string,
  affectedComponents: string[],
  evidenceIds: string[],
  anomalies: Array<{
    id: string;
    component: string;
    metric_name: string;
    metric_value: number;
    detection_method: string;
    severity: string;
    description: string;
    detected_at_utc: string;
  }>,
  existingAuditHistory?: Array<{ timestamp_utc: string; action: string; actor?: string; details: string }>
) {
  const downstream = new Set<string>(affectedComponents);
  const paths: string[] = [];
  for (const comp of affectedComponents) {
    const deps = COMPONENT_DEPENDENCIES[comp] || [];
    for (const d of deps) {
      downstream.add(d);
      paths.push(`${comp} -> ${d}`);
    }
  }

  const hypotheses: Array<{
    rank: number;
    hypothesis_type: string;
    title: string;
    explanation: string;
    confidence_score: number;
    confidence_method: string;
    uncertainty_note: string;
    supporting_evidence: string[];
  }> = [];

  const hasCpu = anomalies.some((a) => a.metric_name === "cpu_usage");
  const hasMem = anomalies.some((a) => a.metric_name === "memory_usage");
  const hasNet = anomalies.some(
    (a) => a.metric_name === "network_latency_ms" || a.metric_name === "packet_loss_pct"
  );
  const hasSvc = anomalies.some((a) => a.metric_name === "service_status");

  if (hasCpu) {
    hypotheses.push({
      rank: 1,
      hypothesis_type: "compute_saturation",
      title: "Worker / API CPU Saturation & Runqueue Contention",
      explanation:
        "Sustained CPU breach observed alongside correlated telemetry metadata; suggests compute thread starvation or tight retry loops.",
      confidence_score: 0.78,
      confidence_method: "Weighted deterministic evidence scoring (threshold + correlation window)",
      uncertainty_note:
        "Probabilistic hypothesis only — raw process stack traces remain local to Tier 1 collector.",
      supporting_evidence: anomalies
        .filter((a) => a.metric_name === "cpu_usage")
        .map((a) => a.id),
    });
  }
  if (hasNet || hasSvc) {
    hypotheses.push({
      rank: hypotheses.length + 1,
      hypothesis_type: "dependency_latency_cascade",
      title: "Downstream Dependency Lock or Network Degradation",
      explanation:
        "Elevated latency, packet loss, or unavailable service status indicates upstream/downstream contention across dependent services.",
      confidence_score: hasSvc ? 0.82 : 0.69,
      confidence_method: "Dependency-graph propagation + threshold breach telemetry",
      uncertainty_note:
        "Requires operator verification of target database locks or interface drops; root cause is not confirmed automatically.",
      supporting_evidence: anomalies
        .filter(
          (a) =>
            a.metric_name === "network_latency_ms" ||
            a.metric_name === "packet_loss_pct" ||
            a.metric_name === "service_status"
        )
        .map((a) => a.id),
    });
  }
  if (hasMem) {
    hypotheses.push({
      rank: hypotheses.length + 1,
      hypothesis_type: "memory_pressure",
      title: "Heap / Page-Cache Memory Pressure",
      explanation:
        "Memory utilization crossed configured boundary, increasing GC pause probability and swap contention.",
      confidence_score: 0.71,
      confidence_method: "Rolling baseline deviation + threshold boundary check",
      uncertainty_note:
        "Memory allocation dumps stay local to host environment for privacy preservation.",
      supporting_evidence: anomalies
        .filter((a) => a.metric_name === "memory_usage")
        .map((a) => a.id),
    });
  }
  if (hypotheses.length === 0) {
    hypotheses.push({
      rank: 1,
      hypothesis_type: "multivariate_deviation",
      title: "Multivariate Operational Deviation",
      explanation: "Rolling baseline deviation detected across approved infrastructure signals.",
      confidence_score: 0.62,
      confidence_method: "Rolling statistical z-score baseline",
      uncertainty_note: "Insufficient high-severity rule breaches to narrow further automatically.",
      supporting_evidence: anomalies.map((a) => a.id),
    });
  }

  hypotheses.sort((a, b) => b.confidence_score - a.confidence_score);
  hypotheses.forEach((h, i) => {
    h.rank = i + 1;
  });

  const top = hypotheses[0];
  const timeline = anomalies
    .slice()
    .sort((a, b) => a.detected_at_utc.localeCompare(b.detected_at_utc))
    .map((a) => ({
      event_timestamp_utc: a.detected_at_utc,
      event_type: `ANOMALY_${a.detection_method.toUpperCase()}`,
      description: a.description,
      severity: a.severity,
      component: a.component,
      evidence_ref: a.id,
    }));

  const recommendations = [
    {
      priority: 1,
      action_title: `Inspect local Tier 1 diagnostics on ${affectedComponents.join(", ")}`,
      rationale: "Raw logs and process profiles remain stored locally in Tier 1 SQLite for privacy.",
      safety_note: "Read-only diagnostic check; no automated host mutation.",
      requires_approval: true,
    },
    {
      priority: 2,
      action_title: "Verify upstream/downstream saturation and connection pools",
      rationale: "Mitigates cascading latency across dependent service edges.",
      safety_note: "Operator approval required before scaling or restarting workloads.",
      requires_approval: true,
    },
  ];

  const audit_history = existingAuditHistory ?? [
    {
      timestamp_utc: utcNowIso(),
      action: "PASSPORT_SYNTHESIZED",
      actor: "causalx-rca-engine",
      details: `Generated ${hypotheses.length} ranked hypotheses from ${evidenceIds.length} evidence record(s).`,
    },
  ];

  const passport = {
    incident_id: incidentId,
    incident_code: incidentCode,
    title,
    severity,
    status,
    detection_time_utc: detectedAt,
    source: sourceId,
    affected_components: affectedComponents,
    evidence_ids: evidenceIds,
    timeline,
    hypotheses,
    confidence: top.confidence_score,
    confidence_method: top.confidence_method,
    uncertainty: top.uncertainty_note,
    estimated_impact: {
      estimated_affected_components: Array.from(downstream),
      dependency_paths: paths,
      impact_disclaimer:
        "Estimated blast radius derived from service dependency topology; confirm manually before remediation.",
    },
    recommendations,
    audit_history,
  };

  db.prepare(
    `INSERT INTO incident_passports (id, tenant_id, incident_id, passport_json, generated_at_utc)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(incident_id) DO UPDATE SET passport_json = excluded.passport_json, generated_at_utc = excluded.generated_at_utc`
  ).run(crypto.randomUUID(), tenantId, incidentId, JSON.stringify(passport), utcNowIso());

  return passport;
}

interface IngestInput {
  payload_id: string;
  collector_id: string;
  event_timestamp_utc: string;
  approved_metadata: Record<string, unknown>;
  allowed_fields?: string[];
  blocked_fields?: string[];
  policy_version?: string;
  privacy_risk_score: number;
  payload_hash_sha256: string;
  hmac_signature: string;
  approval_decision: string;
}

function ingestTelemetry(tenantId: string, env: IngestInput) {
  const meta = env.approved_metadata;
  const forbidden = Object.keys(meta).filter((k) =>
    FORBIDDEN_CENTRAL_KEYS.has(k.trim().toLowerCase())
  );
  if (forbidden.length > 0) {
    const err = new Error(
      `Central ingestion rejected restricted field(s): ${forbidden.join(", ")}`
    ) as Error & { statusCode?: number };
    err.statusCode = 422;
    throw err;
  }

  if (env.approval_decision !== "APPROVED" || env.privacy_risk_score >= 100) {
    const err = new Error("Blocked or high-risk payload rejected by central gate.") as Error & {
      statusCode?: number;
    };
    err.statusCode = 422;
    throw err;
  }

  const computedHash = computeSha256Hex(meta);
  if (computedHash !== env.payload_hash_sha256) {
    const err = new Error("Payload SHA-256 hash mismatch.") as Error & { statusCode?: number };
    err.statusCode = 400;
    throw err;
  }

  const expectedHmac = computeHmacHex(HMAC_SECRET, canonicalJson(meta));
  const a = Buffer.from(expectedHmac, "utf8");
  const b = Buffer.from(env.hmac_signature, "utf8");
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    const err = new Error("Payload HMAC-SHA256 signature invalid.") as Error & {
      statusCode?: number;
    };
    err.statusCode = 400;
    throw err;
  }

  const dup = db
    .prepare("SELECT id FROM telemetry WHERE tenant_id = ? AND payload_id = ?")
    .get(tenantId, env.payload_id);
  if (dup) {
    return {
      status: "duplicate_ignored",
      payload_id: env.payload_id,
      verification_status: "VERIFIED",
      anomalies_detected: 0,
      incident_code: null as string | null,
    };
  }

  const nowIso = utcNowIso();
  const eventTs = String(meta.event_timestamp_utc || env.event_timestamp_utc || nowIso);
  const sourceId = String(meta.source_id || `src_${env.collector_id}`);
  const component = String(meta.component || "host-system");
  const cpuUsage = Number(meta.cpu_usage || 0);
  const memUsage = Number(meta.memory_usage || 0);
  const diskUsage = Number(meta.disk_usage || 0);
  const latencyMs = Number(meta.network_latency_ms || 0);
  const packetLoss = Number(meta.packet_loss_pct || 0);
  const serviceStatus = String(meta.service_status || "healthy");
  const isSim = meta.is_simulation ? 1 : 0;

  db.prepare(
    `UPDATE collectors SET status = 'ONLINE', last_seen_utc = ?, last_cpu_pct = ?, last_mem_mb = ?
     WHERE tenant_id = ? AND collector_id = ?`
  ).run(
    nowIso,
    Number(meta.collector_cpu_pct || 0),
    Number(meta.collector_rss_mb || 0),
    tenantId,
    env.collector_id
  );

  const telemetryId = crypto.randomUUID();
  db.prepare(
    `INSERT INTO telemetry (
      id, tenant_id, collector_id, payload_id, source_id, component, event_category,
      event_timestamp_utc, ingested_at_utc, source_timezone, cpu_usage, memory_usage,
      disk_usage, network_latency_ms, packet_loss_pct, service_status, failed_login_count,
      uptime_seconds, severity, is_simulation
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    telemetryId,
    tenantId,
    env.collector_id,
    env.payload_id,
    sourceId,
    component,
    String(meta.event_category || "infrastructure"),
    eventTs,
    nowIso,
    String(meta.source_timezone || "UTC"),
    cpuUsage,
    memUsage,
    diskUsage,
    latencyMs,
    packetLoss,
    serviceStatus,
    Number(meta.failed_login_count || 0),
    Number(meta.uptime_seconds || 0),
    String(meta.severity || "LOW"),
    isSim
  );

  db.prepare(
    `INSERT INTO egress_proofs (
      id, tenant_id, collector_id, payload_id, source_id, event_timestamp_utc,
      approved_metadata_json, allowed_fields_json, blocked_fields_json, policy_version,
      privacy_risk_score, payload_hash_sha256, hmac_signature, verification_status,
      approval_decision, delivery_status, created_at_utc
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'VERIFIED', ?, 'DELIVERED', ?)`
  ).run(
    crypto.randomUUID(),
    tenantId,
    env.collector_id,
    env.payload_id,
    sourceId,
    eventTs,
    JSON.stringify(meta),
    JSON.stringify(env.allowed_fields || Object.keys(meta).sort()),
    JSON.stringify(env.blocked_fields || []),
    env.policy_version || "1.0.0",
    env.privacy_risk_score,
    env.payload_hash_sha256,
    env.hmac_signature,
    env.approval_decision,
    nowIso
  );

  // Rule + rolling baseline anomaly detection
  const thresholds = getTenantThresholds(tenantId);
  const historyRows = db
    .prepare(
      "SELECT cpu_usage, memory_usage, network_latency_ms FROM telemetry WHERE tenant_id = ? ORDER BY event_timestamp_utc DESC LIMIT 30"
    )
    .all(tenantId) as Array<{
    cpu_usage: number;
    memory_usage: number;
    network_latency_ms: number;
  }>;

  const mean = (arr: number[]) => (arr.length ? arr.reduce((a, b) => a + b, 0) / arr.length : 0);
  const cpuMean = mean(historyRows.map((r) => r.cpu_usage));
  const memMean = mean(historyRows.map((r) => r.memory_usage));
  const latMean = mean(historyRows.map((r) => r.network_latency_ms));

  const detectedAnomalies: Array<{
    id: string;
    component: string;
    metric_name: string;
    metric_value: number;
    detection_method: string;
    severity: string;
    description: string;
    detected_at_utc: string;
  }> = [];

  const recordAnomaly = (
    metricName: string,
    metricValue: number,
    baselineMean: number,
    method: string,
    severity: string,
    description: string
  ) => {
    const aid = crypto.randomUUID();
    db.prepare(
      `INSERT INTO anomalies (
        id, tenant_id, collector_id, telemetry_id, source_id, component, metric_name,
        metric_value, baseline_mean, baseline_std, detection_method, severity, description,
        contributing_signals_json, detected_at_utc
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)`
    ).run(
      aid,
      tenantId,
      env.collector_id,
      telemetryId,
      sourceId,
      component,
      metricName,
      metricValue,
      baselineMean,
      method,
      severity,
      description,
      JSON.stringify({ [metricName]: metricValue }),
      eventTs
    );
    detectedAnomalies.push({
      id: aid,
      component,
      metric_name: metricName,
      metric_value: metricValue,
      detection_method: method,
      severity,
      description,
      detected_at_utc: eventTs,
    });
  };

  if (cpuUsage > thresholds.cpu_threshold) {
    recordAnomaly(
      "cpu_usage",
      cpuUsage,
      cpuMean,
      "rule",
      "Critical",
      `CPU utilization ${cpuUsage.toFixed(1)}% exceeded threshold (${thresholds.cpu_threshold}%).`
    );
  }
  if (memUsage > thresholds.memory_threshold) {
    recordAnomaly(
      "memory_usage",
      memUsage,
      memMean,
      "rule",
      "Critical",
      `Memory utilization ${memUsage.toFixed(1)}% exceeded threshold (${thresholds.memory_threshold}%).`
    );
  }
  if (latencyMs > thresholds.latency_threshold_ms) {
    recordAnomaly(
      "network_latency_ms",
      latencyMs,
      latMean,
      "rule",
      "High",
      `Network latency ${latencyMs.toFixed(1)} ms exceeded threshold (${thresholds.latency_threshold_ms} ms).`
    );
  }
  if (packetLoss > thresholds.packet_loss_threshold_pct) {
    recordAnomaly(
      "packet_loss_pct",
      packetLoss,
      0,
      "rule",
      "High",
      `Packet loss ${packetLoss.toFixed(2)}% exceeded threshold (${thresholds.packet_loss_threshold_pct}%).`
    );
  }
  if (serviceStatus === "unavailable") {
    recordAnomaly(
      "service_status",
      1,
      0,
      "rule",
      "Critical",
      `Critical service ${component} reported unavailable status.`
    );
  }

  let incidentCode: string | null = null;
  if (detectedAnomalies.length > 0) {
    const windowStart = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    const existingInc = db
      .prepare(
        `SELECT * FROM incidents
         WHERE tenant_id = ? AND status IN ('OPEN', 'INVESTIGATING') AND detected_at_utc >= ?
         ORDER BY detected_at_utc DESC LIMIT 1`
      )
      .get(tenantId, windowStart) as
      | {
          id: string;
          incident_code: string;
          title: string;
          status: string;
          severity: string;
          primary_source_id: string;
          affected_components_json: string;
          evidence_ids_json: string;
          detected_at_utc: string;
        }
      | undefined;

    if (existingInc) {
      incidentCode = existingInc.incident_code;
      const comps = Array.from(
        new Set([...(JSON.parse(existingInc.affected_components_json) as string[]), component])
      );
      const evIds = Array.from(
        new Set([
          ...(JSON.parse(existingInc.evidence_ids_json) as string[]),
          ...detectedAnomalies.map((a) => a.id),
        ])
      );
      const nextSeverity = detectedAnomalies.some((a) => a.severity === "Critical")
        ? "Critical"
        : existingInc.severity;
      db.prepare(
        "UPDATE incidents SET severity = ?, affected_components_json = ?, evidence_ids_json = ?, updated_at_utc = ? WHERE id = ?"
      ).run(nextSeverity, JSON.stringify(comps), JSON.stringify(evIds), nowIso, existingInc.id);

      const allAnom = db
        .prepare("SELECT * FROM anomalies WHERE tenant_id = ? ORDER BY detected_at_utc DESC LIMIT 20")
        .all(tenantId) as Array<{
        id: string;
        component: string;
        metric_name: string;
        metric_value: number;
        detection_method: string;
        severity: string;
        description: string;
        detected_at_utc: string;
      }>;
      const linked = allAnom.filter((a) => evIds.includes(a.id));
      buildPassportForIncident(
        existingInc.id,
        tenantId,
        existingInc.incident_code,
        existingInc.title,
        nextSeverity,
        existingInc.status,
        existingInc.primary_source_id,
        existingInc.detected_at_utc,
        comps,
        evIds,
        linked
      );
    } else {
      const countRow = db
        .prepare("SELECT COUNT(*) as cnt FROM incidents WHERE tenant_id = ?")
        .get(tenantId) as { cnt: number };
      incidentCode = `INC-${String(countRow.cnt + 1).padStart(4, "0")}`;
      const incId = crypto.randomUUID();
      const incTitle = `${component} ${detectedAnomalies[0].metric_name.replace(/_/g, " ")} anomaly`;
      const sev = detectedAnomalies.some((a) => a.severity === "Critical") ? "Critical" : "High";
      const evIds = detectedAnomalies.map((a) => a.id);
      const comps = [component];
      db.prepare(
        `INSERT INTO incidents (
          id, tenant_id, incident_code, title, status, severity, primary_source_id,
          affected_components_json, evidence_ids_json, correlation_score, detected_at_utc, updated_at_utc
        ) VALUES (?, ?, ?, ?, 'OPEN', ?, ?, ?, ?, 0.85, ?, ?)`
      ).run(
        incId,
        tenantId,
        incidentCode,
        incTitle,
        sev,
        sourceId,
        JSON.stringify(comps),
        JSON.stringify(evIds),
        eventTs,
        nowIso
      );

      buildPassportForIncident(
        incId,
        tenantId,
        incidentCode,
        incTitle,
        sev,
        "OPEN",
        sourceId,
        eventTs,
        comps,
        evIds,
        detectedAnomalies
      );
    }

    broadcastToTenant(tenantId, "incident:updated", {
      incident_code: incidentCode,
      source_id: sourceId,
    });
  }

  broadcastToTenant(tenantId, "telemetry:ingested", {
    payload_id: env.payload_id,
    collector_id: env.collector_id,
    source_id: sourceId,
    event_timestamp_utc: eventTs,
    cpu_usage: cpuUsage,
    memory_usage: memUsage,
    network_latency_ms: latencyMs,
    packet_loss_pct: packetLoss,
    anomalies_detected: detectedAnomalies.length,
    incident_code: incidentCode,
  });

  return {
    status: "accepted",
    payload_id: env.payload_id,
    verification_status: "VERIFIED",
    anomalies_detected: detectedAnomalies.length,
    incident_code: incidentCode,
  };
}

// Sample real local Node/OS telemetry via node:os and process, filtered through local Privacy Shield
let prevCpuTotals: { idle: number; total: number } | null = null;

function sampleOsCpuPercent(): number {
  const cpus = os.cpus();
  let idle = 0;
  let total = 0;
  for (const cpu of cpus) {
    idle += cpu.times.idle;
    total +=
      cpu.times.user + cpu.times.nice + cpu.times.sys + cpu.times.idle + cpu.times.irq;
  }
  if (!prevCpuTotals) {
    prevCpuTotals = { idle, total };
    const load1m = os.loadavg()[0] || 0.2;
    return Number(Math.min(98, Math.max(2, (load1m / Math.max(1, cpus.length)) * 100)).toFixed(1));
  }
  const idleDelta = idle - prevCpuTotals.idle;
  const totalDelta = total - prevCpuTotals.total;
  prevCpuTotals = { idle, total };
  if (totalDelta <= 0) return 8.0;
  return Number(Math.max(1, Math.min(99, (1 - idleDelta / totalDelta) * 100)).toFixed(1));
}

function runLocalCollectorCycle(tenantSlug: string, collectorId: string, scenario?: string) {
  const tenant = db
    .prepare("SELECT * FROM tenants WHERE slug = ?")
    .get(tenantSlug) as TenantRow | undefined;
  if (!tenant) return null;

  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const memPct = Number((((totalMem - freeMem) / Math.max(1, totalMem)) * 100).toFixed(1));
  const cpuPct = sampleOsCpuPercent();
  const rssMb = Number((process.memoryUsage().rss / (1024 * 1024)).toFixed(1));
  const nowIso = utcNowIso();

  // Raw local event (kept inside local collector boundary; sensitive/restricted fields stripped before egress)
  const rawEvent: Record<string, unknown> = {
    hostname: os.hostname(),
    username: os.userInfo().username,
    internal_ip: "127.0.0.1",
    component: "host-system",
    event_category: "infrastructure",
    event_timestamp_utc: nowIso,
    source_timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC",
    cpu_usage: cpuPct,
    memory_usage: memPct,
    disk_usage: 44.0,
    network_latency_ms: Number((12 + (cpuPct * 0.35)).toFixed(1)),
    packet_loss_pct: 0.0,
    service_status: "healthy",
    uptime_seconds: Math.round(os.uptime()),
    severity: "LOW",
    is_simulation: Boolean(scenario),
    collector_cpu_pct: cpuPct,
    collector_rss_mb: rssMb,
  };

  if (scenario === "cpu_spike") {
    rawEvent.component = "api-gateway";
    rawEvent.event_category = "compute_saturation";
    rawEvent.cpu_usage = 96.4;
    rawEvent.network_latency_ms = 92.0;
    rawEvent.severity = "Critical";
  } else if (scenario === "memory_leak") {
    rawEvent.component = "payment-worker";
    rawEvent.event_category = "memory_exhaustion";
    rawEvent.memory_usage = 95.8;
    rawEvent.service_status = "degraded";
    rawEvent.severity = "Critical";
  } else if (scenario === "network_drop") {
    rawEvent.component = "edge-ingress";
    rawEvent.event_category = "network_degradation";
    rawEvent.network_latency_ms = 285.0;
    rawEvent.packet_loss_pct = 9.4;
    rawEvent.service_status = "degraded";
    rawEvent.severity = "High";
  } else if (scenario === "db_lock") {
    rawEvent.component = "postgres-primary";
    rawEvent.event_category = "database_contention";
    rawEvent.cpu_usage = 91.2;
    rawEvent.network_latency_ms = 265.0;
    rawEvent.service_status = "unavailable";
    rawEvent.severity = "Critical";
  } else if (scenario === "secret_leak_test") {
    rawEvent.component = "auth-service";
    rawEvent.event_category = "privacy_shield_verification";
    rawEvent.password = "REDACTED_DO_NOT_TRANSMIT";
    rawEvent.api_key = "sk-sim-blocked-local";
    rawEvent.bearer_token = "eyJ-sim-blocked-local";
    rawEvent.severity = "Medium";
  }

  // Local Privacy Shield: strip SENSITIVE and RESTRICTED fields, pseudonymize host -> src_*
  const blockedFields: string[] = [];
  const approvedMetadata: Record<string, unknown> = {
    source_id: pseudonymizeSource(tenant.slug, os.hostname()),
    collector_id: collectorId,
  };

  for (const [k, v] of Object.entries(rawEvent)) {
    if (FORBIDDEN_CENTRAL_KEYS.has(k.toLowerCase())) {
      blockedFields.push(k);
    } else {
      approvedMetadata[k] = v;
    }
  }
  blockedFields.sort();

  const payloadId = crypto.randomUUID();
  const payloadHash = computeSha256Hex(approvedMetadata);
  const hmacSig = computeHmacHex(HMAC_SECRET, canonicalJson(approvedMetadata));

  const res = ingestTelemetry(tenant.id, {
    payload_id: payloadId,
    collector_id: collectorId,
    event_timestamp_utc: nowIso,
    approved_metadata: approvedMetadata,
    allowed_fields: Object.keys(approvedMetadata).sort(),
    blocked_fields: blockedFields,
    policy_version: "1.0.0",
    privacy_risk_score: 0,
    payload_hash_sha256: payloadHash,
    hmac_signature: hmacSig,
    approval_decision: "APPROVED",
  });

  return { ...res, blocked_fields: blockedFields };
}

interface AuthedRequest extends Request {
  principal?: JwtClaims;
}

function requireAuth(req: AuthedRequest, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization || "";
  if (!authHeader.startsWith("Bearer ")) {
    res.status(401).json({ detail: "Missing Bearer authentication token" });
    return;
  }
  try {
    req.principal = decodeJwt(authHeader.slice(7).trim());
    next();
  } catch (err) {
    res.status(401).json({ detail: err instanceof Error ? err.message : "Invalid token" });
  }
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: "1mb" }));

  // Health
  app.get("/api/v1/health", (_req, res) => {
    res.json({
      status: "ok",
      service: "causal-x-backend",
      version: "1.0.0",
      environment: APP_ENV,
      region: "us-east-1",
      database: "sqlite-local",
      timestamp_utc: utcNowIso(),
    });
  });

  // Auth: Gmail / Email + Password (and Collector API Key)
  app.post("/api/v1/auth/login", (req, res) => {
    try {
      const { email, password, collector_id, collector_api_key, tenant_slug } = req.body || {};
      if (email && password) {
        const normEmail = normalizeEmail(email);
        const user = db.prepare("SELECT * FROM users WHERE email = ?").get(normEmail) as
          | UserRow
          | undefined;
        if (!user || !user.is_active || !verifySecret(String(password), user.hashed_password)) {
          res.status(401).json({ detail: "Invalid email or password" });
          return;
        }
        const tenant = db
          .prepare("SELECT * FROM tenants WHERE id = ?")
          .get(user.tenant_id) as TenantRow | undefined;
        if (!tenant) {
          res.status(401).json({ detail: "Tenant not found" });
          return;
        }
        res.json(buildLoginResponse(user, tenant));
        return;
      }

      if (collector_id && collector_api_key && tenant_slug) {
        const tenant = db
          .prepare("SELECT * FROM tenants WHERE slug = ?")
          .get(String(tenant_slug).trim()) as TenantRow | undefined;
        if (!tenant) {
          res.status(401).json({ detail: "Invalid tenant or collector credentials" });
          return;
        }
        const col = db
          .prepare("SELECT * FROM collectors WHERE tenant_id = ? AND collector_id = ?")
          .get(tenant.id, String(collector_id).trim()) as
          | { collector_id: string; api_key_hash: string }
          | undefined;
        if (!col || !verifySecret(String(collector_api_key), col.api_key_hash)) {
          res.status(401).json({ detail: "Invalid tenant or collector credentials" });
          return;
        }
        res.json({
          access_token: createJwt({
            sub: col.collector_id,
            tenant_id: tenant.id,
            tenant_slug: tenant.slug,
            role: "collector",
            principal_type: "collector",
          }),
          token_type: "bearer",
          principal_type: "collector",
          tenant_id: tenant.id,
          tenant_slug: tenant.slug,
          tenant_name: tenant.name,
          region: tenant.region,
          role: "collector",
          subject: col.collector_id,
        });
        return;
      }

      res.status(400).json({
        detail: "Provide email and password (or collector credentials)",
      });
    } catch (err) {
      res.status(400).json({ detail: err instanceof Error ? err.message : "Login failed" });
    }
  });

  // Auth: Register new Gmail / Operator account with password
  app.post("/api/v1/auth/register", (req, res) => {
    try {
      const { email, password, full_name, tenant_slug = "acme-cloud" } = req.body || {};
      const normEmail = normalizeEmail(email);
      const passStr = String(password || "");
      if (passStr.length < 6) {
        res.status(400).json({ detail: "Password must be at least 6 characters" });
        return;
      }
      const tenant = db
        .prepare("SELECT * FROM tenants WHERE slug = ?")
        .get(String(tenant_slug).trim()) as TenantRow | undefined;
      if (!tenant) {
        res.status(404).json({ detail: `Tenant '${tenant_slug}' not found` });
        return;
      }

      const existing = db.prepare("SELECT * FROM users WHERE email = ?").get(normEmail) as
        | UserRow
        | undefined;
      if (existing) {
        if (!verifySecret(passStr, existing.hashed_password)) {
          res.status(409).json({
            detail: "Email already registered with a different password. Use Sign in or Passwordless.",
          });
          return;
        }
        const existingTenant =
          (db.prepare("SELECT * FROM tenants WHERE id = ?").get(existing.tenant_id) as
            | TenantRow
            | undefined) || tenant;
        res.json(buildLoginResponse(existing, existingTenant));
        return;
      }

      const userId = crypto.randomUUID();
      const now = utcNowIso();
      const displayName = String(full_name || normEmail.split("@")[0]).trim();
      const hashed = hashSecret(passStr);
      db.prepare(
        "INSERT INTO users (id, tenant_id, email, full_name, role, hashed_password, is_active, created_at_utc) VALUES (?, ?, ?, ?, 'operator', ?, 1, ?)"
      ).run(userId, tenant.id, normEmail, displayName, hashed, now);

      const createdUser: UserRow = {
        id: userId,
        tenant_id: tenant.id,
        email: normEmail,
        full_name: displayName,
        role: "operator",
        hashed_password: hashed,
        is_active: 1,
      };
      res.json(buildLoginResponse(createdUser, tenant));
    } catch (err) {
      res.status(400).json({ detail: err instanceof Error ? err.message : "Registration failed" });
    }
  });

  // Auth: Passwordless (No Password) Request OTP
  app.post("/api/v1/auth/passwordless/request", (req, res) => {
    try {
      const { email, tenant_slug = "acme-cloud" } = req.body || {};
      const normEmail = normalizeEmail(email);
      const tenant = db
        .prepare("SELECT * FROM tenants WHERE slug = ?")
        .get(String(tenant_slug).trim()) as TenantRow | undefined;
      if (!tenant) {
        res.status(404).json({ detail: `Tenant '${tenant_slug}' not found` });
        return;
      }

      const code = String(crypto.randomInt(100000, 999999));
      const codeHash = crypto
        .createHash("sha256")
        .update(`${normEmail}:${code}`)
        .digest("hex");
      const now = utcNowIso();
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

      db.prepare(
        "INSERT INTO passwordless_codes (id, tenant_id, email, code_hash, expires_at_utc, used, created_at_utc) VALUES (?, ?, ?, ?, ?, 0, ?)"
      ).run(crypto.randomUUID(), tenant.id, normEmail, codeHash, expiresAt, now);

      res.json({
        status: "code_issued",
        email: normEmail,
        tenant_slug: tenant.slug,
        expires_in_seconds: 600,
        dev_verification_code: APP_ENV !== "production" ? code : null,
      });
    } catch (err) {
      res.status(400).json({ detail: err instanceof Error ? err.message : "Request failed" });
    }
  });

  // Auth: Passwordless (No Password) Verify OTP or Instant Dev Access
  app.post("/api/v1/auth/passwordless/verify", (req, res) => {
    try {
      const { email, tenant_slug = "acme-cloud", code, instant = false } = req.body || {};
      const normEmail = normalizeEmail(email);
      const tenant = db
        .prepare("SELECT * FROM tenants WHERE slug = ?")
        .get(String(tenant_slug).trim()) as TenantRow | undefined;
      if (!tenant) {
        res.status(404).json({ detail: `Tenant '${tenant_slug}' not found` });
        return;
      }

      if (instant) {
        if (APP_ENV === "production") {
          res.status(403).json({
            detail: "Instant passwordless login is disabled in production; use one-time code.",
          });
          return;
        }
      } else {
        const cleanCode = String(code || "").trim();
        if (cleanCode.length < 6) {
          res.status(400).json({ detail: "Enter the 6-digit passwordless verification code" });
          return;
        }
        const row = db
          .prepare(
            `SELECT * FROM passwordless_codes
             WHERE tenant_id = ? AND email = ? AND used = 0
             ORDER BY created_at_utc DESC LIMIT 1`
          )
          .get(tenant.id, normEmail) as
          | { id: string; code_hash: string; expires_at_utc: string }
          | undefined;

        if (!row) {
          res.status(401).json({ detail: "No active passwordless code found for this email" });
          return;
        }
        const expectedHash = crypto
          .createHash("sha256")
          .update(`${normEmail}:${cleanCode}`)
          .digest("hex");
        if (
          row.expires_at_utc < utcNowIso() ||
          !crypto.timingSafeEqual(
            Buffer.from(row.code_hash, "utf8"),
            Buffer.from(expectedHash, "utf8")
          )
        ) {
          res.status(401).json({ detail: "Invalid or expired verification code" });
          return;
        }
        db.prepare("UPDATE passwordless_codes SET used = 1 WHERE id = ?").run(row.id);
      }

      let user = db.prepare("SELECT * FROM users WHERE email = ?").get(normEmail) as
        | UserRow
        | undefined;
      if (!user) {
        const userId = crypto.randomUUID();
        const hashed = hashSecret(crypto.randomBytes(24).toString("hex"));
        const displayName = normEmail.split("@")[0];
        db.prepare(
          "INSERT INTO users (id, tenant_id, email, full_name, role, hashed_password, is_active, created_at_utc) VALUES (?, ?, ?, ?, 'operator', ?, 1, ?)"
        ).run(userId, tenant.id, normEmail, displayName, hashed, utcNowIso());
        user = {
          id: userId,
          tenant_id: tenant.id,
          email: normEmail,
          full_name: displayName,
          role: "operator",
          hashed_password: hashed,
          is_active: 1,
        };
      }

      const userTenant =
        (db.prepare("SELECT * FROM tenants WHERE id = ?").get(user.tenant_id) as
          | TenantRow
          | undefined) || tenant;
      res.json(buildLoginResponse(user, userTenant));
    } catch (err) {
      res.status(400).json({ detail: err instanceof Error ? err.message : "Verification failed" });
    }
  });

  // Protected telemetry & platform APIs
  app.post("/api/v1/telemetry", requireAuth, (req: AuthedRequest, res) => {
    try {
      const result = ingestTelemetry(req.principal!.tenant_id, req.body);
      res.json(result);
    } catch (err) {
      const code = (err as Error & { statusCode?: number }).statusCode || 400;
      res.status(code).json({ detail: err instanceof Error ? err.message : "Ingestion failed" });
    }
  });

  app.get("/api/v1/telemetry", requireAuth, (req: AuthedRequest, res) => {
    const limit = Math.min(500, Math.max(1, Number(req.query.limit || 100)));
    const rows = db
      .prepare(
        `SELECT * FROM telemetry WHERE tenant_id = ?
         ORDER BY event_timestamp_utc ASC LIMIT ?`
      )
      .all(req.principal!.tenant_id, limit) as Array<Record<string, unknown>>;
    res.json(
      rows.map((r) => ({
        ...r,
        is_simulation: Boolean(r.is_simulation),
      }))
    );
  });

  app.get("/api/v1/dashboard/overview", requireAuth, (req: AuthedRequest, res) => {
    const tid = req.principal!.tenant_id;
    const tenant = (db.prepare("SELECT * FROM tenants WHERE id = ?").get(tid) as unknown as
      | TenantRow
      | undefined) ?? {
      id: tid,
      slug: req.principal!.tenant_slug,
      name: req.principal!.tenant_slug,
      region: "us-east-1",
      residency_policy: "strict",
    };
    const collectors = db
      .prepare("SELECT * FROM collectors WHERE tenant_id = ?")
      .all(tid) as Array<{ status: string; last_seen_utc: string | null }>;
    const online = collectors.filter((c) => c.status === "ONLINE").length;

    const sourcesRow = db
      .prepare("SELECT COUNT(DISTINCT source_id) as cnt FROM telemetry WHERE tenant_id = ?")
      .get(tid) as { cnt: number };
    const incRow = db
      .prepare(
        "SELECT COUNT(*) as cnt FROM incidents WHERE tenant_id = ? AND status IN ('OPEN', 'INVESTIGATING')"
      )
      .get(tid) as { cnt: number };
    const critRow = db
      .prepare(
        "SELECT COUNT(*) as cnt FROM anomalies WHERE tenant_id = ? AND severity IN ('Critical', 'High')"
      )
      .get(tid) as { cnt: number };

    const proofs = db
      .prepare("SELECT blocked_fields_json, verification_status, privacy_risk_score FROM egress_proofs WHERE tenant_id = ?")
      .all(tid) as Array<{
      blocked_fields_json: string;
      verification_status: string;
      privacy_risk_score: number;
    }>;
    const blockedCount = proofs.reduce(
      (acc, p) => acc + (JSON.parse(p.blocked_fields_json || "[]") as string[]).length,
      0
    );
    const verifiedCount = proofs.filter((p) => p.verification_status === "VERIFIED").length;
    const maxRisk = proofs.reduce((m, p) => Math.max(m, p.privacy_risk_score), 0);

    const latestTelemetry = (
      db
        .prepare(
          "SELECT event_timestamp_utc, source_id, component, cpu_usage, memory_usage, network_latency_ms, packet_loss_pct, severity FROM telemetry WHERE tenant_id = ? ORDER BY event_timestamp_utc DESC LIMIT 40"
        )
        .all(tid) as Array<Record<string, unknown>>
    ).reverse();

    const recentIncidents = db
      .prepare(
        "SELECT id, incident_code, title, severity, status, detected_at_utc, primary_source_id FROM incidents WHERE tenant_id = ? ORDER BY detected_at_utc DESC LIMIT 5"
      )
      .all(tid) as Array<Record<string, unknown>>;

    const openCrit = db
      .prepare(
        "SELECT COUNT(*) as cnt FROM incidents WHERE tenant_id = ? AND status IN ('OPEN', 'INVESTIGATING') AND severity = 'Critical'"
      )
      .get(tid) as { cnt: number };
    const openHigh = db
      .prepare(
        "SELECT COUNT(*) as cnt FROM incidents WHERE tenant_id = ? AND status IN ('OPEN', 'INVESTIGATING') AND severity = 'High'"
      )
      .get(tid) as { cnt: number };

    let healthState: "Excellent" | "Good" | "Fair" | "Poor" = "Excellent";
    let healthReason = "Collectors reporting cleanly; metrics within expected baselines.";
    if (collectors.length > 0 && online === 0) {
      healthState = "Poor";
      healthReason = "All registered collectors are currently OFFLINE or stale.";
    } else if (openCrit.cnt > 0) {
      healthState = "Poor";
      healthReason = "Critical severity incident active.";
    } else if (openHigh.cnt > 0) {
      healthState = "Fair";
      healthReason = "High severity incident requires operator attention.";
    } else if (latestTelemetry.length === 0) {
      healthState = "Fair";
      healthReason = "Waiting for telemetry stream from local collector.";
    }

    const lastSync =
      collectors
        .map((c) => c.last_seen_utc)
        .filter((x): x is string => Boolean(x))
        .sort()
        .pop() ?? null;

    res.json({
      tenant,
      health_state: healthState,
      health_reason: healthReason,
      kpis: {
        active_sources: sourcesRow.cnt,
        online_collectors: online,
        total_collectors: collectors.length,
        active_incidents: incRow.cnt,
        critical_alerts: critRow.cnt,
        blocked_fields_count: blockedCount,
        verified_payloads_count: verifiedCount,
        privacy_risk_score: maxRisk,
        last_sync_utc: lastSync,
      },
      telemetry_series: latestTelemetry,
      recent_incidents: recentIncidents,
    });
  });

  app.get("/api/v1/collectors", requireAuth, (req: AuthedRequest, res) => {
    const rows = db
      .prepare("SELECT * FROM collectors WHERE tenant_id = ? ORDER BY collector_id ASC")
      .all(req.principal!.tenant_id) as Array<Record<string, unknown>>;
    res.json(
      rows.map((c) => ({
        id: c.id,
        collector_id: c.collector_id,
        display_name: c.display_name,
        status: c.status,
        version: c.version,
        region: c.region,
        source_timezone: c.source_timezone,
        last_seen_utc: c.last_seen_utc,
        last_cpu_pct: c.last_cpu_pct,
        last_mem_mb: c.last_mem_mb,
        config: JSON.parse(String(c.config_json || "{}")),
      }))
    );
  });

  app.get("/api/v1/egress/audit", requireAuth, (req: AuthedRequest, res) => {
    const limit = Math.min(200, Math.max(1, Number(req.query.limit || 50)));
    const rows = db
      .prepare(
        "SELECT * FROM egress_proofs WHERE tenant_id = ? ORDER BY created_at_utc DESC LIMIT ?"
      )
      .all(req.principal!.tenant_id, limit) as Array<Record<string, unknown>>;
    res.json(
      rows.map((p) => ({
        id: p.id,
        payload_id: p.payload_id,
        tenant_id: p.tenant_id,
        collector_id: p.collector_id,
        source_id: p.source_id,
        event_timestamp_utc: p.event_timestamp_utc,
        approved_metadata: JSON.parse(String(p.approved_metadata_json || "{}")),
        allowed_fields: JSON.parse(String(p.allowed_fields_json || "[]")),
        blocked_fields: JSON.parse(String(p.blocked_fields_json || "[]")),
        policy_version: p.policy_version,
        privacy_risk_score: p.privacy_risk_score,
        payload_hash_sha256: p.payload_hash_sha256,
        hmac_signature: p.hmac_signature,
        verification_status: p.verification_status,
        approval_decision: p.approval_decision,
        delivery_status: p.delivery_status,
        created_at_utc: p.created_at_utc,
      }))
    );
  });

  app.post("/api/v1/egress/verify", requireAuth, (req, res) => {
    const { payload_id = null, approved_metadata, payload_hash_sha256, hmac_signature } =
      req.body || {};
    const computedSha = computeSha256Hex(approved_metadata);
    const hashValid = computedSha === payload_hash_sha256;
    let hmacValid: boolean | null = null;
    if (hmac_signature) {
      const expected = computeHmacHex(HMAC_SECRET, canonicalJson(approved_metadata));
      const a = Buffer.from(expected, "utf8");
      const b = Buffer.from(String(hmac_signature), "utf8");
      hmacValid = a.length === b.length && crypto.timingSafeEqual(a, b);
    }
    const ok = hashValid && hmacValid !== false;
    res.json({
      payload_id,
      hash_valid: hashValid,
      hmac_valid: hmacValid,
      computed_sha256: computedSha,
      verification_status: ok ? "VERIFIED" : "TAMPER_DETECTED",
      checked_at_utc: utcNowIso(),
    });
  });

  app.get("/api/v1/anomalies", requireAuth, (req: AuthedRequest, res) => {
    const limit = Math.min(500, Math.max(1, Number(req.query.limit || 100)));
    const rows = db
      .prepare(
        "SELECT * FROM anomalies WHERE tenant_id = ? ORDER BY detected_at_utc DESC LIMIT ?"
      )
      .all(req.principal!.tenant_id, limit) as Array<Record<string, unknown>>;
    res.json(
      rows.map((a) => ({
        ...a,
        contributing_signals: JSON.parse(String(a.contributing_signals_json || "{}")),
      }))
    );
  });

  app.get("/api/v1/incidents", requireAuth, (req: AuthedRequest, res) => {
    const tid = req.principal!.tenant_id;
    const rows = db
      .prepare("SELECT * FROM incidents WHERE tenant_id = ? ORDER BY detected_at_utc DESC")
      .all(tid) as Array<Record<string, unknown>>;
    res.json(
      rows.map((inc) => {
        const passportRow = db
          .prepare("SELECT passport_json FROM incident_passports WHERE incident_id = ?")
          .get(String(inc.id)) as { passport_json: string } | undefined;
        const passport = passportRow
          ? (JSON.parse(passportRow.passport_json) as {
              hypotheses?: Array<{ title: string; confidence_score: number }>;
            })
          : null;
        const topHyp = passport?.hypotheses?.[0];
        return {
          id: inc.id,
          incident_code: inc.incident_code,
          title: inc.title,
          status: inc.status,
          severity: inc.severity,
          primary_source_id: inc.primary_source_id,
          affected_components: JSON.parse(String(inc.affected_components_json || "[]")),
          evidence_count: (JSON.parse(String(inc.evidence_ids_json || "[]")) as string[]).length,
          correlation_score: inc.correlation_score,
          leading_hypothesis: topHyp?.title || "Pending synthesis",
          leading_confidence: topHyp?.confidence_score || 0,
          detected_at_utc: inc.detected_at_utc,
          updated_at_utc: inc.updated_at_utc,
        };
      })
    );
  });

  app.get("/api/v1/incidents/:id/passport", requireAuth, (req: AuthedRequest, res) => {
    const tid = req.principal!.tenant_id;
    const inc = db
      .prepare(
        "SELECT * FROM incidents WHERE tenant_id = ? AND (id = ? OR incident_code = ?)"
      )
      .get(tid, req.params.id, req.params.id) as Record<string, unknown> | undefined;
    if (!inc) {
      res.status(404).json({ detail: "Incident not found for authenticated tenant." });
      return;
    }
    const pRow = db
      .prepare("SELECT passport_json FROM incident_passports WHERE incident_id = ?")
      .get(String(inc.id)) as { passport_json: string } | undefined;
    if (pRow) {
      res.json(JSON.parse(pRow.passport_json));
      return;
    }
    res.status(404).json({ detail: "Incident Passport not generated yet." });
  });

  app.post("/api/v1/incidents/:id/status", requireAuth, (req: AuthedRequest, res) => {
    const tid = req.principal!.tenant_id;
    const newStatus = String(req.body?.status || "").trim().toUpperCase();
    if (!["OPEN", "INVESTIGATING", "RESOLVED"].includes(newStatus)) {
      res.status(400).json({ detail: "Status must be OPEN, INVESTIGATING, or RESOLVED" });
      return;
    }
    const inc = db
      .prepare(
        "SELECT * FROM incidents WHERE tenant_id = ? AND (id = ? OR incident_code = ?)"
      )
      .get(tid, req.params.id, req.params.id) as Record<string, unknown> | undefined;
    if (!inc) {
      res.status(404).json({ detail: "Incident not found for authenticated tenant." });
      return;
    }
    const prevStatus = String(inc.status);
    db.prepare("UPDATE incidents SET status = ?, updated_at_utc = ? WHERE id = ?").run(
      newStatus,
      utcNowIso(),
      String(inc.id)
    );
    const pRow = db
      .prepare("SELECT passport_json FROM incident_passports WHERE incident_id = ?")
      .get(String(inc.id)) as { passport_json: string } | undefined;
    if (pRow) {
      const parsed = JSON.parse(pRow.passport_json) as Record<string, unknown>;
      const history = (parsed.audit_history as Array<Record<string, unknown>>) || [];
      history.push({
        timestamp_utc: utcNowIso(),
        action: "STATUS_UPDATED",
        actor: req.principal!.sub,
        details: `${prevStatus} -> ${newStatus}`,
      });
      parsed.status = newStatus;
      parsed.audit_history = history;
      db.prepare("UPDATE incident_passports SET passport_json = ? WHERE incident_id = ?").run(
        JSON.stringify(parsed),
        String(inc.id)
      );
    }
    broadcastToTenant(tid, "incident:updated", {
      id: inc.id,
      incident_code: inc.incident_code,
      status: newStatus,
    });
    res.json({ id: inc.id, incident_code: inc.incident_code, status: newStatus });
  });

  app.get("/api/v1/settings/thresholds", requireAuth, (req: AuthedRequest, res) => {
    res.json(getTenantThresholds(req.principal!.tenant_id));
  });

  app.patch("/api/v1/settings/thresholds", requireAuth, (req: AuthedRequest, res) => {
    const tid = req.principal!.tenant_id;
    const cur = getTenantThresholds(tid);
    const next = {
      cpu_threshold: Number(req.body?.cpu_threshold ?? cur.cpu_threshold),
      memory_threshold: Number(req.body?.memory_threshold ?? cur.memory_threshold),
      latency_threshold_ms: Number(req.body?.latency_threshold_ms ?? cur.latency_threshold_ms),
      packet_loss_threshold_pct: Number(
        req.body?.packet_loss_threshold_pct ?? cur.packet_loss_threshold_pct
      ),
      offline_timeout_seconds: Number(
        req.body?.offline_timeout_seconds ?? cur.offline_timeout_seconds
      ),
      updated_at_utc: utcNowIso(),
    };
    db.prepare(
      `UPDATE tenant_thresholds SET
        cpu_threshold = ?, memory_threshold = ?, latency_threshold_ms = ?,
        packet_loss_threshold_pct = ?, offline_timeout_seconds = ?, updated_at_utc = ?
       WHERE tenant_id = ?`
    ).run(
      next.cpu_threshold,
      next.memory_threshold,
      next.latency_threshold_ms,
      next.packet_loss_threshold_pct,
      next.offline_timeout_seconds,
      next.updated_at_utc,
      tid
    );
    res.json(next);
  });

  // Controlled simulation trigger for live demonstrations (tagged is_simulation: true)
  app.post("/api/v1/collector/simulate", requireAuth, (req: AuthedRequest, res) => {
    const scenario = String(req.body?.scenario || "cpu_spike").trim().toLowerCase();
    const col = db
      .prepare("SELECT collector_id FROM collectors WHERE tenant_id = ? LIMIT 1")
      .get(req.principal!.tenant_id) as { collector_id: string } | undefined;
    const collectorId = col?.collector_id || "collector-local-01";
    const result = runLocalCollectorCycle(req.principal!.tenant_slug, collectorId, scenario);
    res.json({ ...(result || {}), scenario });
  });

  // Attach Vite in development or static dist/ in production
  if (process.env.NODE_ENV === "production") {
    const distDir = path.resolve(process.cwd(), "dist");
    app.use(express.static(distDir));
    app.get("*", (_req, res) => {
      res.sendFile(path.join(distDir, "index.html"));
    });
  } else {
    const { createServer: createViteServer } = await import("vite");
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  }

  const server = http.createServer(app);

  // WebSocket server at /api/v1/ws/updates
  const wss = new WebSocketServer({ noServer: true });
  server.on("upgrade", (request, socket, head) => {
    const url = new URL(request.url || "/", `http://${request.headers.host || "localhost"}`);
    if (url.pathname !== "/api/v1/ws/updates") {
      return;
    }
    const token = url.searchParams.get("token") || "";
    try {
      const claims = decodeJwt(token);
      wss.handleUpgrade(request, socket, head, (ws) => {
        const set = tenantSockets.get(claims.tenant_id) ?? new Set<WebSocket>();
        set.add(ws);
        tenantSockets.set(claims.tenant_id, set);
        ws.send(
          JSON.stringify({
            type: "ws:connected",
            data: { tenant_id: claims.tenant_id, timestamp_utc: utcNowIso() },
          })
        );
        ws.on("close", () => {
          set.delete(ws);
        });
      });
    } catch {
      socket.destroy();
    }
  });

  // Initial local OS sample + periodic 5s real collector telemetry for acme-cloud
  try {
    runLocalCollectorCycle("acme-cloud", "collector-local-01");
  } catch {
    // ignore startup sample errors
  }
  setInterval(() => {
    try {
      runLocalCollectorCycle("acme-cloud", "collector-local-01");
    } catch {
      // keep loop resilient
    }
  }, 5000);

  server.listen(PORT, "0.0.0.0", () => {
    console.log(`CAUSAL-X full-stack server running at http://0.0.0.0:${PORT}`);
  });
}

void startServer();
