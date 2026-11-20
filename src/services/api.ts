import axios, { AxiosError, type InternalAxiosRequestConfig } from "axios";

export interface AuthSession {
  access_token: string;
  token_type: string;
  principal_type: string;
  tenant_id: string;
  tenant_slug: string;
  tenant_name: string;
  region: string;
  role: string;
  subject: string;
}

export interface PasswordlessRequestResult {
  status: string;
  email: string;
  tenant_slug: string;
  expires_in_seconds: number;
  dev_verification_code?: string | null;
}

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  environment: string;
  region: string;
  database: string;
  timestamp_utc: string;
}

export interface TelemetryPoint {
  id?: string;
  payload_id?: string;
  collector_id?: string;
  event_timestamp_utc: string;
  ingested_at_utc?: string;
  source_timezone?: string;
  source_id: string;
  component: string;
  event_category?: string;
  cpu_usage: number;
  memory_usage: number;
  disk_usage?: number;
  network_latency_ms: number;
  packet_loss_pct: number;
  service_status?: string;
  failed_login_count?: number;
  severity: string;
  is_simulation?: boolean;
}

export interface IncidentSummary {
  id: string;
  incident_code: string;
  title: string;
  status: string;
  severity: string;
  primary_source_id: string;
  affected_components?: string[];
  evidence_count?: number;
  correlation_score?: number;
  leading_hypothesis?: string;
  leading_confidence?: number;
  detected_at_utc: string;
  updated_at_utc?: string;
}

export interface DashboardOverview {
  tenant: {
    id: string;
    slug: string;
    name: string;
    region: string;
    residency_policy: string;
  };
  health_state: "Excellent" | "Good" | "Fair" | "Poor";
  health_reason: string;
  kpis: {
    active_sources: number;
    online_collectors: number;
    total_collectors: number;
    active_incidents: number;
    critical_alerts: number;
    blocked_fields_count: number;
    verified_payloads_count: number;
    privacy_risk_score: number;
    last_sync_utc: string | null;
  };
  telemetry_series: TelemetryPoint[];
  recent_incidents: IncidentSummary[];
}

export interface AnomalyRecord {
  id: string;
  collector_id: string;
  telemetry_id: string;
  source_id: string;
  component: string;
  metric_name: string;
  metric_value: number;
  baseline_mean: number | null;
  baseline_std: number | null;
  detection_method: string;
  severity: string;
  description: string;
  contributing_signals: Record<string, number>;
  detected_at_utc: string;
}

export interface EgressProofRecord {
  id: string;
  payload_id: string;
  tenant_id: string;
  collector_id: string;
  source_id: string;
  event_timestamp_utc: string;
  approved_metadata: Record<string, unknown>;
  allowed_fields: string[];
  blocked_fields: string[];
  policy_version: string;
  privacy_risk_score: number;
  payload_hash_sha256: string;
  hmac_signature: string;
  verification_status: string;
  approval_decision: string;
  delivery_status: string;
  created_at_utc: string;
}

export interface EgressVerifyResult {
  payload_id: string | null;
  hash_valid: boolean;
  hmac_valid: boolean | null;
  computed_sha256: string;
  verification_status: string;
  checked_at_utc: string;
}

export interface CollectorRecord {
  id: string;
  collector_id: string;
  display_name: string;
  status: string;
  version: string;
  region: string;
  source_timezone: string;
  last_seen_utc: string | null;
  last_cpu_pct: number;
  last_mem_mb: number;
  config: Record<string, unknown>;
}

export interface IncidentPassportData {
  incident_id: string;
  incident_code: string;
  title: string;
  severity: string;
  status: string;
  detection_time_utc: string;
  source: string;
  affected_components: string[];
  evidence_ids: string[];
  timeline: Array<{
    event_timestamp_utc: string;
    event_type: string;
    description: string;
    severity: string;
    component: string;
    evidence_ref: string;
  }>;
  hypotheses: Array<{
    rank: number;
    hypothesis_type: string;
    title: string;
    explanation: string;
    confidence_score: number;
    confidence_method: string;
    uncertainty_note: string;
    supporting_evidence: string[];
  }>;
  confidence: number;
  confidence_method: string;
  uncertainty: string;
  estimated_impact: {
    estimated_affected_components: string[];
    dependency_paths: string[];
    impact_disclaimer: string;
  };
  recommendations: Array<{
    priority: number;
    action_title: string;
    rationale: string;
    safety_note: string;
    requires_approval: boolean;
  }>;
  audit_history: Array<{
    timestamp_utc: string;
    action: string;
    actor?: string;
    details: string;
  }>;
}

export interface ThresholdSettings {
  cpu_threshold: number;
  memory_threshold: number;
  latency_threshold_ms: number;
  packet_loss_threshold_pct: number;
  offline_timeout_seconds: number;
  updated_at_utc?: string;
}

export interface SimulationTriggerResult {
  status: string;
  scenario: string;
  payload_id: string;
  blocked_fields: string[];
  anomalies_detected: number;
  incident_code: string | null;
}

const SESSION_KEY = "causalx_auth_session";

const ENV_API_BASE = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.trim();
const API_BASE = ENV_API_BASE ? ENV_API_BASE.replace(/\/$/, "") : "";

const ENV_WS_BASE = (import.meta.env.VITE_WS_BASE_URL as string | undefined)?.trim();

function resolveWsBase(): string {
  if (ENV_WS_BASE) {
    return ENV_WS_BASE.replace(/\/$/, "");
  }
  if (API_BASE.startsWith("http")) {
    return API_BASE.replace(/^http/, "ws");
  }
  if (typeof window !== "undefined") {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    return `${protocol}//${window.location.host}`;
  }
  return "ws://localhost:3000";
}

export function getApiBaseUrl(): string {
  if (API_BASE) return API_BASE;
  if (typeof window !== "undefined") return window.location.origin;
  return "http://localhost:3000";
}

export function getStoredSession(): AuthSession | null {
  try {
    const raw = localStorage.getItem(SESSION_KEY);
    return raw ? (JSON.parse(raw) as AuthSession) : null;
  } catch {
    return null;
  }
}

export function saveStoredSession(session: AuthSession): void {
  localStorage.setItem(SESSION_KEY, JSON.stringify(session));
}

export function clearStoredSession(): void {
  localStorage.removeItem(SESSION_KEY);
}

interface AuthRequestConfig extends InternalAxiosRequestConfig {
  skipAuth?: boolean;
}

export const apiClient = axios.create({
  baseURL: API_BASE || undefined,
  timeout: 15000,
  headers: {
    Accept: "application/json",
    "Content-Type": "application/json",
  },
});

apiClient.interceptors.request.use(
  (config: AuthRequestConfig) => {
    if (!config.skipAuth) {
      const session = getStoredSession();
      if (!session?.access_token) {
        return Promise.reject(new Error("AUTH_REQUIRED"));
      }
      config.headers = config.headers ?? {};
      config.headers.Authorization = `Bearer ${session.access_token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

apiClient.interceptors.response.use(
  (response) => response,
  (error: AxiosError<{ detail?: string; message?: string }>) => {
    const reqConfig = error.config as AuthRequestConfig | undefined;
    const status = error.response?.status;
    const serverDetail = error.response?.data?.detail || error.response?.data?.message;

    if (status === 401 && !reqConfig?.skipAuth) {
      clearStoredSession();
      return Promise.reject(new Error("AUTH_REQUIRED"));
    }

    if (serverDetail) {
      return Promise.reject(new Error(serverDetail));
    }

    if (error.message === "AUTH_REQUIRED") {
      return Promise.reject(error);
    }

    return Promise.reject(new Error(error.message || "Request failed"));
  }
);

export async function fetchBackendHealth(): Promise<HealthResponse> {
  const { data } = await apiClient.get<HealthResponse>("/api/v1/health", {
    skipAuth: true,
  } as AuthRequestConfig);
  return data;
}

export async function loginUser(email: string, password: string): Promise<AuthSession> {
  const { data } = await apiClient.post<AuthSession>(
    "/api/v1/auth/login",
    { email, password },
    { skipAuth: true } as AuthRequestConfig
  );
  saveStoredSession(data);
  return data;
}

export async function registerOperator(
  email: string,
  password: string,
  tenantSlug: string,
  fullName?: string
): Promise<AuthSession> {
  const { data } = await apiClient.post<AuthSession>(
    "/api/v1/auth/register",
    {
      email,
      password,
      tenant_slug: tenantSlug,
      full_name: fullName || undefined,
    },
    { skipAuth: true } as AuthRequestConfig
  );
  saveStoredSession(data);
  return data;
}

export async function requestPasswordlessCode(
  email: string,
  tenantSlug: string
): Promise<PasswordlessRequestResult> {
  const { data } = await apiClient.post<PasswordlessRequestResult>(
    "/api/v1/auth/passwordless/request",
    { email, tenant_slug: tenantSlug },
    { skipAuth: true } as AuthRequestConfig
  );
  return data;
}

export async function verifyPasswordlessCode(
  email: string,
  tenantSlug: string,
  code: string
): Promise<AuthSession> {
  const { data } = await apiClient.post<AuthSession>(
    "/api/v1/auth/passwordless/verify",
    { email, tenant_slug: tenantSlug, code, instant: false },
    { skipAuth: true } as AuthRequestConfig
  );
  saveStoredSession(data);
  return data;
}

export async function loginPasswordlessInstant(
  email: string,
  tenantSlug: string
): Promise<AuthSession> {
  const { data } = await apiClient.post<AuthSession>(
    "/api/v1/auth/passwordless/verify",
    { email, tenant_slug: tenantSlug, instant: true },
    { skipAuth: true } as AuthRequestConfig
  );
  saveStoredSession(data);
  return data;
}

export async function fetchDashboardOverview(): Promise<DashboardOverview> {
  const { data } = await apiClient.get<DashboardOverview>("/api/v1/dashboard/overview");
  return data;
}

export async function fetchTelemetry(limit = 100): Promise<TelemetryPoint[]> {
  const { data } = await apiClient.get<TelemetryPoint[]>("/api/v1/telemetry", {
    params: { limit },
  });
  return data;
}

export async function fetchCollectors(): Promise<CollectorRecord[]> {
  const { data } = await apiClient.get<CollectorRecord[]>("/api/v1/collectors");
  return data;
}

export async function fetchEgressAudit(limit = 50): Promise<EgressProofRecord[]> {
  const { data } = await apiClient.get<EgressProofRecord[]>("/api/v1/egress/audit", {
    params: { limit },
  });
  return data;
}

export async function verifyEgressPayload(proof: EgressProofRecord): Promise<EgressVerifyResult> {
  const { data } = await apiClient.post<EgressVerifyResult>("/api/v1/egress/verify", {
    payload_id: proof.payload_id,
    approved_metadata: proof.approved_metadata,
    payload_hash_sha256: proof.payload_hash_sha256,
    hmac_signature: proof.hmac_signature,
  });
  return data;
}

export async function fetchAnomalies(limit = 100): Promise<AnomalyRecord[]> {
  const { data } = await apiClient.get<AnomalyRecord[]>("/api/v1/anomalies", {
    params: { limit },
  });
  return data;
}

export async function fetchIncidents(): Promise<IncidentSummary[]> {
  const { data } = await apiClient.get<IncidentSummary[]>("/api/v1/incidents");
  return data;
}

export async function fetchIncidentPassport(id: string): Promise<IncidentPassportData> {
  const { data } = await apiClient.get<IncidentPassportData>(
    `/api/v1/incidents/${encodeURIComponent(id)}/passport`
  );
  return data;
}

export async function updateIncidentStatus(
  id: string,
  status: "OPEN" | "INVESTIGATING" | "RESOLVED",
  note?: string
): Promise<{ id: string; incident_code: string; status: string }> {
  const { data } = await apiClient.post<{ id: string; incident_code: string; status: string }>(
    `/api/v1/incidents/${encodeURIComponent(id)}/status`,
    { status, note }
  );
  return data;
}

export async function fetchThresholds(): Promise<ThresholdSettings> {
  const { data } = await apiClient.get<ThresholdSettings>("/api/v1/settings/thresholds");
  return data;
}

export async function updateThresholds(payload: ThresholdSettings): Promise<ThresholdSettings> {
  const { data } = await apiClient.patch<ThresholdSettings>(
    "/api/v1/settings/thresholds",
    payload
  );
  return data;
}

export async function triggerControlledSimulation(
  scenario: "cpu_spike" | "memory_leak" | "network_drop" | "db_lock" | "secret_leak_test"
): Promise<SimulationTriggerResult> {
  const { data } = await apiClient.post<SimulationTriggerResult>("/api/v1/collector/simulate", {
    scenario,
  });
  return data;
}

export function openTenantWebSocket(
  token: string,
  onEvent: (event: { type: string; data: Record<string, unknown> }) => void,
  onStatusChange: (connected: boolean) => void
): WebSocket {
  const ws = new WebSocket(
    `${resolveWsBase()}/api/v1/ws/updates?token=${encodeURIComponent(token)}`
  );
  ws.onopen = () => onStatusChange(true);
  ws.onclose = () => onStatusChange(false);
  ws.onerror = () => onStatusChange(false);
  ws.onmessage = (msg) => {
    try {
      const parsed = JSON.parse(msg.data) as { type: string; data: Record<string, unknown> };
      onEvent(parsed);
    } catch {
      // ignore malformed messages
    }
  };
  return ws;
}
