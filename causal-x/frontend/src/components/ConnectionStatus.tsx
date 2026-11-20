import { AlertTriangle, CheckCircle2, RefreshCw } from "lucide-react";
import type { HealthResponse } from "../lib/api";

interface ConnectionStatusProps {
  loading: boolean;
  health: HealthResponse | null;
  error: string | null;
  apiBaseUrl: string;
  onRetry: () => void;
}

export function ConnectionStatus({
  loading,
  health,
  error,
  apiBaseUrl,
  onRetry,
}: ConnectionStatusProps) {
  if (loading) {
    return (
      <div className="rounded-xl border border-sky-200 bg-white p-5 shadow-sm">
        <p className="text-sm font-medium text-[#475569]">
          Checking backend connectivity at <span className="font-mono text-[#0F172A]">{apiBaseUrl}</span>...
        </p>
      </div>
    );
  }

  if (error || !health) {
    return (
      <div className="flex flex-col justify-between gap-4 rounded-xl border border-amber-200 bg-white p-5 shadow-sm sm:flex-row sm:items-center">
        <div className="flex items-start gap-3">
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-600" aria-hidden="true" />
          <div>
            <p className="text-sm font-semibold text-[#0F172A]">
              Backend Disconnected
            </p>
            <p className="mt-1 text-sm text-[#475569]">
              Unable to reach <span className="font-mono text-xs">{apiBaseUrl}/api/v1/health</span>.{" "}
              {error ?? "Start the FastAPI backend or Docker stack to stream live metadata."}
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={onRetry}
          className="inline-flex shrink-0 items-center gap-2 whitespace-nowrap rounded-lg border border-sky-200 bg-[#EFF9FF] px-4 py-2 text-sm font-medium text-[#0284C7] transition-colors hover:bg-[#E0F2FE] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#0284C7]"
        >
          <RefreshCw className="h-4 w-4" aria-hidden="true" />
          Retry Connection
        </button>
      </div>
    );
  }

  const isHealthy = health.status === "ok";

  return (
    <div className="flex flex-col justify-between gap-4 rounded-xl border border-sky-200 bg-white p-5 shadow-sm sm:flex-row sm:items-center">
      <div className="flex items-start gap-3">
        <CheckCircle2
          className={`mt-0.5 h-5 w-5 shrink-0 ${isHealthy ? "text-emerald-600" : "text-amber-600"}`}
          aria-hidden="true"
        />
        <div>
          <p className="text-sm font-semibold text-[#0F172A]">
            {isHealthy ? "Backend Connected" : "Backend Degraded"} · {health.service} {health.version}
          </p>
          <p className="mt-1 text-xs text-[#475569] tabular-nums">
            Database: {health.database} · Region: {health.region} · UTC: {health.timestamp_utc}
          </p>
        </div>
      </div>
      <button
        type="button"
        onClick={onRetry}
        className="inline-flex shrink-0 items-center gap-2 whitespace-nowrap rounded-lg border border-sky-200 bg-[#EFF9FF] px-4 py-2 text-sm font-medium text-[#0284C7] transition-colors hover:bg-[#E0F2FE] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#0284C7]"
      >
        <RefreshCw className="h-4 w-4" aria-hidden="true" />
        Refresh
      </button>
    </div>
  );
}
