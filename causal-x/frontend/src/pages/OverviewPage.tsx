import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { DashboardLayout } from "../components/DashboardLayout";
import { EmptyState } from "../components/EmptyState";
import { LoadingState } from "../components/LoadingState";
import { MetricCard } from "../components/MetricCard";
import { PageHeader } from "../components/PageHeader";
import { SectionCard } from "../components/SectionCard";
import { StatusBadge } from "../components/StatusBadge";
import {
  fetchDashboardOverview,
  getStoredSession,
  openTenantWebSocket,
  type DashboardOverview,
} from "../lib/api";

export function OverviewPage() {
  const [data, setData] = useState<DashboardOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [wsConnected, setWsConnected] = useState(false);

  const loadData = useCallback(async () => {
    try {
      const res = await fetchDashboardOverview();
      setData(res);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load overview");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadData();
    const session = getStoredSession();
    if (!session?.access_token) return;

    const ws = openTenantWebSocket(
      session.access_token,
      () => {
        void loadData();
      },
      setWsConnected
    );
    return () => ws.close();
  }, [loadData]);

  return (
    <DashboardLayout wsConnected={wsConnected}>
      <PageHeader
        title="Platform Overview"
        description="Consolidated multi-tenant metadata health, real-time collector telemetry, and active incidents."
        actions={data ? <StatusBadge label={data.health_state} /> : undefined}
      />

      {loading ? (
        <LoadingState />
      ) : error ? (
        <div className="rounded-xl border border-amber-200 bg-white p-6 shadow-sm">
          <p className="text-sm font-semibold text-[#0F172A]">Backend Unavailable</p>
          <p className="mt-1 text-sm text-[#475569]">{error}</p>
          <button
            type="button"
            onClick={() => void loadData()}
            className="mt-4 rounded-lg bg-[#0284C7] px-4 py-2 text-xs font-semibold text-white hover:bg-[#0369A1]"
          >
            Retry
          </button>
        </div>
      ) : !data ? null : (
        <div className="space-y-6">
          <div className="rounded-xl border border-sky-100 bg-white p-4 shadow-sm">
            <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
              <span className="font-medium text-[#0F172A]">{data.health_reason}</span>
              <span className="text-xs text-[#475569] tabular-nums">
                Region: {data.tenant.region} · Last sync: {data.kpis.last_sync_utc ?? "Pending"}
              </span>
            </div>
          </div>

          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <MetricCard
              label="Active Sources"
              value={data.kpis.active_sources}
              detail={`${data.kpis.online_collectors}/${data.kpis.total_collectors} collectors online`}
            />
            <MetricCard
              label="Active Incidents"
              value={data.kpis.active_incidents}
              detail={`${data.kpis.critical_alerts} critical/high alerts`}
            />
            <MetricCard
              label="Blocked Restricted Fields"
              value={data.kpis.blocked_fields_count}
              detail={`Max egress risk: ${data.kpis.privacy_risk_score}`}
            />
            <MetricCard
              label="Verified Payloads"
              value={data.kpis.verified_payloads_count}
              detail="SHA-256 & HMAC verified"
            />
          </div>

          <div className="grid gap-6 lg:grid-cols-2">
            <SectionCard
              title="CPU & Memory Utilization (%)"
              subtitle="Ordered by UTC event timestamp"
            >
              {data.telemetry_series.length === 0 ? (
                <EmptyState
                  title="No Telemetry Received Yet"
                  description="Start the Tier 1 local collector or inject a controlled scenario to populate charts."
                />
              ) : (
                <div className="h-64 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={data.telemetry_series}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#E0F2FE" />
                      <XAxis
                        dataKey="event_timestamp_utc"
                        tickFormatter={(v: string) => v.slice(11, 19)}
                        tick={{ fontSize: 11, fill: "#475569" }}
                      />
                      <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: "#475569" }} />
                      <Tooltip />
                      <Area
                        type="monotone"
                        dataKey="cpu_usage"
                        name="CPU %"
                        stroke="#0284C7"
                        fill="#38BDF8"
                        fillOpacity={0.22}
                      />
                      <Area
                        type="monotone"
                        dataKey="memory_usage"
                        name="Memory %"
                        stroke="#0EA5E9"
                        fill="#E0F2FE"
                        fillOpacity={0.45}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              )}
            </SectionCard>

            <SectionCard
              title="Network Latency (ms)"
              subtitle="Approved metadata stream"
            >
              {data.telemetry_series.length === 0 ? (
                <EmptyState
                  title="Waiting for Latency Metadata"
                  description="Latency measurements appear once the collector transmits approved payloads."
                />
              ) : (
                <div className="h-64 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={data.telemetry_series}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#E0F2FE" />
                      <XAxis
                        dataKey="event_timestamp_utc"
                        tickFormatter={(v: string) => v.slice(11, 19)}
                        tick={{ fontSize: 11, fill: "#475569" }}
                      />
                      <YAxis tick={{ fontSize: 11, fill: "#475569" }} />
                      <Tooltip />
                      <Area
                        type="monotone"
                        dataKey="network_latency_ms"
                        name="Latency (ms)"
                        stroke="#0284C7"
                        fill="#38BDF8"
                        fillOpacity={0.2}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              )}
            </SectionCard>
          </div>

          <SectionCard
            title="Recent Correlated Incidents"
            action={
              <Link to="/incidents" className="text-xs font-semibold text-[#0284C7] hover:underline">
                View all incidents
              </Link>
            }
          >
            {data.recent_incidents.length === 0 ? (
              <EmptyState
                title="No Correlated Incidents"
                description="No anomalous conditions have breached thresholds or IsolationForest baselines."
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead>
                    <tr className="border-b border-sky-100 text-xs text-[#475569]">
                      <th className="py-2.5 pr-4 font-semibold">Incident</th>
                      <th className="py-2.5 pr-4 font-semibold">Title</th>
                      <th className="py-2.5 pr-4 font-semibold">Severity</th>
                      <th className="py-2.5 pr-4 font-semibold">Status</th>
                      <th className="py-2.5 font-semibold">Detected (UTC)</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.recent_incidents.map((inc) => (
                      <tr key={inc.id} className="border-b border-sky-50 hover:bg-[#EFF9FF]/60">
                        <td className="py-3 pr-4 font-mono text-xs font-semibold text-[#0284C7]">
                          <Link to={`/incidents/${inc.id}`} className="hover:underline">
                            {inc.incident_code}
                          </Link>
                        </td>
                        <td className="py-3 pr-4 font-medium text-[#0F172A]">{inc.title}</td>
                        <td className="py-3 pr-4">
                          <StatusBadge label={inc.severity} />
                        </td>
                        <td className="py-3 pr-4">
                          <StatusBadge label={inc.status} />
                        </td>
                        <td className="py-3 font-mono text-xs text-[#475569] tabular-nums">
                          {inc.detected_at_utc}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </SectionCard>
        </div>
      )}
    </DashboardLayout>
  );
}
