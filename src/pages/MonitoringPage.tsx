import { useCallback, useEffect, useState } from "react";
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { DashboardLayout } from "../components/DashboardLayout";
import { EmptyState } from "../components/EmptyState";
import { LoadingState } from "../components/LoadingState";
import { PageHeader } from "../components/PageHeader";
import { SectionCard } from "../components/SectionCard";
import { StatusBadge } from "../components/StatusBadge";
import {
  fetchAnomalies,
  fetchTelemetry,
  getStoredSession,
  openTenantWebSocket,
  triggerControlledSimulation,
  type AnomalyRecord,
  type TelemetryPoint,
} from "../services/api";

export function MonitoringPage() {
  const [telemetry, setTelemetry] = useState<TelemetryPoint[]>([]);
  const [anomalies, setAnomalies] = useState<AnomalyRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [wsConnected, setWsConnected] = useState(false);
  const [simRunning, setSimRunning] = useState<string | null>(null);
  const [simNotice, setSimNotice] = useState<string | null>(null);

  const loadMonitoring = useCallback(async () => {
    try {
      const [tel, anom] = await Promise.all([fetchTelemetry(80), fetchAnomalies(50)]);
      setTelemetry(tel);
      setAnomalies(anom);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load telemetry");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadMonitoring();
    const session = getStoredSession();
    if (!session?.access_token) return;
    const ws = openTenantWebSocket(
      session.access_token,
      () => void loadMonitoring(),
      setWsConnected
    );
    return () => ws.close();
  }, [loadMonitoring]);

  const handleSimulate = async (
    scenario: "cpu_spike" | "memory_leak" | "network_drop" | "db_lock"
  ) => {
    setSimRunning(scenario);
    setSimNotice(null);
    try {
      const res = await triggerControlledSimulation(scenario);
      setSimNotice(
        `Controlled simulation '${scenario}' ingested (${res.anomalies_detected} anomaly(ies)${
          res.incident_code ? `, correlated to ${res.incident_code}` : ""
        }).`
      );
      await loadMonitoring();
    } catch (err) {
      setSimNotice(err instanceof Error ? err.message : "Simulation failed");
    } finally {
      setSimRunning(null);
    }
  };

  return (
    <DashboardLayout wsConnected={wsConnected}>
      <PageHeader
        title="Live Infrastructure Monitoring"
        description="Event-time ordered CPU, memory, latency, and packet-loss streams with multi-layer anomaly annotations."
      />

      {loading ? (
        <LoadingState />
      ) : error ? (
        <div className="rounded-xl border border-amber-200 bg-white p-6 text-sm text-[#475569]">
          {error}
        </div>
      ) : (
        <div className="space-y-6">
          <SectionCard
            title="Controlled Fault Simulation (Testing & Live Demo)"
            subtitle="Explicitly labelled simulation events processed locally through the Privacy Shield before ingestion"
            action={
              <div className="flex flex-wrap gap-2">
                {(
                  [
                    { id: "cpu_spike", label: "Simulate CPU Spike" },
                    { id: "db_lock", label: "Simulate DB Lock" },
                    { id: "network_drop", label: "Simulate Network Drop" },
                    { id: "memory_leak", label: "Simulate Memory Leak" },
                  ] as const
                ).map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    disabled={simRunning !== null}
                    onClick={() => void handleSimulate(item.id)}
                    className="rounded-lg border border-sky-200 bg-[#EFF9FF] px-3 py-1.5 text-xs font-semibold text-[#0284C7] hover:bg-[#E0F2FE] disabled:opacity-60"
                  >
                    {simRunning === item.id ? "Injecting..." : item.label}
                  </button>
                ))}
              </div>
            }
          >
            <p className="text-xs text-[#475569]">
              {simNotice ??
                "Host telemetry is sampled continuously in the background. Use these controlled simulation triggers to demonstrate threshold breaches, correlation, and Incident Passport generation."}
            </p>
          </SectionCard>

          <SectionCard
            title="Resource & Network Telemetry Stream"
            subtitle="All timestamps normalized to UTC; out-of-order deliveries sorted by event time"
          >
            {telemetry.length === 0 ? (
              <EmptyState
                title="No Telemetry Samples"
                description="Run the collector or trigger a simulation event to observe real-time charts."
              />
            ) : (
              <div className="h-72 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={telemetry}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#E0F2FE" />
                    <XAxis
                      dataKey="event_timestamp_utc"
                      tickFormatter={(v: string) => v.slice(11, 19)}
                      tick={{ fontSize: 11, fill: "#475569" }}
                    />
                    <YAxis tick={{ fontSize: 11, fill: "#475569" }} />
                    <Tooltip />
                    <Line type="monotone" dataKey="cpu_usage" name="CPU %" stroke="#0284C7" dot={false} strokeWidth={2} />
                    <Line type="monotone" dataKey="memory_usage" name="Memory %" stroke="#38BDF8" dot={false} strokeWidth={2} />
                    <Line type="monotone" dataKey="network_latency_ms" name="Latency (ms)" stroke="#0369A1" dot={false} strokeWidth={2} />
                    <Line type="monotone" dataKey="packet_loss_pct" name="Packet Loss %" stroke="#F59E0B" dot={false} strokeWidth={2} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            )}
          </SectionCard>

          <SectionCard
            title="Detected Anomalies (Rule · Baseline · ML · Combined)"
            subtitle="Every anomaly cites contributing signals and detection methodology"
          >
            {anomalies.length === 0 ? (
              <EmptyState
                title="No Anomalies Detected"
                description="Current telemetry remains within configured thresholds and IsolationForest baseline bounds."
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead>
                    <tr className="border-b border-sky-100 text-xs text-[#475569]">
                      <th className="py-2.5 pr-4 font-semibold">UTC Time</th>
                      <th className="py-2.5 pr-4 font-semibold">Component</th>
                      <th className="py-2.5 pr-4 font-semibold">Metric</th>
                      <th className="py-2.5 pr-4 font-semibold">Value</th>
                      <th className="py-2.5 pr-4 font-semibold">Method</th>
                      <th className="py-2.5 pr-4 font-semibold">Severity</th>
                      <th className="py-2.5 font-semibold">Explanation</th>
                    </tr>
                  </thead>
                  <tbody>
                    {anomalies.map((a) => (
                      <tr key={a.id} className="border-b border-sky-50">
                        <td className="py-3 pr-4 font-mono text-xs text-[#475569] tabular-nums">
                          {a.detected_at_utc}
                        </td>
                        <td className="py-3 pr-4 text-xs font-medium text-[#0F172A]">
                          {a.component}
                        </td>
                        <td className="py-3 pr-4 font-mono text-xs text-[#0F172A]">
                          {a.metric_name}
                        </td>
                        <td className="py-3 pr-4 font-mono text-xs text-[#0F172A] tabular-nums">
                          {a.metric_value}
                        </td>
                        <td className="py-3 pr-4 font-mono text-xs uppercase text-[#0284C7]">
                          {a.detection_method}
                        </td>
                        <td className="py-3 pr-4">
                          <StatusBadge label={a.severity} />
                        </td>
                        <td className="py-3 text-xs text-[#475569]">{a.description}</td>
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
