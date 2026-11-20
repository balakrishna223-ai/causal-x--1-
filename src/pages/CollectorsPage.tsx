import { useCallback, useEffect, useState } from "react";

import { DashboardLayout } from "../components/DashboardLayout";
import { EmptyState } from "../components/EmptyState";
import { LoadingState } from "../components/LoadingState";
import { PageHeader } from "../components/PageHeader";
import { SectionCard } from "../components/SectionCard";
import { StatusBadge } from "../components/StatusBadge";
import {
  fetchCollectors,
  getStoredSession,
  openTenantWebSocket,
  type CollectorRecord,
} from "../lib/api";

export function CollectorsPage() {
  const [collectors, setCollectors] = useState<CollectorRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [wsConnected, setWsConnected] = useState(false);

  const loadCollectors = useCallback(async () => {
    try {
      const list = await fetchCollectors();
      setCollectors(list);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load collectors");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadCollectors();
    const session = getStoredSession();
    if (!session?.access_token) return;
    const ws = openTenantWebSocket(
      session.access_token,
      () => void loadCollectors(),
      setWsConnected
    );
    return () => ws.close();
  }, [loadCollectors]);

  return (
    <DashboardLayout wsConnected={wsConnected}>
      <PageHeader
        title="Collector Fleet"
        description="Tier 1 collector heartbeat status, last-seen UTC timestamps, resource footprint, and offline timeout monitoring."
      />

      {loading ? (
        <LoadingState />
      ) : error ? (
        <div className="rounded-xl border border-amber-200 bg-white p-6 text-sm text-[#475569]">
          {error}
        </div>
      ) : (
        <SectionCard title="Registered Tenant Collectors">
          {collectors.length === 0 ? (
            <EmptyState
              title="No Collectors Registered"
              description="No local collectors are registered for this tenant."
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-sky-100 text-xs text-[#475569]">
                    <th className="py-2.5 pr-4 font-semibold">Collector ID</th>
                    <th className="py-2.5 pr-4 font-semibold">Status</th>
                    <th className="py-2.5 pr-4 font-semibold">Region / TZ</th>
                    <th className="py-2.5 pr-4 font-semibold">Version</th>
                    <th className="py-2.5 pr-4 font-semibold">Process Usage</th>
                    <th className="py-2.5 font-semibold">Last Seen (UTC)</th>
                  </tr>
                </thead>
                <tbody>
                  {collectors.map((col) => (
                    <tr key={col.id} className="border-b border-sky-50">
                      <td className="py-3 pr-4">
                        <p className="font-mono text-xs font-semibold text-[#0284C7]">
                          {col.collector_id}
                        </p>
                        <p className="text-xs text-[#475569]">{col.display_name}</p>
                      </td>
                      <td className="py-3 pr-4">
                        <StatusBadge label={col.status} />
                      </td>
                      <td className="py-3 pr-4 text-xs text-[#475569]">
                        {col.region} · {col.source_timezone}
                      </td>
                      <td className="py-3 pr-4 font-mono text-xs text-[#0F172A]">
                        {col.version}
                      </td>
                      <td className="py-3 pr-4 font-mono text-xs text-[#0F172A] tabular-nums">
                        {col.last_cpu_pct.toFixed(1)}% CPU · {col.last_mem_mb.toFixed(1)} MB
                      </td>
                      <td className="py-3 font-mono text-xs text-[#475569] tabular-nums">
                        {col.last_seen_utc ?? "Never"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </SectionCard>
      )}
    </DashboardLayout>
  );
}
