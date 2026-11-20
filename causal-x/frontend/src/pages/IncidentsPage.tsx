import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Search } from "lucide-react";

import { DashboardLayout } from "../components/DashboardLayout";
import { EmptyState } from "../components/EmptyState";
import { LoadingState } from "../components/LoadingState";
import { PageHeader } from "../components/PageHeader";
import { SectionCard } from "../components/SectionCard";
import { StatusBadge } from "../components/StatusBadge";
import {
  fetchIncidents,
  getStoredSession,
  openTenantWebSocket,
  type IncidentSummary,
} from "../lib/api";

export function IncidentsPage() {
  const navigate = useNavigate();
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [wsConnected, setWsConnected] = useState(false);

  const loadIncidents = useCallback(async () => {
    try {
      const list = await fetchIncidents();
      setIncidents(list);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load incidents");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadIncidents();
    const session = getStoredSession();
    if (!session?.access_token) return;
    const ws = openTenantWebSocket(
      session.access_token,
      () => void loadIncidents(),
      setWsConnected
    );
    return () => ws.close();
  }, [loadIncidents]);

  const filtered = useMemo(() => {
    return incidents.filter((inc) => {
      const matchesSeverity =
        severityFilter === "ALL" || inc.severity.toUpperCase() === severityFilter;
      const q = query.trim().toLowerCase();
      const matchesQuery =
        !q ||
        inc.incident_code.toLowerCase().includes(q) ||
        inc.title.toLowerCase().includes(q) ||
        inc.primary_source_id.toLowerCase().includes(q) ||
        (inc.leading_hypothesis ?? "").toLowerCase().includes(q);
      return matchesSeverity && matchesQuery;
    });
  }, [incidents, query, severityFilter]);

  return (
    <DashboardLayout wsConnected={wsConnected}>
      <PageHeader
        title="Incident Centre"
        description="Correlated incidents grouped by source, component dependency, and sliding time window. Click any incident to open its Incident Passport."
      />

      {loading ? (
        <LoadingState />
      ) : error ? (
        <div className="rounded-xl border border-amber-200 bg-white p-6 text-sm text-[#475569]">
          {error}
        </div>
      ) : (
        <SectionCard
          title="Correlated Incidents"
          action={
            <div className="flex flex-wrap items-center gap-3">
              <div className="relative">
                <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-[#475569]" />
                <input
                  type="text"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Search code, title, hypothesis..."
                  className="rounded-lg border border-sky-200 bg-white py-2 pl-9 pr-3 text-xs text-[#0F172A] focus:border-[#0284C7] focus:outline-none"
                />
              </div>
              <div className="flex items-center gap-1 rounded-lg bg-[#EFF9FF] p-1">
                {["ALL", "CRITICAL", "HIGH", "MEDIUM"].map((sev) => (
                  <button
                    key={sev}
                    type="button"
                    onClick={() => setSeverityFilter(sev)}
                    className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
                      severityFilter === sev
                        ? "bg-white text-[#0F172A] shadow-sm"
                        : "text-[#475569] hover:text-[#0F172A]"
                    }`}
                  >
                    {sev}
                  </button>
                ))}
              </div>
            </div>
          }
        >
          {filtered.length === 0 ? (
            <EmptyState
              title="No Matching Incidents"
              description="No correlated incidents match the active filter criteria."
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-sky-100 text-xs text-[#475569]">
                    <th className="py-2.5 pr-4 font-semibold">Incident ID</th>
                    <th className="py-2.5 pr-4 font-semibold">Title</th>
                    <th className="py-2.5 pr-4 font-semibold">Severity</th>
                    <th className="py-2.5 pr-4 font-semibold">Detected (UTC)</th>
                    <th className="py-2.5 pr-4 font-semibold">Source</th>
                    <th className="py-2.5 pr-4 font-semibold">Leading Hypothesis</th>
                    <th className="py-2.5 font-semibold">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((inc) => (
                    <tr
                      key={inc.id}
                      onClick={() => navigate(`/incidents/${inc.id}`)}
                      className="cursor-pointer border-b border-sky-50 transition-colors hover:bg-[#EFF9FF]"
                    >
                      <td className="py-3 pr-4 font-mono text-xs font-semibold text-[#0284C7]">
                        {inc.incident_code}
                      </td>
                      <td className="py-3 pr-4 font-medium text-[#0F172A]">{inc.title}</td>
                      <td className="py-3 pr-4">
                        <StatusBadge label={inc.severity} />
                      </td>
                      <td className="py-3 pr-4 font-mono text-xs text-[#475569] tabular-nums">
                        {inc.detected_at_utc}
                      </td>
                      <td className="py-3 pr-4 font-mono text-xs text-[#475569]">
                        {inc.primary_source_id}
                      </td>
                      <td className="py-3 pr-4 text-xs text-[#0F172A]">
                        {inc.leading_hypothesis} (
                        <span className="font-mono tabular-nums">
                          {Math.round((inc.leading_confidence ?? 0) * 100)}%
                        </span>
                        )
                      </td>
                      <td className="py-3">
                        <StatusBadge label={inc.status} />
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
