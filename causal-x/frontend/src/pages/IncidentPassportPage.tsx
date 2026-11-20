import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft } from "lucide-react";

import { DashboardLayout } from "../components/DashboardLayout";
import { IncidentTimeline } from "../components/IncidentTimeline";
import { LoadingState } from "../components/LoadingState";
import { MetricCard } from "../components/MetricCard";
import { PageHeader } from "../components/PageHeader";
import { SectionCard } from "../components/SectionCard";
import { StatusBadge } from "../components/StatusBadge";
import {
  fetchIncidentPassport,
  updateIncidentStatus,
  type IncidentPassportData,
} from "../lib/api";

export function IncidentPassportPage() {
  const { id } = useParams<{ id: string }>();
  const [passport, setPassport] = useState<IncidentPassportData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [updatingStatus, setUpdatingStatus] = useState(false);

  const loadPassport = useCallback(async () => {
    if (!id) return;
    setLoading(true);
    try {
      const data = await fetchIncidentPassport(id);
      setPassport(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load Incident Passport");
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    void loadPassport();
  }, [loadPassport]);

  const handleStatusChange = async (newStatus: "OPEN" | "INVESTIGATING" | "RESOLVED") => {
    if (!id) return;
    setUpdatingStatus(true);
    try {
      await updateIncidentStatus(id, newStatus);
      await loadPassport();
    } finally {
      setUpdatingStatus(false);
    }
  };

  return (
    <DashboardLayout>
      <div className="mb-4">
        <Link
          to="/incidents"
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-[#0284C7] hover:underline"
        >
          <ArrowLeft className="h-3.5 w-3.5" aria-hidden="true" />
          Back to Incident Centre
        </Link>
      </div>

      {loading ? (
        <LoadingState rows={6} />
      ) : error || !passport ? (
        <div className="rounded-xl border border-amber-200 bg-white p-6 text-sm text-[#475569]">
          {error ?? "Incident Passport unavailable."}
        </div>
      ) : (
        <div className="space-y-6">
          <PageHeader
            title={`${passport.incident_code} · ${passport.title}`}
            description={`Incident Passport · Detected ${passport.detection_time_utc} · Source: ${passport.source}`}
            actions={
              <div className="flex flex-wrap items-center gap-2">
                <StatusBadge label={passport.severity} />
                <StatusBadge label={passport.status} />
                {(["INVESTIGATING", "RESOLVED"] as const).map((target) => (
                  <button
                    key={target}
                    type="button"
                    disabled={updatingStatus || passport.status === target}
                    onClick={() => void handleStatusChange(target)}
                    className="rounded-lg border border-sky-200 bg-white px-3 py-1.5 text-xs font-semibold text-[#0F172A] hover:bg-[#EFF9FF] disabled:opacity-50"
                  >
                    Mark {target}
                  </button>
                ))}
              </div>
            }
          />

          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <MetricCard
              label="Top Hypothesis Confidence"
              value={`${Math.round(passport.confidence * 100)}%`}
              detail="Probabilistic (not confirmed)"
            />
            <MetricCard
              label="Correlated Evidence IDs"
              value={passport.evidence_ids.length}
              detail="Metadata & anomaly references"
            />
            <MetricCard
              label="Affected Components"
              value={passport.affected_components.length}
              detail={passport.affected_components.join(", ")}
            />
            <MetricCard
              label="Estimated Impact Scope"
              value={passport.estimated_impact.estimated_affected_components.length}
              detail="Via dependency graph"
            />
          </div>

          <SectionCard
            title="Ranked Root-Cause Hypotheses"
            subtitle="Deterministic evidence-backed ranking. Root causes are never marked confirmed automatically."
          >
            <div className="space-y-4">
              {passport.hypotheses.map((h) => (
                <article
                  key={h.rank}
                  className="rounded-lg border border-sky-100 bg-[#EFF9FF]/50 p-5"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h3 className="font-display text-base font-semibold text-[#0F172A]">
                      Rank #{h.rank}: {h.title}
                    </h3>
                    <span className="font-mono text-xs font-semibold text-[#0284C7] tabular-nums">
                      Confidence: {Math.round(h.confidence_score * 100)}%
                    </span>
                  </div>
                  <p className="mt-2 text-sm leading-relaxed text-[#0F172A]">{h.explanation}</p>
                  <div className="mt-3 space-y-1 text-xs text-[#475569]">
                    <p>
                      <strong className="text-[#0F172A]">Method:</strong> {h.confidence_method}
                    </p>
                    <p>
                      <strong className="text-[#0F172A]">Uncertainty:</strong> {h.uncertainty_note}
                    </p>
                    <p className="font-mono">
                      Supporting evidence: {h.supporting_evidence.join(", ") || "None"}
                    </p>
                  </div>
                </article>
              ))}
            </div>
          </SectionCard>

          <div className="grid gap-6 lg:grid-cols-2">
            <SectionCard
              title="Chronological Incident Timeline"
              subtitle="Ordered strictly by UTC event timestamp"
            >
              <IncidentTimeline events={passport.timeline} />
            </SectionCard>

            <div className="space-y-6">
              <SectionCard
                title="Estimated Downstream Impact"
                subtitle={passport.estimated_impact.impact_disclaimer}
              >
                <p className="text-xs font-semibold text-[#0F172A]">
                  Potentially Affected Components
                </p>
                <p className="mt-1 font-mono text-xs text-[#0284C7]">
                  {passport.estimated_impact.estimated_affected_components.join(", ")}
                </p>
                {passport.estimated_impact.dependency_paths.length > 0 && (
                  <>
                    <p className="mt-4 text-xs font-semibold text-[#0F172A]">Dependency Paths</p>
                    <ul className="mt-1 space-y-1 font-mono text-xs text-[#475569]">
                      {passport.estimated_impact.dependency_paths.map((p) => (
                        <li key={p}>{p}</li>
                      ))}
                    </ul>
                  </>
                )}
              </SectionCard>

              <SectionCard
                title="Recommended Next Steps"
                subtitle="Human-approved investigation guidance"
              >
                <ul className="space-y-3">
                  {passport.recommendations.map((rec) => (
                    <li key={rec.priority} className="border-b border-sky-50 pb-3 last:border-b-0 last:pb-0">
                      <p className="text-sm font-semibold text-[#0F172A]">
                        {rec.priority}. {rec.action_title}
                      </p>
                      <p className="mt-1 text-xs text-[#475569]">{rec.rationale}</p>
                      <p className="mt-1 text-xs font-medium text-[#0284C7]">
                        Safeguard: {rec.safety_note}
                      </p>
                    </li>
                  ))}
                </ul>
              </SectionCard>
            </div>
          </div>

          <SectionCard title="Passport Evidence & Audit History">
            <div className="grid gap-6 md:grid-cols-2">
              <div>
                <p className="text-xs font-semibold text-[#0F172A]">Linked Evidence IDs</p>
                <ul className="mt-2 space-y-1 font-mono text-xs text-[#475569]">
                  {passport.evidence_ids.map((ev) => (
                    <li key={ev}>{ev}</li>
                  ))}
                </ul>
              </div>
              <div>
                <p className="text-xs font-semibold text-[#0F172A]">Audit History</p>
                <ul className="mt-2 space-y-2 text-xs text-[#475569]">
                  {passport.audit_history.map((entry, idx) => (
                    <li key={idx} className="tabular-nums">
                      <span className="font-mono font-semibold text-[#0F172A]">
                        {entry.timestamp_utc}
                      </span>{" "}
                      · {entry.action} — {entry.details}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </SectionCard>
        </div>
      )}
    </DashboardLayout>
  );
}
