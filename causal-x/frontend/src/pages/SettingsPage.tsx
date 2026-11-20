import React, { useEffect, useState } from "react";
import { CheckCircle2 } from "lucide-react";

import { DashboardLayout } from "../components/DashboardLayout";
import { LoadingState } from "../components/LoadingState";
import { PageHeader } from "../components/PageHeader";
import { SectionCard } from "../components/SectionCard";
import {
  fetchThresholds,
  getStoredSession,
  updateThresholds,
  type ThresholdSettings,
} from "../lib/api";

export function SettingsPage() {
  const session = getStoredSession();
  const [form, setForm] = useState<ThresholdSettings>({
    cpu_threshold: 90,
    memory_threshold: 90,
    latency_threshold_ms: 200,
    packet_loss_threshold_pct: 5,
    offline_timeout_seconds: 60,
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [savedNotice, setSavedNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchThresholds()
      .then((data) => {
        setForm(data);
        setError(null);
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load settings"))
      .finally(() => setLoading(false));
  }, []);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setSavedNotice(null);
    setError(null);
    try {
      const updated = await updateThresholds(form);
      setForm(updated);
      setSavedNotice("Tenant thresholds updated in PostgreSQL.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update thresholds");
    } finally {
      setSaving(false);
    }
  };

  return (
    <DashboardLayout>
      <PageHeader
        title="Platform Settings"
        description="Configure tenant anomaly detection thresholds, collector offline timeouts, and inspect regional data residency."
      />

      {loading ? (
        <LoadingState rows={3} />
      ) : (
        <div className="grid gap-6 lg:grid-cols-2">
          <SectionCard
            title="Configurable Anomaly & Offline Thresholds"
            subtitle="Changes apply immediately to incoming telemetry for the active tenant"
          >
            <form onSubmit={(e) => void handleSave(e)} className="space-y-4">
              {error && <p className="text-xs font-medium text-red-700">{error}</p>}
              {savedNotice && (
                <p className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-700">
                  <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
                  {savedNotice}
                </p>
              )}

              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <label className="block text-xs font-semibold text-[#0F172A]">
                    CPU Threshold (%)
                  </label>
                  <input
                    type="number"
                    step="0.5"
                    value={form.cpu_threshold}
                    onChange={(e) => setForm({ ...form, cpu_threshold: Number(e.target.value) })}
                    className="mt-1 w-full rounded-lg border border-sky-200 px-3 py-2 text-sm tabular-nums"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-[#0F172A]">
                    Memory Threshold (%)
                  </label>
                  <input
                    type="number"
                    step="0.5"
                    value={form.memory_threshold}
                    onChange={(e) => setForm({ ...form, memory_threshold: Number(e.target.value) })}
                    className="mt-1 w-full rounded-lg border border-sky-200 px-3 py-2 text-sm tabular-nums"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-[#0F172A]">
                    Latency Threshold (ms)
                  </label>
                  <input
                    type="number"
                    step="5"
                    value={form.latency_threshold_ms}
                    onChange={(e) =>
                      setForm({ ...form, latency_threshold_ms: Number(e.target.value) })
                    }
                    className="mt-1 w-full rounded-lg border border-sky-200 px-3 py-2 text-sm tabular-nums"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-[#0F172A]">
                    Packet Loss Threshold (%)
                  </label>
                  <input
                    type="number"
                    step="0.5"
                    value={form.packet_loss_threshold_pct}
                    onChange={(e) =>
                      setForm({ ...form, packet_loss_threshold_pct: Number(e.target.value) })
                    }
                    className="mt-1 w-full rounded-lg border border-sky-200 px-3 py-2 text-sm tabular-nums"
                  />
                </div>
                <div className="sm:col-span-2">
                  <label className="block text-xs font-semibold text-[#0F172A]">
                    Collector Offline Timeout (seconds)
                  </label>
                  <input
                    type="number"
                    step="5"
                    value={form.offline_timeout_seconds}
                    onChange={(e) =>
                      setForm({ ...form, offline_timeout_seconds: Number(e.target.value) })
                    }
                    className="mt-1 w-full rounded-lg border border-sky-200 px-3 py-2 text-sm tabular-nums"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={saving}
                className="rounded-lg bg-[#0284C7] px-5 py-2.5 text-sm font-semibold text-white hover:bg-[#0369A1] disabled:opacity-60"
              >
                {saving ? "Saving..." : "Save Thresholds"}
              </button>
            </form>
          </SectionCard>

          <SectionCard
            title="Tenant Residency & Privacy Policy"
            subtitle="Enforced in backend queries and local collector"
          >
            <dl className="space-y-3 text-sm">
              <div>
                <dt className="text-xs font-semibold text-[#475569]">Tenant Organization</dt>
                <dd className="font-medium text-[#0F172A]">{session?.tenant_name}</dd>
              </div>
              <div>
                <dt className="text-xs font-semibold text-[#475569]">Assigned Region</dt>
                <dd className="font-mono text-xs text-[#0284C7]">{session?.region}</dd>
              </div>
              <div>
                <dt className="text-xs font-semibold text-[#475569]">Raw Telemetry Storage</dt>
                <dd className="text-xs text-[#0F172A]">
                  Tier 1 Local SQLite only — raw logs, passwords, and tokens never leave the customer
                  environment.
                </dd>
              </div>
            </dl>
          </SectionCard>
        </div>
      )}
    </DashboardLayout>
  );
}
