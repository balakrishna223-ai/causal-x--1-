import { useCallback, useEffect, useState } from "react";

import { DashboardLayout } from "../components/DashboardLayout";
import { EgressProofCard } from "../components/EgressProofCard";
import { EmptyState } from "../components/EmptyState";
import { LoadingState } from "../components/LoadingState";
import { MetricCard } from "../components/MetricCard";
import { PageHeader } from "../components/PageHeader";
import {
  fetchEgressAudit,
  getStoredSession,
  openTenantWebSocket,
  triggerControlledSimulation,
  type EgressProofRecord,
} from "../services/api";

export function EgressProofPage() {
  const [proofs, setProofs] = useState<EgressProofRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [wsConnected, setWsConnected] = useState(false);
  const [testingSecretLeak, setTestingSecretLeak] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const loadAudit = useCallback(async () => {
    try {
      const rows = await fetchEgressAudit(50);
      setProofs(rows);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load egress audit");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadAudit();
    const session = getStoredSession();
    if (!session?.access_token) return;
    const ws = openTenantWebSocket(
      session.access_token,
      () => void loadAudit(),
      setWsConnected
    );
    return () => ws.close();
  }, [loadAudit]);

  const handleTestSecretLeak = async () => {
    setTestingSecretLeak(true);
    setNotice(null);
    try {
      const res = await triggerControlledSimulation("secret_leak_test");
      setNotice(
        `Controlled secret_leak_test processed locally: blocked fields [${res.blocked_fields.join(
          ", "
        )}] were retained locally and stripped before transmission.`
      );
      await loadAudit();
    } catch (err) {
      setNotice(err instanceof Error ? err.message : "Secret-leak test failed");
    } finally {
      setTestingSecretLeak(false);
    }
  };

  const totalBlocked = proofs.reduce((acc, p) => acc + p.blocked_fields.length, 0);
  const totalVerified = proofs.filter((p) => p.verification_status === "VERIFIED").length;

  return (
    <DashboardLayout wsConnected={wsConnected}>
      <PageHeader
        title="Egress Proof Centre"
        description="Cryptographic audit of exact allow-listed metadata leaving the Tier 1 collector. Raw logs, secrets, and credentials never appear here."
        actions={
          <button
            type="button"
            disabled={testingSecretLeak}
            onClick={() => void handleTestSecretLeak()}
            className="rounded-lg bg-[#FBBF24] px-4 py-2 text-xs font-semibold text-[#0F172A] hover:bg-[#F59E0B] disabled:opacity-60"
          >
            {testingSecretLeak ? "Testing Privacy Shield..." : "Test Secret-Leak Blocking"}
          </button>
        }
      />

      {notice && (
        <div className="mb-4 rounded-xl border border-emerald-200 bg-emerald-50 p-4 text-xs font-medium text-emerald-800">
          {notice}
        </div>
      )}

      {loading ? (
        <LoadingState />
      ) : error ? (
        <div className="rounded-xl border border-amber-200 bg-white p-6 text-sm text-[#475569]">
          {error}
        </div>
      ) : (
        <div className="space-y-6">
          <div className="grid gap-4 sm:grid-cols-3">
            <MetricCard
              label="Audited Egress Payloads"
              value={proofs.length}
              detail="Metadata-only envelopes"
            />
            <MetricCard
              label="Verified SHA-256 & HMAC"
              value={totalVerified}
              detail="Zero tamper detections"
            />
            <MetricCard
              label="Restricted/Unapproved Fields Blocked"
              value={totalBlocked}
              detail="Retained strictly on local collector"
            />
          </div>

          {proofs.length === 0 ? (
            <EmptyState
              title="No Egress Proofs Recorded Yet"
              description="Once the local collector sends approved metadata, each payload proof record will appear here for inspection."
            />
          ) : (
            <div className="space-y-4">
              {proofs.map((proof) => (
                <EgressProofCard key={proof.id} proof={proof} />
              ))}
            </div>
          )}
        </div>
      )}
    </DashboardLayout>
  );
}
