import { useState } from "react";
import { CheckCircle2, ShieldAlert, ShieldCheck } from "lucide-react";
import { verifyEgressPayload, type EgressProofRecord, type EgressVerifyResult } from "../lib/api";
import { StatusBadge } from "./StatusBadge";

interface EgressProofCardProps {
  proof: EgressProofRecord;
}

export function EgressProofCard({ proof }: EgressProofCardProps) {
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<EgressVerifyResult | null>(null);
  const [verifyError, setVerifyError] = useState<string | null>(null);

  const handleVerify = async () => {
    setVerifying(true);
    setVerifyError(null);
    try {
      const result = await verifyEgressPayload(proof);
      setVerifyResult(result);
    } catch (err) {
      setVerifyError(err instanceof Error ? err.message : "Verification request failed");
    } finally {
      setVerifying(false);
    }
  };

  return (
    <article className="rounded-xl border border-sky-100 bg-white p-6 shadow-sm">
      <div className="flex flex-col justify-between gap-4 border-b border-sky-50 pb-4 sm:flex-row sm:items-center">
        <div>
          <p className="font-mono text-xs font-semibold text-[#0284C7]">
            Payload ID: {proof.payload_id}
          </p>
          <p className="mt-1 text-xs text-[#475569] tabular-nums">
            Tenant: {proof.tenant_id} · Collector: {proof.collector_id} · UTC: {proof.event_timestamp_utc}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge label={proof.approval_decision} />
          <StatusBadge label={verifyResult?.verification_status ?? proof.verification_status} />
          <StatusBadge label={proof.delivery_status} tone="good" />
        </div>
      </div>

      <div className="mt-4 grid gap-4 md:grid-cols-2">
        <div>
          <p className="text-xs font-semibold text-[#0F172A]">Allowed Fields Transmitted</p>
          <p className="mt-1 font-mono text-xs text-[#475569]">
            {proof.allowed_fields.length > 0 ? proof.allowed_fields.join(", ") : "None"}
          </p>

          <p className="mt-4 text-xs font-semibold text-[#0F172A]">
            Blocked Fields (Retained Locally Only)
          </p>
          <p className="mt-1 font-mono text-xs text-red-700">
            {proof.blocked_fields.length > 0
              ? proof.blocked_fields.join(", ")
              : "None detected in this sample"}
          </p>

          <div className="mt-4 space-y-1 text-xs text-[#475569] tabular-nums">
            <p>
              Policy Version: <span className="font-mono text-[#0F172A]">{proof.policy_version}</span>
            </p>
            <p>
              Egress Risk Score:{" "}
              <span className="font-mono text-[#0F172A]">{proof.privacy_risk_score}</span>
            </p>
            <p className="truncate">
              SHA-256:{" "}
              <span className="font-mono text-[#0F172A]">{proof.payload_hash_sha256}</span>
            </p>
            <p className="truncate">
              HMAC-SHA256:{" "}
              <span className="font-mono text-[#0F172A]">{proof.hmac_signature}</span>
            </p>
          </div>
        </div>

        <div>
          <p className="text-xs font-semibold text-[#0F172A]">
            Exact Approved Metadata Received by SaaS
          </p>
          <pre className="mt-1.5 max-h-48 overflow-auto rounded-lg border border-sky-100 bg-[#EFF9FF] p-3 font-mono text-xs text-[#0F172A]">
            {JSON.stringify(proof.approved_metadata, null, 2)}
          </pre>
        </div>
      </div>

      <div className="mt-4 flex flex-col justify-between gap-3 border-t border-sky-50 pt-4 sm:flex-row sm:items-center">
        <div className="text-xs text-[#475569]">
          {verifyResult ? (
            <span className="inline-flex items-center gap-1.5 font-medium text-emerald-700">
              <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
              SHA-256 valid: {String(verifyResult.hash_valid)} · HMAC valid:{" "}
              {String(verifyResult.hmac_valid)} · Checked {verifyResult.checked_at_utc}
            </span>
          ) : verifyError ? (
            <span className="inline-flex items-center gap-1.5 font-medium text-red-700">
              <ShieldAlert className="h-4 w-4" aria-hidden="true" />
              {verifyError}
            </span>
          ) : (
            <span>Canonical JSON verified on ingestion; run live re-verification anytime.</span>
          )}
        </div>
        <button
          type="button"
          onClick={() => void handleVerify()}
          disabled={verifying}
          className="inline-flex shrink-0 items-center gap-2 whitespace-nowrap rounded-lg border border-sky-200 bg-[#EFF9FF] px-4 py-2 text-xs font-semibold text-[#0284C7] transition-colors hover:bg-[#E0F2FE] disabled:opacity-60"
        >
          <ShieldCheck className="h-4 w-4" aria-hidden="true" />
          {verifying ? "Verifying..." : "Verify Payload Integrity"}
        </button>
      </div>
    </article>
  );
}
