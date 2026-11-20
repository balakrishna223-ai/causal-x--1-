import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ArrowRight, FileCheck2, GitBranch, ShieldCheck } from "lucide-react";

import { ConnectionStatus } from "../components/ConnectionStatus";
import { HeroBackground } from "../components/HeroBackground";
import { MetricCard } from "../components/MetricCard";
import { Navbar } from "../components/Navbar";
import { StatusBadge } from "../components/StatusBadge";
import {
  fetchBackendHealth,
  fetchDashboardOverview,
  getApiBaseUrl,
  getStoredSession,
  type DashboardOverview,
  type HealthResponse,
} from "../lib/api";

const PROCESS_STEPS = [
  { step: "01", title: "Collect Locally", detail: "psutil samples host & process telemetry inside Tier 1" },
  { step: "02", title: "Protect Sensitive Data", detail: "Classify, redact, and block secrets before egress" },
  { step: "03", title: "Verify Payload", detail: "Canonical JSON + SHA-256 & HMAC proof check" },
  { step: "04", title: "Detect Anomalies", detail: "Rules + rolling baseline + IsolationForest" },
  { step: "05", title: "Explain Incidents", detail: "NetworkX correlation & Incident Passports" },
];

export function LandingPage() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [overview, setOverview] = useState<DashboardOverview | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const apiBaseUrl = getApiBaseUrl();

  const loadLivePreview = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const h = await fetchBackendHealth();
      setHealth(h);
      const session = getStoredSession();
      if (session?.access_token) {
        try {
          const ov = await fetchDashboardOverview();
          setOverview(ov);
        } catch {
          setOverview(null);
        }
      } else {
        setOverview(null);
      }
    } catch (err) {
      setHealth(null);
      setOverview(null);
      setError(err instanceof Error ? err.message : "Backend unreachable");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadLivePreview();
  }, [loadLivePreview]);

  return (
    <HeroBackground>
      <Navbar />
      <main className="mx-auto max-w-6xl px-6 py-16 md:py-24">
        {/* Hero */}
        <section className="mx-auto max-w-3xl text-center">
          <h1
            className="font-display text-4xl font-bold tracking-tight text-[#0F172A] md:text-5xl"
            style={{ textWrap: "balance" }}
          >
            Beyond Alerts. Understand the Cause. Protect Every Signal.
          </h1>
          <p className="mx-auto mt-6 max-w-2xl text-base leading-relaxed text-[#475569] md:text-lg">
            CAUSAL-X is a privacy-first, proof-carrying AIOps platform that keeps sensitive
            telemetry local while turning approved metadata into explainable operational
            intelligence.
          </p>

          <div className="mt-8 flex flex-wrap items-center justify-center gap-4">
            <Link
              to="/overview"
              className="inline-flex items-center gap-2 whitespace-nowrap rounded-lg bg-[#0284C7] px-6 py-3 text-sm font-semibold text-white transition-colors hover:bg-[#0369A1]"
            >
              Open Live Platform
              <ArrowRight className="h-4 w-4" aria-hidden="true" />
            </Link>
            <Link
              to="/privacy/egress"
              className="inline-flex items-center gap-2 whitespace-nowrap rounded-lg border border-sky-200 bg-white px-6 py-3 text-sm font-semibold text-[#0F172A] transition-colors hover:bg-[#EFF9FF]"
            >
              Explore Privacy Proof
            </Link>
          </div>

          <p className="mt-5 text-sm font-medium text-[#475569]">
            Raw secrets stay local. Only approved metadata is transmitted.
          </p>
        </section>

        {/* Three Feature Cards */}
        <section className="mt-16 grid gap-6 md:grid-cols-3">
          <article className="rounded-xl border border-sky-100 bg-white p-6 shadow-sm">
            <ShieldCheck className="h-6 w-6 text-[#0284C7]" aria-hidden="true" />
            <h2 className="mt-4 font-display text-lg font-semibold text-[#0F172A]">
              Privacy Shield
            </h2>
            <p className="mt-2 text-sm leading-relaxed text-[#475569]">
              Classifies fields locally into safe, sensitive, and restricted tiers before any
              outbound HTTP request is built.
            </p>
          </article>

          <article className="rounded-xl border border-sky-100 bg-white p-6 shadow-sm">
            <FileCheck2 className="h-6 w-6 text-[#0284C7]" aria-hidden="true" />
            <h2 className="mt-4 font-display text-lg font-semibold text-[#0F172A]">
              Proof-Carrying Telemetry
            </h2>
            <p className="mt-2 text-sm leading-relaxed text-[#475569]">
              Canonicalizes approved metadata, attaches UUID payload IDs with SHA-256 and HMAC
              proofs, and verifies ingestion integrity.
            </p>
          </article>

          <article className="rounded-xl border border-sky-100 bg-white p-6 shadow-sm">
            <GitBranch className="h-6 w-6 text-[#0284C7]" aria-hidden="true" />
            <h2 className="mt-4 font-display text-lg font-semibold text-[#0F172A]">
              Explainable Root-Cause Intelligence
            </h2>
            <p className="mt-2 text-sm leading-relaxed text-[#475569]">
              Correlates anomalies across dependent components and ranks evidence-backed hypotheses
              with explicit confidence and uncertainty.
            </p>
          </article>
        </section>

        {/* Horizontal Process Flow */}
        <section className="mt-16 rounded-xl border border-sky-100 bg-white p-6 shadow-sm">
          <h2 className="font-display text-base font-semibold text-[#0F172A]">
            End-to-End Privacy & Intelligence Pipeline
          </h2>
          <div className="mt-5 grid gap-4 md:grid-cols-5">
            {PROCESS_STEPS.map((item) => (
              <div key={item.step} className="rounded-lg border border-sky-100 bg-[#EFF9FF]/60 p-4">
                <p className="font-mono text-xs font-semibold text-[#0284C7]">{item.step}</p>
                <p className="mt-1 text-sm font-semibold text-[#0F172A]">{item.title}</p>
                <p className="mt-1 text-xs leading-relaxed text-[#475569]">{item.detail}</p>
              </div>
            ))}
          </div>
        </section>

        {/* API-Connected Live Preview */}
        <section className="mt-12 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h2 className="font-display text-base font-semibold text-[#0F172A]">
              Live Platform Telemetry Preview
            </h2>
            {overview && <StatusBadge label={overview.health_state} />}
          </div>

          <ConnectionStatus
            loading={loading}
            health={health}
            error={error}
            apiBaseUrl={apiBaseUrl}
            onRetry={() => void loadLivePreview()}
          />

          {overview ? (
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <MetricCard
                label="Collector Fleet State"
                value={`${overview.kpis.online_collectors}/${overview.kpis.total_collectors} Online`}
                detail={`Tenant: ${overview.tenant.slug} (${overview.tenant.region})`}
              />
              <MetricCard
                label="Active Incidents"
                value={overview.kpis.active_incidents}
                detail={`${overview.kpis.critical_alerts} high/critical alerts`}
              />
              <MetricCard
                label="Egress Privacy Risk"
                value={overview.kpis.privacy_risk_score}
                detail={`${overview.kpis.blocked_fields_count} restricted fields blocked locally`}
              />
              <MetricCard
                label="Verified Payloads"
                value={overview.kpis.verified_payloads_count}
                detail="SHA-256 & HMAC verified"
              />
            </div>
          ) : health && !error ? (
            <div className="flex flex-col justify-between gap-4 rounded-xl border border-sky-100 bg-white p-5 shadow-sm sm:flex-row sm:items-center">
              <p className="text-sm text-[#475569]">
                Backend is online. Sign in to a tenant workspace to stream live collector state,
                incidents, privacy risk, and verified payload counts.
              </p>
              <Link
                to="/login"
                className="inline-flex shrink-0 items-center whitespace-nowrap rounded-lg bg-[#0284C7] px-4 py-2 text-xs font-semibold text-white hover:bg-[#0369A1]"
              >
                Sign in to Inspect Tenant Metrics
              </Link>
            </div>
          ) : null}
        </section>

        {/* Final Call to Action */}
        <section className="mt-16 rounded-xl border border-sky-200 bg-white p-8 text-center shadow-sm">
          <h2 className="font-display text-2xl font-bold text-[#0F172A]">
            Secure observability without losing context.
          </h2>
          <p className="mx-auto mt-2 max-w-xl text-sm text-[#475569]">
            Inspect live host metrics, verify cryptographic egress proofs, and trace correlated
            incidents through transparent root-cause passports.
          </p>
          <div className="mt-6">
            <Link
              to="/overview"
              className="inline-flex items-center gap-2 whitespace-nowrap rounded-lg bg-[#FBBF24] px-6 py-3 text-sm font-semibold text-[#0F172A] transition-colors hover:bg-[#F59E0B]"
            >
              Launch Dashboard
              <ArrowRight className="h-4 w-4" aria-hidden="true" />
            </Link>
          </div>
        </section>
      </main>
    </HeroBackground>
  );
}
