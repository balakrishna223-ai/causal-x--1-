import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { AlertCircle, CheckCircle2, KeyRound, Mail, Shield } from "lucide-react";

import { Navbar } from "../components/Navbar";
import {
  loginPasswordlessInstant,
  loginUser,
  registerOperator,
  requestPasswordlessCode,
  verifyPasswordlessCode,
} from "../services/api";

type AuthMode = "password" | "register" | "passwordless";

export function LoginPage() {
  const navigate = useNavigate();
  const [mode, setMode] = useState<AuthMode>("password");
  const [email, setEmail] = useState(import.meta.env.PROD ? "" : "ops@acme-cloud.dev");
  const [password, setPassword] = useState(import.meta.env.PROD ? "" : "DevAcmePass!2026");
  const [fullName, setFullName] = useState("");
  const [tenantSlug, setTenantSlug] = useState<"acme-cloud" | "globex-fin">("acme-cloud");
  const [otpCode, setOtpCode] = useState("");
  const [issuedCodeHint, setIssuedCodeHint] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);

  const handlePasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setInfo(null);
    try {
      if (mode === "register") {
        await registerOperator(email, password, tenantSlug, fullName);
      } else {
        await loginUser(email, password);
      }
      navigate("/overview");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Authentication failed");
    } finally {
      setLoading(false);
    }
  };

  const handleRequestOtp = async () => {
    if (!email.trim()) {
      setError("Enter your Gmail or operator email address first.");
      return;
    }
    setLoading(true);
    setError(null);
    setInfo(null);
    try {
      const res = await requestPasswordlessCode(email, tenantSlug);
      setIssuedCodeHint(res.dev_verification_code ?? null);
      if (res.dev_verification_code) {
        setOtpCode(res.dev_verification_code);
        setInfo(
          `One-time code issued for ${res.email} (valid 10m). Dev verification code: ${res.dev_verification_code}`
        );
      } else {
        setInfo(`One-time verification code issued for ${res.email}.`);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to issue verification code");
    } finally {
      setLoading(false);
    }
  };

  const handlePasswordlessSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await verifyPasswordlessCode(email, tenantSlug, otpCode);
      navigate("/overview");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification failed");
    } finally {
      setLoading(false);
    }
  };

  const handleInstantPasswordless = async () => {
    if (!email.trim()) {
      setError("Enter your Gmail or operator email address first.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      await loginPasswordlessInstant(email, tenantSlug);
      navigate("/overview");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Passwordless sign-in failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#EFF9FF]">
      <Navbar />
      <main className="mx-auto flex max-w-md flex-col justify-center px-6 py-12">
        <div className="rounded-xl border border-sky-100 bg-white p-8 shadow-sm">
          <div className="flex items-center gap-2 text-[#0284C7]">
            <Shield className="h-5 w-5" aria-hidden="true" />
            <span className="text-xs font-semibold">Tenant-Isolated Authentication</span>
          </div>
          <h1 className="mt-3 font-display text-2xl font-bold text-[#0F172A]">
            Sign in to CAUSAL-X
          </h1>
          <p className="mt-1 text-sm text-[#475569]">
            {import.meta.env.PROD
              ? "Sign in with your operator account, or create an account for the public demo workspace."
              : "Authenticate with Gmail & password or use Passwordless (no password) access to inspect isolated metadata and proofs."}
          </p>

          {/* Authentication Mode Tabs */}
          <div
            className={`mt-5 grid ${import.meta.env.PROD ? "grid-cols-2" : "grid-cols-3"} gap-1 rounded-lg bg-[#EFF9FF] p-1 text-xs font-medium`}
          >
            <button
              type="button"
              onClick={() => {
                setMode("password");
                setError(null);
                setInfo(null);
              }}
              className={`rounded-md px-2 py-2 transition-colors ${
                mode === "password"
                  ? "bg-white font-semibold text-[#0F172A] shadow-sm"
                  : "text-[#475569] hover:text-[#0F172A]"
              }`}
            >
              Sign in
            </button>
            <button
              type="button"
              onClick={() => {
                setMode("register");
                if (email === "ops@acme-cloud.dev" || email === "ops@globex-fin.dev") {
                  setEmail("");
                  setPassword("");
                }
                setError(null);
                setInfo(null);
              }}
              className={`rounded-md px-2 py-2 transition-colors ${
                mode === "register"
                  ? "bg-white font-semibold text-[#0F172A] shadow-sm"
                  : "text-[#475569] hover:text-[#0F172A]"
              }`}
            >
              {import.meta.env.PROD ? "Create Demo Account" : "Gmail Sign up"}
            </button>
            {!import.meta.env.PROD && (
              <button
                type="button"
                onClick={() => {
                  setMode("passwordless");
                  setError(null);
                  setInfo(null);
                }}
                className={`rounded-md px-2 py-2 transition-colors ${
                  mode === "passwordless"
                    ? "bg-white font-semibold text-[#0F172A] shadow-sm"
                    : "text-[#475569] hover:text-[#0F172A]"
                }`}
              >
                No Password
              </button>
            )}
          </div>

          {error && (
            <div className="mt-4 flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-700">
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
              <span>{error}</span>
            </div>
          )}

          {info && (
            <div className="mt-4 flex items-start gap-2 rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-xs text-emerald-800">
              <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
              <span>{info}</span>
            </div>
          )}

          {mode === "register" && import.meta.env.PROD && (
            <p className="mt-4 rounded-lg border border-sky-100 bg-[#EFF9FF] p-3 text-xs text-[#475569]">
              Demo accounts are limited to the Acme Cloud sample workspace. Email verification is
              not configured; do not use sensitive credentials or connect production telemetry.
            </p>
          )}

          {mode !== "passwordless" ? (
            <form onSubmit={(e) => void handlePasswordSubmit(e)} className="mt-5 space-y-4">
              {mode === "register" && (
                <div>
                  <label htmlFor="full-name" className="block text-xs font-semibold text-[#0F172A]">
                    Operator Name (optional)
                  </label>
                  <input
                    id="full-name"
                    type="text"
                    placeholder="Harshitha SRE"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    className="mt-1.5 w-full rounded-lg border border-sky-200 bg-white px-3.5 py-2.5 text-sm text-[#0F172A] focus:border-[#0284C7] focus:outline-none"
                  />
                </div>
              )}

              <div>
                <label htmlFor="email" className="block text-xs font-semibold text-[#0F172A]">
                  {import.meta.env.PROD ? "Operator Email" : "Gmail or Operator Email"}
                </label>
                <input
                  id="email"
                  type="email"
                  required
                  placeholder="your.name@gmail.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="mt-1.5 w-full rounded-lg border border-sky-200 bg-white px-3.5 py-2.5 text-sm text-[#0F172A] focus:border-[#0284C7] focus:outline-none"
                />
              </div>

              <div>
                <label htmlFor="password" className="block text-xs font-semibold text-[#0F172A]">
                  Password
                </label>
                <input
                  id="password"
                  type="password"
                  required
                  minLength={mode === "register" ? 6 : 1}
                  placeholder={mode === "register" ? "Minimum 6 characters" : "Enter password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="mt-1.5 w-full rounded-lg border border-sky-200 bg-white px-3.5 py-2.5 text-sm text-[#0F172A] focus:border-[#0284C7] focus:outline-none"
                />
              </div>

              {mode === "register" && (
                !import.meta.env.PROD && (
                  <div>
                    <label htmlFor="tenant-reg" className="block text-xs font-semibold text-[#0F172A]">
                      Assign Tenant Workspace
                    </label>
                    <select
                      id="tenant-reg"
                      value={tenantSlug}
                      onChange={(e) => setTenantSlug(e.target.value as "acme-cloud" | "globex-fin")}
                      className="mt-1.5 w-full rounded-lg border border-sky-200 bg-white px-3.5 py-2.5 text-sm text-[#0F172A] focus:border-[#0284C7] focus:outline-none"
                    >
                      <option value="acme-cloud">Acme Cloud Operations (us-east-1)</option>
                      <option value="globex-fin">Globex Financial Systems (eu-central-1)</option>
                    </select>
                  </div>
                )
              )}

              <button
                type="submit"
                disabled={loading}
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-[#0284C7] px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-[#0369A1] disabled:opacity-60"
              >
                <KeyRound className="h-4 w-4" aria-hidden="true" />
                {loading
                  ? "Authenticating..."
                  : mode === "register"
                    ? import.meta.env.PROD
                      ? "Create Demo Account & Sign in"
                      : "Create Gmail Operator & Sign in"
                    : "Sign in with Email & Password"}
              </button>
            </form>
          ) : (
            <form onSubmit={(e) => void handlePasswordlessSubmit(e)} className="mt-5 space-y-4">
              <div>
                <label
                  htmlFor="passwordless-email"
                  className="block text-xs font-semibold text-[#0F172A]"
                >
                  Gmail or Operator Email (No Password Required)
                </label>
                <input
                  id="passwordless-email"
                  type="email"
                  required
                  placeholder="your.name@gmail.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="mt-1.5 w-full rounded-lg border border-sky-200 bg-white px-3.5 py-2.5 text-sm text-[#0F172A] focus:border-[#0284C7] focus:outline-none"
                />
              </div>

              <div>
                <label htmlFor="tenant-otp" className="block text-xs font-semibold text-[#0F172A]">
                  Tenant Workspace
                </label>
                <select
                  id="tenant-otp"
                  value={tenantSlug}
                  onChange={(e) => setTenantSlug(e.target.value as "acme-cloud" | "globex-fin")}
                  className="mt-1.5 w-full rounded-lg border border-sky-200 bg-white px-3.5 py-2.5 text-sm text-[#0F172A] focus:border-[#0284C7] focus:outline-none"
                >
                  <option value="acme-cloud">Acme Cloud Operations (us-east-1)</option>
                  <option value="globex-fin">Globex Financial Systems (eu-central-1)</option>
                </select>
              </div>

              <div className="flex gap-2">
                <button
                  type="button"
                  disabled={loading}
                  onClick={() => void handleRequestOtp()}
                  className="flex-1 rounded-lg border border-sky-200 bg-[#EFF9FF] px-3 py-2 text-xs font-semibold text-[#0284C7] hover:bg-[#E0F2FE] disabled:opacity-60"
                >
                  Get One-Time Code
                </button>
                <button
                  type="button"
                  disabled={loading}
                  onClick={() => void handleInstantPasswordless()}
                  className="flex-1 rounded-lg bg-[#FBBF24] px-3 py-2 text-xs font-semibold text-[#0F172A] hover:bg-[#F59E0B] disabled:opacity-60"
                >
                  Instant No-Password Sign in
                </button>
              </div>

              <div>
                <label htmlFor="otp-code" className="block text-xs font-semibold text-[#0F172A]">
                  6-Digit Verification Code {issuedCodeHint ? `(Issued: ${issuedCodeHint})` : ""}
                </label>
                <input
                  id="otp-code"
                  type="text"
                  inputMode="numeric"
                  placeholder="Enter 6-digit code"
                  value={otpCode}
                  onChange={(e) => setOtpCode(e.target.value)}
                  className="mt-1.5 w-full rounded-lg border border-sky-200 bg-white px-3.5 py-2.5 font-mono text-sm text-[#0F172A] focus:border-[#0284C7] focus:outline-none"
                />
              </div>

              <button
                type="submit"
                disabled={loading || otpCode.trim().length < 6}
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-[#0284C7] px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-[#0369A1] disabled:opacity-60"
              >
                <Mail className="h-4 w-4" aria-hidden="true" />
                {loading ? "Verifying..." : "Verify Code & Sign in"}
              </button>
            </form>
          )}

          {!import.meta.env.PROD && (
            <div className="mt-6 border-t border-sky-100 pt-5">
              <p className="text-xs font-semibold text-[#475569]">
                Quick Tenant Operator Presets
              </p>
              <div className="mt-3 grid gap-2 sm:grid-cols-2">
                <button
                  type="button"
                  onClick={() => {
                    setMode("password");
                    setEmail("ops@acme-cloud.dev");
                    setPassword("DevAcmePass!2026");
                    setTenantSlug("acme-cloud");
                  }}
                  className="rounded-lg border border-sky-200 bg-[#EFF9FF] px-3 py-2 text-left text-xs font-medium text-[#0F172A] hover:bg-[#E0F2FE]"
                >
                  Acme Cloud (us-east-1)
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setMode("password");
                    setEmail("ops@globex-fin.dev");
                    setPassword("DevGlobexPass!2026");
                    setTenantSlug("globex-fin");
                  }}
                  className="rounded-lg border border-sky-200 bg-[#EFF9FF] px-3 py-2 text-left text-xs font-medium text-[#0F172A] hover:bg-[#E0F2FE]"
                >
                  Globex Fin (eu-central-1)
                </button>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
