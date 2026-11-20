import React, { useState } from "react";
import { Link } from "react-router-dom";
import { Lock } from "lucide-react";

import { getStoredSession } from "../lib/api";
import { Navbar } from "./Navbar";
import { Sidebar } from "./Sidebar";

interface DashboardLayoutProps {
  children: React.ReactNode;
  wsConnected?: boolean;
}

export function DashboardLayout({ children, wsConnected }: DashboardLayoutProps) {
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const session = getStoredSession();

  return (
    <div className="min-h-screen bg-[#EFF9FF]">
      <Navbar
        showSidebarToggle
        onOpenSidebar={() => setMobileSidebarOpen(true)}
      />

      <div className="mx-auto flex max-w-7xl">
        <Sidebar
          mobileOpen={mobileSidebarOpen}
          onCloseMobile={() => setMobileSidebarOpen(false)}
        />

        <main className="min-w-0 flex-1 px-4 py-6 sm:px-8 sm:py-8">
          {!session ? (
            <div className="rounded-xl border border-sky-200 bg-white p-8 text-center shadow-sm">
              <Lock className="mx-auto h-8 w-8 text-[#0284C7]" aria-hidden="true" />
              <h2 className="mt-3 font-display text-lg font-semibold text-[#0F172A]">
                Tenant Authentication Required
              </h2>
              <p className="mx-auto mt-1 max-w-md text-sm text-[#475569]">
                CAUSAL-X enforces strict backend tenant isolation. Sign in with a development tenant
                account to inspect live telemetry, incidents, and egress proofs.
              </p>
              <Link
                to="/login"
                className="mt-5 inline-flex items-center rounded-lg bg-[#0284C7] px-5 py-2.5 text-sm font-semibold text-white hover:bg-[#0369A1]"
              >
                Sign in to Tenant Workspace
              </Link>
            </div>
          ) : (
            <>
              {wsConnected !== undefined && (
                <div className="mb-4 flex items-center justify-end text-xs text-[#475569]">
                  <span>
                    Live WebSocket stream:{" "}
                    <strong className={wsConnected ? "text-emerald-700" : "text-amber-700"}>
                      {wsConnected ? "Connected" : "Reconnecting / Standby"}
                    </strong>
                  </span>
                </div>
              )}
              {children}
            </>
          )}
        </main>
      </div>
    </div>
  );
}
