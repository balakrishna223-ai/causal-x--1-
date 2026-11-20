import { Link, useLocation, useNavigate } from "react-router-dom";
import {
  Activity,
  AlertCircle,
  Globe,
  Home,
  LayoutDashboard,
  LogOut,
  Server,
  Settings,
  ShieldCheck,
  X,
} from "lucide-react";
import { clearStoredSession, getStoredSession } from "../services/api";

interface SidebarProps {
  mobileOpen: boolean;
  onCloseMobile: () => void;
}

const NAV_ITEMS = [
  { to: "/home", label: "Home", icon: Home },
  { to: "/overview", label: "Overview", icon: LayoutDashboard },
  { to: "/monitoring", label: "Monitoring", icon: Activity },
  { to: "/incidents", label: "Incidents", icon: AlertCircle },
  { to: "/privacy/egress", label: "Privacy Proof", icon: ShieldCheck },
  { to: "/collectors", label: "Collectors", icon: Server },
  { to: "/settings", label: "Settings", icon: Settings },
  { to: "/", label: "Landing Page", icon: Globe },
];

export function Sidebar({ mobileOpen, onCloseMobile }: SidebarProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const session = getStoredSession();

  const handleSignOut = () => {
    clearStoredSession();
    onCloseMobile();
    navigate("/login");
  };

  const navContent = (
    <div className="flex h-full flex-col justify-between p-4">
      <div>
        <div className="mb-4 px-3 py-2">
          <p className="text-xs font-medium text-[#475569]">Tenant Workspace</p>
          <p className="mt-0.5 truncate text-sm font-semibold text-[#0F172A]">
            {session?.tenant_name || "Not signed in"}
          </p>
          {session && (
            <p className="mt-0.5 text-xs text-[#475569]">
              {session.tenant_slug} · {session.region}
            </p>
          )}
        </div>

        <nav className="space-y-1">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const active =
              location.pathname === item.to ||
              (item.to === "/incidents" && location.pathname.startsWith("/incidents/"));
            return (
              <Link
                key={item.to}
                to={item.to}
                onClick={onCloseMobile}
                className={`flex items-center gap-3 whitespace-nowrap rounded-lg px-3 py-2.5 text-sm font-medium transition-colors ${
                  active
                    ? "bg-[#E0F2FE] text-[#0284C7]"
                    : "text-[#475569] hover:bg-[#EFF9FF] hover:text-[#0F172A]"
                }`}
              >
                <Icon className="h-4 w-4 shrink-0" aria-hidden="true" />
                <span>{item.label}</span>
              </Link>
            );
          })}
        </nav>
      </div>

      <div className="border-t border-sky-100 pt-4">
        {session ? (
          <button
            type="button"
            onClick={handleSignOut}
            className="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-[#475569] transition-colors hover:bg-red-50 hover:text-red-700"
          >
            <LogOut className="h-4 w-4 shrink-0" aria-hidden="true" />
            <span>Sign out</span>
          </button>
        ) : (
          <Link
            to="/login"
            onClick={onCloseMobile}
            className="flex w-full items-center justify-center rounded-lg bg-[#0284C7] px-3 py-2 text-sm font-semibold text-white hover:bg-[#0369A1]"
          >
            Sign in
          </Link>
        )}
      </div>
    </div>
  );

  return (
    <>
      <aside className="hidden w-64 shrink-0 border-r border-sky-100 bg-white lg:block">
        {navContent}
      </aside>

      {mobileOpen && (
        <div className="fixed inset-0 z-40 flex lg:hidden">
          <div
            className="fixed inset-0 bg-slate-900/30"
            onClick={onCloseMobile}
            aria-hidden="true"
          />
          <aside className="relative z-50 flex w-64 flex-col bg-white shadow-xl">
            <div className="flex items-center justify-between border-b border-sky-100 px-4 py-3">
              <span className="font-display text-base font-bold text-[#0F172A]">CAUSAL-X</span>
              <button
                type="button"
                onClick={onCloseMobile}
                aria-label="Close sidebar"
                className="rounded-lg p-1.5 text-[#475569] hover:bg-[#EFF9FF]"
              >
                <X className="h-5 w-5" aria-hidden="true" />
              </button>
            </div>
            <div className="flex-1 overflow-y-auto">{navContent}</div>
          </aside>
        </div>
      )}
    </>
  );
}
