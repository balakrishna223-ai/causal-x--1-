import { useState } from "react";
import { Link } from "react-router-dom";
import { Menu, X } from "lucide-react";

interface NavbarProps {
  onOpenSidebar?: () => void;
  showSidebarToggle?: boolean;
}

export function Navbar({ onOpenSidebar, showSidebarToggle = false }: NavbarProps) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  return (
    <header className="sticky top-0 z-30 border-b border-sky-100 bg-white/90 backdrop-blur-md">
      <div className="mx-auto flex max-w-7xl items-center justify-between gap-8 px-6 py-3.5">
        <div className="flex items-center gap-3 shrink-0">
          {showSidebarToggle && onOpenSidebar && (
            <button
              type="button"
              onClick={onOpenSidebar}
              aria-label="Open navigation sidebar"
              className="inline-flex h-10 w-10 items-center justify-center rounded-lg border border-sky-200 text-[#0F172A] hover:bg-[#EFF9FF] lg:hidden"
            >
              <Menu className="h-5 w-5" aria-hidden="true" />
            </button>
          )}
          <Link
            to="/"
            className="shrink-0 whitespace-nowrap font-display text-lg font-bold tracking-tight text-[#0F172A]"
          >
            CAUSAL-X
          </Link>
        </div>

        <nav className="hidden items-center gap-6 text-sm font-medium text-[#475569] md:flex">
          <Link to="/overview" className="shrink-0 whitespace-nowrap hover:text-[#0284C7]">
            Platform
          </Link>
          <Link to="/monitoring" className="shrink-0 whitespace-nowrap hover:text-[#0284C7]">
            Monitoring
          </Link>
          <Link to="/incidents" className="shrink-0 whitespace-nowrap hover:text-[#0284C7]">
            Incidents
          </Link>
          <Link to="/privacy/egress" className="shrink-0 whitespace-nowrap hover:text-[#0284C7]">
            Privacy Proof
          </Link>
          <Link to="/collectors" className="shrink-0 whitespace-nowrap hover:text-[#0284C7]">
            Collectors
          </Link>
        </nav>

        <div className="flex items-center gap-3 shrink-0">
          <Link
            to="/overview"
            className="inline-flex shrink-0 items-center whitespace-nowrap rounded-lg bg-[#FBBF24] px-4 py-2 text-sm font-semibold text-[#0F172A] transition-colors hover:bg-[#F59E0B] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#0284C7]"
          >
            Launch Dashboard
          </Link>
          {!showSidebarToggle && (
            <button
              type="button"
              onClick={() => setMobileMenuOpen((prev) => !prev)}
              aria-label="Toggle navigation menu"
              className="inline-flex h-10 w-10 items-center justify-center rounded-lg border border-sky-200 text-[#0F172A] hover:bg-[#EFF9FF] md:hidden"
            >
              {mobileMenuOpen ? (
                <X className="h-5 w-5" aria-hidden="true" />
              ) : (
                <Menu className="h-5 w-5" aria-hidden="true" />
              )}
            </button>
          )}
        </div>
      </div>

      {mobileMenuOpen && !showSidebarToggle && (
        <div className="border-t border-sky-100 bg-white px-6 py-4 md:hidden">
          <nav className="flex flex-col gap-3 text-sm font-medium text-[#475569]">
            <Link to="/overview" onClick={() => setMobileMenuOpen(false)} className="py-1 hover:text-[#0284C7]">
              Platform
            </Link>
            <Link to="/monitoring" onClick={() => setMobileMenuOpen(false)} className="py-1 hover:text-[#0284C7]">
              Monitoring
            </Link>
            <Link to="/incidents" onClick={() => setMobileMenuOpen(false)} className="py-1 hover:text-[#0284C7]">
              Incidents
            </Link>
            <Link to="/privacy/egress" onClick={() => setMobileMenuOpen(false)} className="py-1 hover:text-[#0284C7]">
              Privacy Proof
            </Link>
            <Link to="/collectors" onClick={() => setMobileMenuOpen(false)} className="py-1 hover:text-[#0284C7]">
              Collectors
            </Link>
          </nav>
        </div>
      )}
    </header>
  );
}
