import React from "react";

interface SectionCardProps {
  title: string;
  subtitle?: string;
  action?: React.ReactNode;
  children: React.ReactNode;
}

export function SectionCard({ title, subtitle, action, children }: SectionCardProps) {
  return (
    <section className="rounded-xl border border-sky-100 bg-white p-6 shadow-sm">
      <div className="mb-4 flex flex-col justify-between gap-2 border-b border-sky-50 pb-4 sm:flex-row sm:items-center">
        <div>
          <h2 className="font-display text-base font-semibold text-[#0F172A]">{title}</h2>
          {subtitle && <p className="mt-0.5 text-xs text-[#475569]">{subtitle}</p>}
        </div>
        {action && <div className="shrink-0">{action}</div>}
      </div>
      {children}
    </section>
  );
}
