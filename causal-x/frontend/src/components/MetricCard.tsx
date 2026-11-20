import React from "react";

interface MetricCardProps {
  label: string;
  value: string | number;
  detail?: string;
}

export function MetricCard({ label, value, detail }: MetricCardProps) {
  return (
    <div className="rounded-xl border border-sky-100 bg-white p-5 shadow-sm">
      <p className="text-xs font-medium text-[#475569]">{label}</p>
      <p className="mt-2 font-display text-2xl font-bold text-[#0F172A] tabular-nums">{value}</p>
      {detail && <p className="mt-1 text-xs text-[#475569]">{detail}</p>}
    </div>
  );
}
