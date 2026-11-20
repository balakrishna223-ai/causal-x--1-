import { AlertCircle, AlertTriangle, CheckCircle2, Info } from "lucide-react";

interface StatusBadgeProps {
  label: string;
  tone?: "excellent" | "good" | "fair" | "poor";
}

export function toneFromValue(value: string): "excellent" | "good" | "fair" | "poor" {
  const norm = value.toLowerCase();
  if (norm === "excellent" || norm === "online" || norm === "verified" || norm === "resolved" || norm === "approved" || norm === "healthy") {
    return "excellent";
  }
  if (norm === "good" || norm === "low" || norm === "investigating" || norm === "delivered") {
    return "good";
  }
  if (norm === "fair" || norm === "medium" || norm === "open" || norm === "degraded") {
    return "fair";
  }
  return "poor";
}

export function StatusBadge({ label, tone }: StatusBadgeProps) {
  const resolved = tone ?? toneFromValue(label);
  const styles = {
    excellent: "text-emerald-700 bg-emerald-50 border-emerald-200",
    good: "text-[#0284C7] bg-[#EFF9FF] border-sky-200",
    fair: "text-amber-700 bg-amber-50 border-amber-200",
    poor: "text-red-700 bg-red-50 border-red-200",
  }[resolved];

  const Icon = {
    excellent: CheckCircle2,
    good: Info,
    fair: AlertTriangle,
    poor: AlertCircle,
  }[resolved];

  return (
    <span
      className={`inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-md border px-2.5 py-1 text-xs font-semibold ${styles}`}
    >
      <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
      <span>{label}</span>
    </span>
  );
}
