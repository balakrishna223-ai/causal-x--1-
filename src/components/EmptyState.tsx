import React from "react";
import { Inbox } from "lucide-react";

interface EmptyStateProps {
  title: string;
  description: string;
  action?: React.ReactNode;
}

export function EmptyState({ title, description, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center rounded-xl border border-sky-100 bg-white px-6 py-12 text-center">
      <Inbox className="h-8 w-8 text-[#38BDF8]" aria-hidden="true" />
      <h3 className="mt-3 font-display text-base font-semibold text-[#0F172A]">{title}</h3>
      <p className="mt-1 max-w-md text-sm text-[#475569]">{description}</p>
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}
