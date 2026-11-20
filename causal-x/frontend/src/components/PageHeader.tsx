import React from "react";

interface PageHeaderProps {
  title: string;
  description: string;
  actions?: React.ReactNode;
}

export function PageHeader({ title, description, actions }: PageHeaderProps) {
  return (
    <div className="mb-6 flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
      <div>
        <h1 className="font-display text-2xl font-bold tracking-tight text-[#0F172A]">{title}</h1>
        <p className="mt-1 text-sm text-[#475569]">{description}</p>
      </div>
      {actions && <div className="flex shrink-0 items-center gap-3">{actions}</div>}
    </div>
  );
}
