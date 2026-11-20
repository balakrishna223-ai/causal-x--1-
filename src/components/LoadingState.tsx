export function LoadingState({ rows = 4 }: { rows?: number }) {
  return (
    <div className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {Array.from({ length: 4 }).map((_, idx) => (
          <div
            key={idx}
            className="h-24 animate-pulse rounded-xl border border-sky-100 bg-white p-5"
          />
        ))}
      </div>
      <div className="space-y-3 rounded-xl border border-sky-100 bg-white p-6">
        {Array.from({ length: rows }).map((_, idx) => (
          <div key={idx} className="h-8 animate-pulse rounded bg-[#EFF9FF]" />
        ))}
      </div>
    </div>
  );
}
