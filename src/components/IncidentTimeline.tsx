import { StatusBadge } from "./StatusBadge";

export interface TimelineEventItem {
  event_timestamp_utc: string;
  event_type: string;
  description: string;
  severity: string;
  component: string;
  evidence_ref: string;
}

interface IncidentTimelineProps {
  events: TimelineEventItem[];
}

export function IncidentTimeline({ events }: IncidentTimelineProps) {
  if (events.length === 0) {
    return <p className="text-sm text-[#475569]">No timeline events recorded yet.</p>;
  }

  return (
    <ol className="space-y-4">
      {events.map((ev, idx) => (
        <li
          key={`${ev.evidence_ref}-${idx}`}
          className="flex flex-col justify-between gap-3 border-b border-sky-50 pb-4 last:border-b-0 last:pb-0 sm:flex-row sm:items-start"
        >
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2 text-xs text-[#475569] tabular-nums">
              <span className="font-mono font-semibold text-[#0F172A]">
                {ev.event_timestamp_utc}
              </span>
              <span aria-hidden="true">·</span>
              <span>{ev.component}</span>
              <span aria-hidden="true">·</span>
              <span className="font-mono">{ev.event_type}</span>
            </div>
            <p className="text-sm text-[#0F172A]">{ev.description}</p>
            <p className="font-mono text-xs text-[#475569]">Evidence ref: {ev.evidence_ref}</p>
          </div>
          <StatusBadge label={ev.severity} />
        </li>
      ))}
    </ol>
  );
}
