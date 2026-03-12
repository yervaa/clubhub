import type { MockEvent } from "@/lib/mock-data";

type EventCardProps = {
  event: MockEvent;
};

export function EventCard({ event }: EventCardProps) {
  return (
    <article className="rounded-xl border border-slate-200 bg-white p-5">
      <p className="text-xs font-semibold uppercase tracking-[0.08em] text-slate-500">{event.clubName}</p>
      <h3 className="mt-2 text-base font-semibold text-slate-900">{event.title}</h3>
      <p className="mt-2 text-sm text-slate-600">{event.description}</p>
      <div className="mt-4 space-y-1 text-sm text-slate-600">
        <p>{event.eventDate}</p>
        <p>{event.location}</p>
      </div>
      <p className="mt-3 text-xs font-medium uppercase tracking-[0.08em] text-slate-500">
        {event.rsvpSummary}
      </p>
    </article>
  );
}
