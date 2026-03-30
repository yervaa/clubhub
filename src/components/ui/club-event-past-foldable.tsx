import { ClubEventCardFull, type ClubEventCardQuery } from "@/components/ui/club-event-card-full";
import type { ClubDetail } from "@/lib/clubs/queries";

type ClubEventPastFoldableProps = {
  club: ClubDetail;
  event: ClubDetail["events"][number];
  query: ClubEventCardQuery;
  memberCount: number;
  now: Date;
  canCreateEvents: boolean;
  canMarkAttendance: boolean;
  canManageReflections: boolean;
  canViewAggregatedStats: boolean;
};

export function ClubEventPastFoldable(props: ClubEventPastFoldableProps) {
  const { event, canViewAggregatedStats } = props;
  const totalRsvp = event.rsvpCounts.yes + event.rsvpCounts.no + event.rsvpCounts.maybe;
  const turnoutVsRsvpYes =
    event.rsvpCounts.yes > 0 ? Math.min(100, Math.round((event.attendanceCount / event.rsvpCounts.yes) * 100)) : null;

  return (
    <details className="event-history-details group rounded-xl border border-slate-200/90 bg-white shadow-sm open:border-slate-300 open:shadow-md">
      <summary className="event-history-summary flex min-h-[3.5rem] cursor-pointer list-none flex-col gap-3 p-4 pb-4 pr-12 transition hover:bg-slate-50/80 active:bg-slate-100/80 [&::-webkit-details-marker]:hidden sm:min-h-0 sm:gap-2 sm:pb-4">
        <div className="flex flex-wrap items-center gap-2">
          <span className="event-type-pill text-xs">{event.eventType}</span>
          <span className="badge-soft text-[10px]">Past</span>
          {event.reflection ? (
            <span className="inline-flex items-center rounded-full bg-emerald-50 px-2 py-0.5 text-[10px] font-semibold text-emerald-800 ring-1 ring-emerald-200/80">
              Reflection
            </span>
          ) : (
            <span className="inline-flex items-center rounded-full bg-amber-50 px-2 py-0.5 text-[10px] font-semibold text-amber-900 ring-1 ring-amber-200/70">
              No reflection
            </span>
          )}
        </div>
        <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-end sm:justify-between">
          <div className="min-w-0">
            <p className="break-words font-semibold text-slate-900">{event.title}</p>
            <p className="mt-0.5 text-sm text-slate-600">{event.eventDate}</p>
            <p className="mt-1 break-words text-xs text-slate-500">{event.location}</p>
          </div>
          <div className="text-left text-xs text-slate-500 sm:text-right">
            {canViewAggregatedStats ? (
              <p>
                <span className="font-medium text-slate-700">{event.attendanceCount}</span> attended
                {totalRsvp > 0 ? (
                  <>
                    {" "}
                    · <span className="font-medium text-slate-700">{totalRsvp}</span> RSVP
                    {turnoutVsRsvpYes !== null ? (
                      <span className="block text-[10px] text-slate-400">~{turnoutVsRsvpYes}% of “yes” checked in</span>
                    ) : null}
                  </>
                ) : null}
              </p>
            ) : (
              <p>
                {event.userRsvpStatus ? `Your RSVP: ${event.userRsvpStatus}` : "No RSVP on file"}
                <span className="mt-0.5 block text-slate-600">
                  {event.userMarkedPresent ? "You were marked present" : "Not marked present"}
                </span>
              </p>
            )}
            <span className="mt-2 inline-block min-h-9 rounded-lg py-2 text-[11px] font-semibold uppercase tracking-wider text-blue-600 group-open:hidden sm:min-h-0 sm:py-0">
              Show details
            </span>
            <span className="mt-2 hidden min-h-9 rounded-lg py-2 text-[11px] font-semibold uppercase tracking-wider text-slate-500 group-open:inline-block sm:min-h-0 sm:py-0">
              Hide details
            </span>
          </div>
        </div>
      </summary>
      <div className="border-t border-slate-100 px-2 pb-3 pt-2 sm:pb-2 sm:pt-1">
        <ClubEventCardFull {...props} as="div" omitPrimaryHeader />
      </div>
    </details>
  );
}
