import { ClubEventCardFull, type ClubEventCardQuery } from "@/components/ui/club-event-card-full";
import { EventSummaryBlock, eventPastFoldableBadges } from "@/components/ui/event-summary";
import type { ClubDetail } from "@/lib/clubs/queries";

type ClubEventPastFoldableProps = {
  club: ClubDetail;
  event: ClubDetail["events"][number];
  query: ClubEventCardQuery;
  memberCount: number;
  now: Date;
  canCreateEvents: boolean;
  canEditEvents: boolean;
  canDeleteEvents: boolean;
  canMarkAttendance: boolean;
  canManageReflections: boolean;
  canViewAggregatedStats: boolean;
};

export function ClubEventPastFoldable(props: ClubEventPastFoldableProps) {
  const { event, canViewAggregatedStats } = props;
  const totalRsvp = event.rsvpCounts.yes + event.rsvpCounts.no + event.rsvpCounts.maybe;
  const turnoutVsRsvpYes =
    event.rsvpCounts.yes > 0 ? Math.min(100, Math.round((event.attendanceCount / event.rsvpCounts.yes) * 100)) : null;

  const supportingRight = canViewAggregatedStats ? (
    <div className="text-xs leading-relaxed text-slate-500 sm:text-right">
      <p>
        <span className="font-semibold text-slate-700">{event.attendanceCount}</span> attended
        {totalRsvp > 0 ? (
          <>
            <span className="text-slate-300"> · </span>
            <span className="font-semibold text-slate-700">{totalRsvp}</span> RSVP
          </>
        ) : null}
      </p>
      {turnoutVsRsvpYes !== null ? (
        <p className="mt-0.5 text-[11px] text-slate-400">~{turnoutVsRsvpYes}% of “yes” checked in</p>
      ) : null}
    </div>
  ) : (
    <div className="text-xs leading-relaxed text-slate-500 sm:text-right">
      <p>
        <span className="font-medium text-slate-700">
          {event.userRsvpStatus ? `RSVP: ${event.userRsvpStatus}` : "No RSVP"}
        </span>
      </p>
      <p className="mt-0.5 text-slate-600">
        {event.userMarkedPresent ? "Marked present" : "Not marked present"}
      </p>
    </div>
  );

  return (
    <details className="event-history-details group rounded-xl border border-slate-200/90 bg-white shadow-sm open:border-slate-300 open:shadow-md">
      <summary className="event-history-summary cursor-pointer list-none p-0 [&::-webkit-details-marker]:hidden">
        <div className="flex flex-col gap-4 p-4 pr-12 transition hover:bg-slate-50/80 active:bg-slate-100/80 sm:flex-row sm:items-start sm:justify-between sm:gap-6 sm:pr-14">
          <div className="min-w-0 flex-1">
            <EventSummaryBlock
              title={event.title}
              titleAs="p"
              titleSize="panel"
              titleAside={eventPastFoldableBadges(Boolean(event.reflection))}
              secondaryLine={event.eventType}
              at={event.eventDateRaw}
              location={event.location}
              metaCompact
              supportingBorder={false}
            />
          </div>

          <div className="flex flex-shrink-0 flex-col gap-2 border-t border-slate-100 pt-3 sm:w-52 sm:border-l sm:border-t-0 sm:pl-5 sm:pt-0">
            {supportingRight}
            <span className="text-xs font-semibold text-blue-600 group-open:hidden sm:text-right">Show details →</span>
            <span className="hidden text-xs font-semibold text-slate-500 group-open:block sm:text-right">Hide details</span>
          </div>
        </div>
      </summary>
      <div className="border-t border-slate-100 px-3 pb-3 pt-2 sm:px-4 sm:pb-4">
        <ClubEventCardFull {...props} as="div" omitPrimaryHeader />
      </div>
    </details>
  );
}
