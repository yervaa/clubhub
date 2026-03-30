import type { ReactNode } from "react";
import Link from "next/link";
import { createEventAction } from "@/app/(app)/clubs/actions";
import { ClubEventCardFull } from "@/components/ui/club-event-card-full";
import { ClubEventPastFoldable } from "@/components/ui/club-event-past-foldable";
import { ScrollToInputButton } from "@/components/ui/scroll-to-input-button";
import { EVENT_TYPE_OPTIONS } from "@/lib/events";
import {
  eventNeedsOfficerReview,
  getEventReviewFlags,
  partitionEventsByLifecycle,
  RECENTLY_HAPPENED_DAYS,
} from "@/lib/clubs/event-lifecycle";
import type { ClubDetail } from "@/lib/clubs/queries";

export type ClubEventsPermissions = {
  canCreateEvents: boolean;
  canMarkAttendance: boolean;
  canManageReflections: boolean;
  /** RSVP/attendance aggregates on past events (operational roles). */
  canViewAggregatedStats: boolean;
  canViewInsights?: boolean;
};

type ClubEventsSectionProps = {
  club: ClubDetail;
  permissions?: ClubEventsPermissions;
  query: {
    eventError?: string;
    eventSuccess?: string;
    duplicateEventId?: string;
    reflectionError?: string;
    reflectionSuccess?: string;
    reflectionEventId?: string;
    rsvpError?: string;
    rsvpSuccess?: string;
    rsvpEventId?: string;
    attendanceError?: string;
    attendanceSuccess?: string;
    attendanceEventId?: string;
    attendanceUserId?: string;
    attendancePresent?: string;
  };
  /** `needs-review` limits lists to items with open follow-ups (officers). */
  listFilter?: "all" | "needs-review";
};

export function ClubEventsSection({ club, query, permissions, listFilter = "all" }: ClubEventsSectionProps) {
  const legacyIsOfficer = club.currentUserRole === "officer";
  const canCreateEvents = permissions?.canCreateEvents ?? legacyIsOfficer;
  const canMarkAttendance = permissions?.canMarkAttendance ?? legacyIsOfficer;
  const canManageReflections = permissions?.canManageReflections ?? legacyIsOfficer;
  const canViewAggregatedStats =
    permissions?.canViewAggregatedStats ??
    (canMarkAttendance || canManageReflections || canCreateEvents);
  const canViewInsights = permissions?.canViewInsights ?? false;

  const memberCount = club.memberCount;
  const duplicateEvent = canCreateEvents && query.duplicateEventId
    ? club.events.find((event) => event.id === query.duplicateEventId) ?? null
    : null;

  const now = new Date();
  const { upcoming, recentlyHappened, past } = partitionEventsByLifecycle(club.events, now);

  const showReviewCues = canViewAggregatedStats && (canMarkAttendance || canManageReflections);

  const cardQuery = {
    reflectionError: query.reflectionError,
    reflectionSuccess: query.reflectionSuccess,
    reflectionEventId: query.reflectionEventId,
    rsvpSuccess: query.rsvpSuccess,
    rsvpEventId: query.rsvpEventId,
    attendanceSuccess: query.attendanceSuccess,
    attendanceEventId: query.attendanceEventId,
    attendanceUserId: query.attendanceUserId,
    attendancePresent: query.attendancePresent,
  };

  const cardPropsBase = {
    club,
    query: cardQuery,
    memberCount,
    now,
    canCreateEvents,
    canMarkAttendance,
    canManageReflections,
    canViewAggregatedStats,
  };

  const filterNeedsReview = listFilter === "needs-review" && showReviewCues;

  const passesNeedsReview = (event: (typeof club.events)[number]) => {
    if (!filterNeedsReview) return true;
    const flags = getEventReviewFlags(event, now, {
      canMarkAttendance,
      canManageReflections,
      memberCount,
    });
    return eventNeedsOfficerReview(flags);
  };

  const upcomingFiltered = upcoming.filter(passesNeedsReview);
  const recentFiltered = recentlyHappened.filter(passesNeedsReview);
  const pastFiltered = past.filter(passesNeedsReview);

  const recentReviewStats = recentlyHappened.reduce(
    (acc, event) => {
      const flags = getEventReviewFlags(event, now, {
        canMarkAttendance,
        canManageReflections,
        memberCount,
      });
      if (flags.needsAttendanceFollowUp) acc.attendance += 1;
      if (flags.needsReflectionFollowUp) acc.reflection += 1;
      if (flags.hasLowRsvpTurnout) acc.lowRsvp += 1;
      return acc;
    },
    { attendance: 0, reflection: 0, lowRsvp: 0 },
  );
  const recentNeedingReview = recentlyHappened.filter((event) =>
    eventNeedsOfficerReview(
      getEventReviewFlags(event, now, {
        canMarkAttendance,
        canManageReflections,
        memberCount,
      }),
    ),
  ).length;

  const sectionShell = (id: string, title: string, subtitle: string, children: ReactNode) => (
    <section id={id} className="scroll-mt-24 space-y-3 lg:space-y-4">
      <div className="flex flex-col gap-0.5 border-b border-slate-200 pb-2 lg:gap-1 lg:pb-3">
        <h2 className="text-base font-bold tracking-tight text-slate-900 lg:text-lg xl:text-xl">{title}</h2>
        <p className="text-xs text-slate-600 lg:text-sm">{subtitle}</p>
      </div>
      {children}
    </section>
  );

  return (
    <div id="events">
      {query.eventSuccess ? <p className="alert-success mt-4">{query.eventSuccess}</p> : null}
      {query.eventError ? <p className="alert-error mt-3">{query.eventError}</p> : null}
      {query.rsvpSuccess ? <p className="alert-success mt-3">{query.rsvpSuccess}</p> : null}
      {query.rsvpError ? <p className="alert-error mt-3">{query.rsvpError}</p> : null}
      {query.attendanceSuccess ? <p className="alert-success mt-3">{query.attendanceSuccess}</p> : null}
      {query.attendanceError ? <p className="alert-error mt-3">{query.attendanceError}</p> : null}

      {filterNeedsReview ? (
        <div className="mt-4 rounded-xl border border-amber-200 bg-amber-50/90 px-4 py-3 text-sm text-amber-950">
          <p className="font-semibold">Filtered: needs follow-up</p>
          <p className="mt-1 text-amber-900/90">Showing events that still need attendance, reflection, or had low RSVP uptake.</p>
          <Link href={`/clubs/${club.id}/events`} className="mt-2 inline-block text-sm font-semibold text-amber-900 underline">
            Clear filter
          </Link>
        </div>
      ) : null}

      {canCreateEvents ? (
        <form id="create-event" action={createEventAction} className="mt-4 space-y-4 rounded-xl border border-slate-200 bg-slate-50/70 p-4 sm:p-5">
          <input type="hidden" name="club_id" value={club.id} />
          {duplicateEvent ? <input type="hidden" name="duplicate_event_id" value={duplicateEvent.id} /> : null}
          <div>
            <p className="text-sm font-semibold text-slate-900">
              {duplicateEvent ? "Create a duplicated draft" : "Schedule a new event"}
            </p>
            <p className="mt-1 text-sm text-slate-600">
              {duplicateEvent
                ? "Title, description, location, and event type were copied from an existing event. Choose a new date and time before creating."
                : "Create a clear event card members can respond to quickly."}
            </p>
          </div>
          {duplicateEvent ? (
            <div className="rounded-xl border border-blue-200 bg-blue-50/80 p-4">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <p className="text-sm font-semibold text-slate-900">Duplicating: {duplicateEvent.title}</p>
                  <p className="mt-1 text-sm text-slate-600">This draft starts from the selected event, but the new event date must be chosen again.</p>
                </div>
                <Link
                  href={`/clubs/${club.id}/events`}
                  className="btn-secondary flex min-h-11 w-full items-center justify-center whitespace-nowrap text-xs sm:min-h-0 sm:w-auto"
                >
                  Clear draft
                </Link>
              </div>
            </div>
          ) : null}
          <div>
            <label htmlFor="event_title" className="mb-1.5 block text-sm font-medium text-slate-700">
              Title
            </label>
            <input
              id="event_title"
              name="title"
              type="text"
              required
              defaultValue={duplicateEvent?.title ?? ""}
              className="input-control min-h-11 sm:min-h-0"
              placeholder="Event title"
            />
          </div>
          <div>
            <label htmlFor="event_type" className="mb-1.5 block text-sm font-medium text-slate-700">
              Event type
            </label>
            <select
              id="event_type"
              name="event_type"
              required
              defaultValue={duplicateEvent?.eventType ?? "Meeting"}
              className="input-control min-h-11 sm:min-h-0"
            >
              {EVENT_TYPE_OPTIONS.map((eventType) => (
                <option key={eventType} value={eventType}>
                  {eventType}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="event_description" className="mb-1.5 block text-sm font-medium text-slate-700">
              Description
            </label>
            <textarea
              id="event_description"
              name="description"
              rows={3}
              required
              defaultValue={duplicateEvent?.description ?? ""}
              className="textarea-control min-h-[5.5rem] text-base sm:text-sm"
              placeholder="Describe the event..."
            />
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <label htmlFor="event_location" className="mb-1.5 block text-sm font-medium text-slate-700">
                Location
              </label>
              <input
                id="event_location"
                name="location"
                type="text"
                required
                defaultValue={duplicateEvent?.location ?? ""}
                className="input-control min-h-11 sm:min-h-0"
                placeholder="Room 204"
              />
            </div>
            <div>
              <label htmlFor="event_date" className="mb-1.5 block text-sm font-medium text-slate-700">
                {duplicateEvent ? "New event date" : "Event date"}
              </label>
              <input id="event_date" name="event_date" type="datetime-local" required className="input-control" />
              {duplicateEvent ? <p className="mt-1 text-xs text-slate-500">Choose a fresh date and time for the duplicated event.</p> : null}
            </div>
          </div>
          <button type="submit" className="btn-primary min-h-11 w-full sm:min-h-0 sm:w-auto">
            {duplicateEvent ? "Create duplicated event" : "Create event"}
          </button>
        </form>
      ) : null}

      {club.events.length === 0 ? (
        <div className="mt-4 rounded-lg border border-slate-200 bg-gradient-to-br from-indigo-50 to-slate-50 p-6">
          <p className="font-semibold text-slate-900">Schedule your first meeting</p>
          <p className="mt-1 text-sm text-slate-600">Create an event so members know when you&#39;re meeting and can RSVP.</p>
          {canCreateEvents && (
            <ScrollToInputButton inputSelector='input[id="event_title"]' className="btn-secondary mt-3">
              Create First Event
            </ScrollToInputButton>
          )}
        </div>
      ) : (
        <div className="list-stack mt-8 space-y-12">
          {showReviewCues && recentNeedingReview > 0 && !filterNeedsReview ? (
            <div className="rounded-xl border border-amber-200 bg-gradient-to-br from-amber-50 to-orange-50/60 p-5 shadow-sm">
              <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                <div>
                  <p className="text-sm font-bold uppercase tracking-wider text-amber-900">Recently happened — follow-up</p>
                  <p className="mt-1 text-sm text-amber-950/90">
                    {recentNeedingReview} event{recentNeedingReview === 1 ? "" : "s"} in the last {RECENTLY_HAPPENED_DAYS} days may need your attention.
                  </p>
                  <ul className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs font-medium text-amber-900/85">
                    {recentReviewStats.attendance > 0 ? <li>{recentReviewStats.attendance} without attendance recorded</li> : null}
                    {recentReviewStats.reflection > 0 ? <li>{recentReviewStats.reflection} without a reflection</li> : null}
                    {recentReviewStats.lowRsvp > 0 ? <li>{recentReviewStats.lowRsvp} with low RSVP turnout</li> : null}
                  </ul>
                </div>
                <Link
                  href={`/clubs/${club.id}/events?filter=needs-review#recent`}
                  className="btn-secondary flex min-h-11 w-full shrink-0 items-center justify-center border-amber-300 bg-white text-amber-950 hover:bg-amber-50 sm:min-h-0 sm:w-auto"
                >
                  View needs review
                </Link>
              </div>
            </div>
          ) : null}

          {sectionShell(
            "upcoming",
            "Upcoming",
            "Events scheduled in the future — RSVP and prepare ahead of time.",
            upcomingFiltered.length === 0 ? (
              <p className="rounded-lg border border-dashed border-slate-200 bg-slate-50/80 px-4 py-6 text-center text-sm text-slate-600">
                No upcoming events. {canCreateEvents ? "Schedule the next club touchpoint above." : "Check back when officers add the next date."}
              </p>
            ) : (
              <div className="space-y-4">
                {upcomingFiltered.map((event) => (
                  <ClubEventCardFull key={event.id} {...cardPropsBase} event={event} />
                ))}
              </div>
            ),
          )}

          {sectionShell(
            "recent",
            "Recently happened",
            `Ended in the last ${RECENTLY_HAPPENED_DAYS} days — finish attendance, reflections, and quick review while it is fresh.`,
            recentFiltered.length === 0 ? (
              <p className="rounded-lg border border-dashed border-slate-200 bg-slate-50/80 px-4 py-6 text-center text-sm text-slate-600">
                {filterNeedsReview
                  ? "No recent events match this filter."
                  : "No events in the recent window. Past events move here right after they end."}
              </p>
            ) : (
              <div className="space-y-4">
                {recentFiltered.map((event) => {
                  const flags = getEventReviewFlags(event, now, {
                    canMarkAttendance,
                    canManageReflections,
                    memberCount,
                  });
                  return (
                    <div key={event.id} className="space-y-2">
                      {showReviewCues && eventNeedsOfficerReview(flags) ? (
                        <div className="flex flex-wrap gap-2 rounded-lg border border-amber-100 bg-amber-50/50 px-3 py-2 text-xs font-medium text-amber-950">
                          {flags.needsAttendanceFollowUp ? (
                            <span className="rounded-full bg-white px-2 py-0.5 ring-1 ring-amber-200">Attendance not recorded</span>
                          ) : null}
                          {flags.needsReflectionFollowUp ? (
                            <span className="rounded-full bg-white px-2 py-0.5 ring-1 ring-amber-200">No reflection yet</span>
                          ) : null}
                          {flags.hasLowRsvpTurnout ? (
                            <span className="rounded-full bg-white px-2 py-0.5 ring-1 ring-amber-200">Low RSVP turnout</span>
                          ) : null}
                        </div>
                      ) : null}
                      <ClubEventCardFull {...cardPropsBase} event={event} />
                    </div>
                  );
                })}
              </div>
            ),
          )}

          {sectionShell(
            "history",
            "Past events",
            "Older completed events — expand a row for full detail, RSVP context, and officer tools.",
            pastFiltered.length === 0 ? (
              <p className="rounded-lg border border-dashed border-slate-200 bg-slate-50/80 px-4 py-6 text-center text-sm text-slate-600">
                {filterNeedsReview ? "No older past events match this filter." : "No older events in this club yet."}
              </p>
            ) : (
              <div className="space-y-3">
                {pastFiltered.slice(0, 25).map((event) => (
                  <ClubEventPastFoldable key={event.id} {...cardPropsBase} event={event} />
                ))}
                {pastFiltered.length > 25 ? (
                  <p className="text-center text-sm text-slate-600">
                    Showing 25 of {pastFiltered.length} past events.{" "}
                    <Link href={`/clubs/${club.id}/events/history`} className="font-semibold text-blue-700 underline">
                      Open full event history
                    </Link>
                    {canViewInsights ? (
                      <>
                        {" "}
                        ·{" "}
                        <Link href={`/clubs/${club.id}/insights`} className="font-semibold text-blue-700 underline">
                          Club insights
                        </Link>
                      </>
                    ) : null}
                  </p>
                ) : (
                  <p className="text-center text-sm text-slate-500">
                    <Link href={`/clubs/${club.id}/events/history`} className="font-semibold text-blue-700 underline">
                      Full event history
                    </Link>
                    {canViewInsights ? (
                      <>
                        {" "}
                        ·{" "}
                        <Link href={`/clubs/${club.id}/insights`} className="font-semibold text-blue-700 underline">
                          Club insights
                        </Link>
                      </>
                    ) : null}
                  </p>
                )}
              </div>
            ),
          )}
        </div>
      )}
    </div>
  );
}
