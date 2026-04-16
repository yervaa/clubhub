import Link from "next/link";
import { saveEventReflectionAction } from "@/app/(app)/clubs/actions";
import { AttendanceChecklist } from "@/components/ui/attendance-checklist";
import { DisclosurePanel } from "@/components/ui/disclosure-panel";
import { EventRsvpControls } from "@/components/ui/event-rsvp-controls";
import { EventManagementControls } from "@/components/ui/event-management-controls";
import { EventSummaryBlock, eventLifecycleBadges } from "@/components/ui/event-summary";
import type { ClubDetail } from "@/lib/clubs/queries";

export type ClubEventCardQuery = {
  reflectionError?: string;
  reflectionSuccess?: string;
  reflectionEventId?: string;
  rsvpSuccess?: string;
  rsvpEventId?: string;
  attendanceSuccess?: string;
  attendanceEventId?: string;
  attendanceUserId?: string;
  attendancePresent?: string;
};

type ClubEventCardFullProps = {
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
  /** Club-wide RSVP/attendance metrics (RBAC: officers with operational permissions). */
  canViewAggregatedStats: boolean;
  /** Use `div` when nested (e.g. inside outer &lt;details&gt;) to avoid duplicate landmark articles. */
  as?: "article" | "div";
  /**
   * When true, skip the hero header (title, date, badges) — used inside past-event foldables
   * that already show a summary row.
   */
  omitPrimaryHeader?: boolean;
};

export function ClubEventCardFull({
  club,
  event,
  query,
  memberCount,
  now,
  canCreateEvents,
  canEditEvents,
  canDeleteEvents,
  canMarkAttendance,
  canManageReflections,
  canViewAggregatedStats,
  as = "article",
  omitPrimaryHeader = false,
}: ClubEventCardFullProps) {
  const timeDiff = event.eventDateRaw.getTime() - now.getTime();
  const hoursDiff = timeDiff / (1000 * 60 * 60);
  const isComingSoon = hoursDiff > 0 && hoursDiff <= 48;
  const isToday = event.eventDateRaw.toDateString() === now.toDateString();
  const isPast = event.eventDateRaw.getTime() < now.getTime();
  const totalResponses = event.rsvpCounts.yes + event.rsvpCounts.no + event.rsvpCounts.maybe;
  const totalResponsesWithWaitlist = totalResponses + event.rsvpCounts.waitlist;
  const activeMembersForAttendance = club.members.filter((m) => m.membershipStatus === "active");
  const unmarkedActiveCount = activeMembersForAttendance.filter(
    (m) => !event.presentMemberIds.includes(m.userId),
  ).length;

  const responsePercent = memberCount > 0 ? Math.min(100, Math.round((totalResponsesWithWaitlist / memberCount) * 100)) : 0;
  const goingPercent = memberCount > 0 ? Math.min(100, Math.round((event.rsvpCounts.yes / memberCount) * 100)) : 0;
  const goingLabel = event.rsvpCounts.yes === 1 ? "person going" : "people going";
  const waitlistLabel = event.rsvpCounts.waitlist === 1 ? "person waitlisted" : "people waitlisted";
  const memberNameById = new Map(
    club.members.map((member) => [
      member.userId,
      member.fullName?.trim() || member.email || "Member",
    ]),
  );
  const goingNames = event.goingMemberIds
    .map((memberId) => memberNameById.get(memberId))
    .filter((name): name is string => Boolean(name))
    .slice(0, 4);
  const goingOverflow = Math.max(0, event.rsvpCounts.yes - goingNames.length);
  const eventRsvpSaved = query.rsvpSuccess && query.rsvpEventId === event.id;
  const eventAttendanceSaved = query.attendanceSuccess && query.attendanceEventId === event.id;
  const eventReflectionSaved = query.reflectionSuccess && query.reflectionEventId === event.id;
  const eventReflectionError = query.reflectionError && query.reflectionEventId === event.id;
  const responseYesWidth = totalResponses > 0 ? `${(event.rsvpCounts.yes / totalResponses) * 100}%` : "0%";
  const responseMaybeWidth = totalResponses > 0 ? `${(event.rsvpCounts.maybe / totalResponses) * 100}%` : "0%";
  const responseNoWidth = totalResponses > 0 ? `${(event.rsvpCounts.no / totalResponses) * 100}%` : "0%";

  const showClubMetrics = canViewAggregatedStats || !isPast;
  const Root = as === "article" ? "article" : "div";

  const reflectionOpenDefault = Boolean(eventReflectionError || eventReflectionSaved);

  const hasFeedbackStrip = Boolean(eventAttendanceSaved || eventReflectionSaved);

  const showOrganizerTools =
    canMarkAttendance ||
    canManageReflections ||
    canViewAggregatedStats ||
    canCreateEvents ||
    canEditEvents ||
    canDeleteEvents;

  const organizerSubtitle = showClubMetrics
    ? memberCount > 0
      ? `${totalResponses} of ${memberCount} responded · attendance, reflections, full metrics`
      : "Attendance, reflections, and engagement metrics"
    : "RSVP context, description, and officer tools";

  const organizerDefaultOpen =
    omitPrimaryHeader && (reflectionOpenDefault || Boolean(eventAttendanceSaved));

  const trimmedDescription = event.description?.trim() ?? "";
  const hasDescription = Boolean(trimmedDescription);
  const showMemberEventDetails = hasDescription && !showOrganizerTools;

  return (
    <Root id={omitPrimaryHeader ? undefined : `event-${event.id}`} className="event-card">
      {!omitPrimaryHeader ? (
        <>
          {hasFeedbackStrip ? (
            <div
              className="mb-4 flex flex-wrap gap-x-3 gap-y-1 rounded-lg border border-emerald-200/80 bg-emerald-50/70 px-3 py-2 text-xs font-medium text-emerald-900"
              role="status"
            >
              {eventAttendanceSaved ? <span>Attendance updated</span> : null}
              {eventReflectionSaved ? <span>Reflection saved</span> : null}
            </div>
          ) : null}

          <EventSummaryBlock
            title={event.title}
            titleAs="h3"
            titleSize="panel"
            titleAside={eventLifecycleBadges({
              isPast,
              isToday,
              isComingSoon,
              hasReflection: Boolean(event.reflection),
            })}
            secondaryLine={event.eventType}
            at={event.eventDateRaw}
            location={event.location}
            metaCompact
            supportingBorder={false}
          />
          {event.seriesId ? (
            <p className="mt-2 text-xs font-medium text-indigo-700">
              Recurring series{event.seriesOccurrence ? ` · Occurrence ${event.seriesOccurrence}` : ""}
            </p>
          ) : null}

          {isPast ? (
            <p className="mt-3 text-sm text-slate-600">
              <span className="font-medium text-slate-800">Your RSVP:</span>{" "}
              {event.userRsvpStatus ?? "—"}
              <span className="text-slate-300"> · </span>
              <span className="font-medium text-slate-800">Attendance:</span>{" "}
              {event.userMarkedPresent ? "Present" : "Not marked"}
            </p>
          ) : null}

          {!isPast ? (
            <div className="event-rsvp-anchor mt-5 border-t border-slate-100 pt-5">
              <h4 className="text-sm font-semibold text-slate-900">RSVP</h4>
              <p className="mt-0.5 text-xs text-slate-500">You can change your response anytime before the event.</p>
              <div className="mt-3">
                <EventRsvpControls
                  clubId={club.id}
                  eventId={event.id}
                  selectedStatus={event.userRsvpStatus}
                  recentlySaved={Boolean(eventRsvpSaved)}
                  embedded
                />
              </div>
              <div className="mt-3 rounded-lg border border-slate-200 bg-slate-50/80 px-3 py-2.5">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Engagement</p>
                <p className="mt-1 text-sm font-semibold text-slate-900">
                  {event.rsvpCounts.yes} {goingLabel}
                </p>
                {event.rsvpCounts.waitlist > 0 ? (
                  <p className="mt-0.5 text-xs text-amber-700">
                    {event.rsvpCounts.waitlist} {waitlistLabel}
                  </p>
                ) : null}
                {event.capacity != null ? (
                  <p className="mt-0.5 text-xs text-slate-600">
                    {event.confirmedYesCount} / {event.capacity} confirmed
                    {event.isOverCapacity ? " · Over capacity" : event.capacityRemaining === 0 ? " · Full" : ""}
                  </p>
                ) : null}
                {goingNames.length > 0 ? (
                  <p className="mt-0.5 text-xs text-slate-600">
                    Going: {goingNames.join(", ")}
                    {goingOverflow > 0 ? ` +${goingOverflow} more` : ""}
                  </p>
                ) : (
                  <p className="mt-0.5 text-xs text-slate-500">No one has RSVP&apos;d yes yet.</p>
                )}
              </div>
            </div>
          ) : null}
        </>
      ) : (
        <p className="text-xs text-slate-500">
          Full details, metrics, and organizer tools are in the sections below.
        </p>
      )}

      <div className={omitPrimaryHeader ? "mt-2 space-y-3" : "mt-5 space-y-3"}>
        {showMemberEventDetails ? (
          <DisclosurePanel title="Event details" subtitle="Description">
            <p className="text-sm leading-6 text-slate-700">{trimmedDescription}</p>
          </DisclosurePanel>
        ) : null}

        {showOrganizerTools ? (
          <DisclosurePanel
            title="Organizer tools"
            subtitle={organizerSubtitle}
            badge={
              <span className="rounded-md bg-slate-100 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-slate-500">
                Advanced
              </span>
            }
            defaultOpen={organizerDefaultOpen}
          >
            <div className="space-y-6">
              {canCreateEvents ? (
                <div>
                  <Link
                    href={`/clubs/${club.id}/events?duplicateEventId=${event.id}#create-event`}
                    className="btn-secondary inline-flex min-h-10 w-full items-center justify-center text-xs sm:w-auto"
                  >
                    Duplicate event
                  </Link>
                </div>
              ) : null}

              {canEditEvents || canDeleteEvents ? (
                <EventManagementControls
                  clubId={club.id}
                  eventId={event.id}
                  title={event.title}
                  description={event.description}
                  location={event.location}
                  eventType={event.eventType}
                  capacity={event.capacity}
                  eventDateIso={event.eventDateRaw.toISOString()}
                  seriesId={event.seriesId}
                  seriesOccurrence={event.seriesOccurrence}
                  canEditEvents={canEditEvents}
                  canDeleteEvents={canDeleteEvents}
                />
              ) : null}

              {hasDescription ? (
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Description</p>
                  <p className="mt-2 text-sm leading-6 text-slate-700">{trimmedDescription}</p>
                </div>
              ) : null}

              <div className="event-meta-grid">
                <div className="event-meta-item">
                  <span className="event-meta-label">Location</span>
                  <span className="event-meta-value">{event.location || "—"}</span>
                </div>
                {showClubMetrics ? (
                  <div className="event-meta-item">
                    <span className="event-meta-label">Response rate</span>
                    <span className="event-meta-value">
                      {memberCount > 0 ? `${responsePercent}% of members` : "No members yet"}
                    </span>
                  </div>
                ) : (
                  <div className="event-meta-item">
                    <span className="event-meta-label">Your RSVP</span>
                    <span className="event-meta-value">
                      {event.userRsvpStatus === "waitlist"
                        ? `You are waitlisted${event.userWaitlistPosition ? ` (#${event.userWaitlistPosition})` : ""}`
                        : event.userRsvpStatus
                          ? `You replied: ${event.userRsvpStatus}`
                          : "You did not RSVP"}
                    </span>
                  </div>
                )}
                {event.capacity != null ? (
                  <div className="event-meta-item">
                    <span className="event-meta-label">Capacity</span>
                    <span className="event-meta-value">
                      {event.confirmedYesCount}/{event.capacity} confirmed
                      {event.rsvpCounts.waitlist > 0 ? ` · ${event.rsvpCounts.waitlist} waitlisted` : ""}
                      {event.isOverCapacity ? " · Over capacity" : ""}
                    </span>
                  </div>
                ) : null}
                {isPast ? (
                  <div className="event-meta-item">
                    <span className="event-meta-label">Your attendance</span>
                    <span className="event-meta-value">
                      {event.userMarkedPresent ? "Marked present" : "Not marked present"}
                    </span>
                  </div>
                ) : null}
              </div>

              {showClubMetrics ? (
                <>
                  <div className="event-metrics-grid">
                    <div className="event-metric-card">
                      <p className="event-metric-label">Going</p>
                      <p className="event-metric-value">
                        {event.rsvpCounts.yes} {goingLabel}
                      </p>
                      <p className="event-metric-copy">
                        {memberCount > 0 ? `${goingPercent}% of the club so far` : "Waiting for members"}
                      </p>
                    </div>
                    <div className="event-metric-card">
                      <p className="event-metric-label">Engagement</p>
                      <p className="event-metric-value">
                        {event.rsvpCounts.yes + event.rsvpCounts.maybe >= 5
                          ? "Strong"
                          : event.rsvpCounts.yes + event.rsvpCounts.maybe >= 2
                            ? "Building"
                            : "Early"}
                      </p>
                      <p className="event-metric-copy">Based on yes + maybe responses</p>
                    </div>
                    <div className="event-metric-card">
                      <p className="event-metric-label">Attendance</p>
                      <p className="event-metric-value">{event.attendanceCount} present</p>
                      <p className="event-metric-copy">Checked in during the event</p>
                    </div>
                  </div>
                  <div className="event-progress-panel">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div>
                        <p className="text-sm font-semibold text-slate-900">Participation</p>
                        <p className="mt-1 text-sm text-slate-600">
                          {memberCount > 0
                            ? `${totalResponsesWithWaitlist} of ${memberCount} ${memberCount === 1 ? "member" : "members"} responded`
                            : "Waiting for members to join this club."}
                        </p>
                      </div>
                      <span className="rounded-md bg-white px-2.5 py-1 text-xs font-medium text-slate-600 ring-1 ring-slate-200/80">
                        {event.rsvpCounts.yes} yes · {event.rsvpCounts.maybe} maybe · {event.rsvpCounts.no} no
                        {event.rsvpCounts.waitlist > 0 ? ` · ${event.rsvpCounts.waitlist} waitlist` : ""}
                      </span>
                    </div>
                    <div className="event-progress-bar mt-4" aria-hidden="true">
                      <div className="event-progress-segment event-progress-yes" style={{ width: responseYesWidth }} />
                      <div
                        className="event-progress-segment event-progress-maybe"
                        style={{ width: responseMaybeWidth }}
                      />
                      <div className="event-progress-segment event-progress-no" style={{ width: responseNoWidth }} />
                    </div>
                    <p className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500">
                      <span className="inline-flex items-center gap-1.5">
                        <span className="h-2 w-2 shrink-0 rounded-full bg-emerald-500" aria-hidden />
                        Yes
                      </span>
                      <span className="inline-flex items-center gap-1.5">
                        <span className="h-2 w-2 shrink-0 rounded-full bg-amber-400" aria-hidden />
                        Maybe
                      </span>
                      <span className="inline-flex items-center gap-1.5">
                        <span className="h-2 w-2 shrink-0 rounded-full bg-rose-400" aria-hidden />
                        No
                      </span>
                    </p>
                  </div>
                </>
              ) : null}

              {canMarkAttendance ? (
                <div className="border-t border-slate-200 pt-4">
                  <p className="text-sm font-semibold text-slate-900">Mark attendance</p>
                  <p className="mt-0.5 text-xs text-slate-500">
                    {event.attendanceCount} marked present · {unmarkedActiveCount} unmarked in checklist
                  </p>
                  <div className="mt-3">
                    <AttendanceChecklist
                      clubId={club.id}
                      eventId={event.id}
                      members={activeMembersForAttendance}
                      presentMemberIds={event.presentMemberIds}
                      currentUserId={club.currentUserId}
                      recentlySavedUserId={query.attendanceEventId === event.id ? query.attendanceUserId : undefined}
                      recentlySavedPresent={
                        query.attendanceEventId === event.id ? query.attendancePresent === "true" : undefined
                      }
                      embedded
                    />
                  </div>
                </div>
              ) : null}

              {isPast && canManageReflections ? (
                <div className="border-t border-slate-200 pt-4">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="text-sm font-semibold text-slate-900">Officer reflection</p>
                    {event.reflection ? (
                      <span className="rounded-md bg-emerald-100 px-2 py-0.5 text-[10px] font-semibold text-emerald-800">
                        Saved
                      </span>
                    ) : (
                      <span className="rounded-md bg-amber-100 px-2 py-0.5 text-[10px] font-semibold text-amber-900">
                        Draft
                      </span>
                    )}
                  </div>
                  <p className="mt-0.5 text-xs text-slate-500">
                    {event.reflection
                      ? `Last updated ${event.reflection.updatedAt}`
                      : "Capture what worked and what to improve for next time."}
                  </p>
                  {eventReflectionError ? <p className="alert-error mt-3">{query.reflectionError}</p> : null}
                  {!event.reflection ? (
                    <div className="mt-3 rounded-xl border border-slate-200 bg-white p-4">
                      <p className="text-sm font-semibold text-slate-900">Add a quick post-event note</p>
                      <p className="mt-1 text-sm text-slate-600">No reflection has been saved for this event yet.</p>
                    </div>
                  ) : (
                    <div className="mt-3 grid gap-3 md:grid-cols-2">
                      <div className="rounded-xl border border-emerald-200 bg-emerald-50/70 p-4">
                        <p className="stat-label text-emerald-700">What worked</p>
                        <p className="mt-2 text-sm leading-6 text-slate-700">{event.reflection.whatWorked}</p>
                      </div>
                      <div className="rounded-xl border border-rose-200 bg-rose-50/70 p-4">
                        <p className="stat-label text-rose-700">What didn&#39;t</p>
                        <p className="mt-2 text-sm leading-6 text-slate-700">{event.reflection.whatDidnt}</p>
                      </div>
                      {event.reflection.notes ? (
                        <div className="rounded-xl border border-slate-200 bg-white p-4 md:col-span-2">
                          <p className="stat-label">Notes</p>
                          <p className="mt-2 text-sm leading-6 text-slate-700">{event.reflection.notes}</p>
                        </div>
                      ) : null}
                    </div>
                  )}
                  <form action={saveEventReflectionAction} className="mt-4 space-y-3">
                    <input type="hidden" name="club_id" value={club.id} />
                    <input type="hidden" name="event_id" value={event.id} />
                    <div>
                      <label htmlFor={`reflection_worked_${event.id}`} className="mb-1.5 block text-sm font-medium text-slate-700">
                        What worked
                      </label>
                      <textarea
                        id={`reflection_worked_${event.id}`}
                        name="what_worked"
                        rows={3}
                        required
                        defaultValue={event.reflection?.whatWorked ?? ""}
                        className="textarea-control"
                        placeholder="What went well at this event?"
                      />
                    </div>
                    <div>
                      <label htmlFor={`reflection_didnt_${event.id}`} className="mb-1.5 block text-sm font-medium text-slate-700">
                        What didn&#39;t
                      </label>
                      <textarea
                        id={`reflection_didnt_${event.id}`}
                        name="what_didnt"
                        rows={3}
                        required
                        defaultValue={event.reflection?.whatDidnt ?? ""}
                        className="textarea-control"
                        placeholder="What should be improved next time?"
                      />
                    </div>
                    <div>
                      <label htmlFor={`reflection_notes_${event.id}`} className="mb-1.5 block text-sm font-medium text-slate-700">
                        Notes
                      </label>
                      <textarea
                        id={`reflection_notes_${event.id}`}
                        name="notes"
                        rows={3}
                        defaultValue={event.reflection?.notes ?? ""}
                        className="textarea-control"
                        placeholder="Optional details, ideas, or follow-ups."
                      />
                    </div>
                    <button type="submit" className="btn-primary">
                      {event.reflection ? "Update reflection" : "Save reflection"}
                    </button>
                  </form>
                </div>
              ) : null}
            </div>
          </DisclosurePanel>
        ) : null}

        {omitPrimaryHeader && !showOrganizerTools && hasDescription ? (
          <DisclosurePanel title="Event details" subtitle="Description">
            <p className="text-sm leading-6 text-slate-700">{trimmedDescription}</p>
          </DisclosurePanel>
        ) : null}
      </div>
    </Root>
  );
}
