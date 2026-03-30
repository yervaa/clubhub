import Link from "next/link";
import { saveEventReflectionAction } from "@/app/(app)/clubs/actions";
import { AttendanceChecklist } from "@/components/ui/attendance-checklist";
import { DisclosurePanel } from "@/components/ui/disclosure-panel";
import { EventRsvpControls } from "@/components/ui/event-rsvp-controls";
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
  const responsePercent = memberCount > 0 ? Math.min(100, Math.round((totalResponses / memberCount) * 100)) : 0;
  const goingPercent = memberCount > 0 ? Math.min(100, Math.round((event.rsvpCounts.yes / memberCount) * 100)) : 0;
  const goingLabel = event.rsvpCounts.yes === 1 ? "person going" : "people going";
  const responseLabel = totalResponses === 1 ? "response" : "responses";
  const eventRsvpSaved = query.rsvpSuccess && query.rsvpEventId === event.id;
  const eventAttendanceSaved = query.attendanceSuccess && query.attendanceEventId === event.id;
  const eventReflectionSaved = query.reflectionSuccess && query.reflectionEventId === event.id;
  const eventReflectionError = query.reflectionError && query.reflectionEventId === event.id;
  const responseYesWidth = totalResponses > 0 ? `${(event.rsvpCounts.yes / totalResponses) * 100}%` : "0%";
  const responseMaybeWidth = totalResponses > 0 ? `${(event.rsvpCounts.maybe / totalResponses) * 100}%` : "0%";
  const responseNoWidth = totalResponses > 0 ? `${(event.rsvpCounts.no / totalResponses) * 100}%` : "0%";

  const showClubMetrics = canViewAggregatedStats || !isPast;
  const Root = as === "article" ? "article" : "div";

  const participationSubtitle = showClubMetrics
    ? memberCount > 0
      ? `${totalResponses} of ${memberCount} responded · ${event.rsvpCounts.yes} yes / ${event.rsvpCounts.maybe} maybe / ${event.rsvpCounts.no} no`
      : "Response breakdown and engagement metrics"
    : "Full description and your RSVP context";

  const reflectionOpenDefault = Boolean(eventReflectionError || eventReflectionSaved);

  return (
    <Root id={omitPrimaryHeader ? undefined : `event-${event.id}`} className="event-card">
      {!omitPrimaryHeader ? (
        <>
          <div className="flex flex-col gap-4 sm:flex-row sm:flex-wrap sm:items-start sm:justify-between">
            <div className="min-w-0 max-w-2xl flex-1 space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="event-type-pill">{event.eventType}</span>
                <span className="badge-soft">{isPast ? "Completed" : isToday ? "Today" : "Upcoming"}</span>
                {isComingSoon && (
                  <span className="inline-flex items-center rounded-full bg-orange-100 px-2.5 py-1 text-xs font-semibold text-orange-800">
                    Coming Soon
                  </span>
                )}
                {eventRsvpSaved ? <span className="feedback-pill feedback-pill-success">RSVP saved</span> : null}
                {eventAttendanceSaved ? <span className="feedback-pill feedback-pill-success">Attendance updated</span> : null}
                {eventReflectionSaved ? <span className="feedback-pill feedback-pill-success">Reflection saved</span> : null}
                {isPast && event.reflection ? (
                  <span className="inline-flex items-center rounded-full bg-emerald-100 px-2.5 py-1 text-xs font-semibold text-emerald-800">
                    Reflection recorded
                  </span>
                ) : null}
              </div>
              <div>
                <h4 className="text-lg font-semibold tracking-tight text-slate-950 sm:text-xl">{event.title}</h4>
                <p className="mt-1 text-base font-medium text-slate-700">{event.eventDate}</p>
                <p className="mt-1 text-sm text-slate-600">{event.location}</p>
                {event.description ? (
                  <p className="mt-2 line-clamp-3 text-sm leading-relaxed text-slate-600">{event.description}</p>
                ) : null}
              </div>
              <div className="flex flex-wrap gap-3 text-sm text-slate-600">
                {showClubMetrics ? (
                  <span>
                    <span className="font-medium text-slate-800">{responsePercent}%</span> response rate
                    {memberCount > 0 ? ` (${totalResponses} ${responseLabel})` : null}
                  </span>
                ) : (
                  <span>
                    Your RSVP:{" "}
                    <span className="font-medium text-slate-800">
                      {event.userRsvpStatus ?? "none"}
                    </span>
                    {isPast ? (
                      <>
                        {" "}
                        · Attendance:{" "}
                        <span className="font-medium text-slate-800">
                          {event.userMarkedPresent ? "present" : "not marked"}
                        </span>
                      </>
                    ) : null}
                  </span>
                )}
                {showClubMetrics && !isPast ? (
                  <span>
                    <span className="font-medium text-slate-800">{event.attendanceCount}</span> checked in so far
                  </span>
                ) : null}
              </div>
            </div>
            <div className="event-status-panel">
              <span className={event.userRsvpStatus ? "badge-strong" : "badge-soft"}>
                {event.userRsvpStatus ? `RSVP ${event.userRsvpStatus}` : "Awaiting RSVP"}
              </span>
              {canCreateEvents ? (
                <Link
                  href={`/clubs/${club.id}/events?duplicateEventId=${event.id}#create-event`}
                  className="btn-secondary inline-flex min-h-10 items-center justify-center text-xs sm:min-h-0"
                >
                  Duplicate
                </Link>
              ) : null}
            </div>
          </div>

          {!isPast ? (
            <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50/50 p-3">
              <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-500">Your RSVP</p>
              <EventRsvpControls
                clubId={club.id}
                eventId={event.id}
                selectedStatus={event.userRsvpStatus}
                recentlySaved={Boolean(eventRsvpSaved)}
              />
            </div>
          ) : null}
        </>
      ) : (
        <p className="text-xs text-slate-500">
          Expand the sections below for the full write-up, participation data, attendance, and reflections.
        </p>
      )}

      <div className={omitPrimaryHeader ? "mt-2 space-y-3" : "mt-4 space-y-3"}>
        <DisclosurePanel
          title="Description & participation"
          subtitle={participationSubtitle}
          badge={
            showClubMetrics ? (
              <span className="badge-soft text-[10px]">{isPast ? "Post-event view" : "RSVP & turnout"}</span>
            ) : null
          }
        >
          <p className="text-sm leading-6 text-slate-700">{event.description}</p>
          <div className="event-meta-grid mt-4">
            <div className="event-meta-item">
              <span className="event-meta-label">Location</span>
              <span className="event-meta-value">{event.location}</span>
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
                  {event.userRsvpStatus ? `You replied: ${event.userRsvpStatus}` : "You did not RSVP"}
                </span>
              </div>
            )}
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
              <div className="event-metrics-grid mt-4">
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
              <div className="event-progress-panel mt-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <p className="text-sm font-semibold text-slate-900">Participation</p>
                    <p className="mt-1 text-sm text-slate-600">
                      {memberCount > 0
                        ? `${totalResponses} of ${memberCount} ${memberCount === 1 ? "member" : "members"} responded`
                        : "Waiting for members to join this club."}
                    </p>
                  </div>
                  <span className="badge-soft">
                    {event.rsvpCounts.yes} yes · {event.rsvpCounts.maybe} maybe · {event.rsvpCounts.no} no
                  </span>
                </div>
                <div className="event-progress-bar mt-4" aria-hidden="true">
                  <div className="event-progress-segment event-progress-yes" style={{ width: responseYesWidth }} />
                  <div className="event-progress-segment event-progress-maybe" style={{ width: responseMaybeWidth }} />
                  <div className="event-progress-segment event-progress-no" style={{ width: responseNoWidth }} />
                </div>
                <div className="mt-3 grid gap-2 text-xs font-medium text-slate-600 sm:grid-cols-3">
                  <span>Yes responses are highlighted in green.</span>
                  <span>Maybe responses are highlighted in amber.</span>
                  <span>No responses are highlighted in rose.</span>
                </div>
              </div>
            </>
          ) : null}
        </DisclosurePanel>

        {canMarkAttendance ? (
          <DisclosurePanel
            title="Mark attendance"
            subtitle={`${event.attendanceCount} marked present · ${Math.max(0, club.members.length - event.presentMemberIds.length)} unmarked in checklist`}
            badge={<span className="badge-soft text-[10px]">Officers</span>}
          >
            <AttendanceChecklist
              clubId={club.id}
              eventId={event.id}
              members={club.members}
              presentMemberIds={event.presentMemberIds}
              currentUserId={club.currentUserId}
              recentlySavedUserId={query.attendanceEventId === event.id ? query.attendanceUserId : undefined}
              recentlySavedPresent={query.attendanceEventId === event.id ? query.attendancePresent === "true" : undefined}
              embedded
            />
          </DisclosurePanel>
        ) : null}

        {isPast && canManageReflections ? (
          <DisclosurePanel
            title="Officer reflection"
            subtitle={
              event.reflection
                ? `Last updated ${event.reflection.updatedAt}`
                : "Capture what worked and what to improve for next time."
            }
            badge={
              event.reflection ? (
                <span className="rounded-full bg-emerald-100 px-2 py-0.5 text-[10px] font-semibold text-emerald-800">
                  Saved
                </span>
              ) : (
                <span className="rounded-full bg-amber-100 px-2 py-0.5 text-[10px] font-semibold text-amber-900">
                  Draft
                </span>
              )
            }
            defaultOpen={reflectionOpenDefault}
          >
            {eventReflectionError ? <p className="alert-error mb-4">{query.reflectionError}</p> : null}
            {!event.reflection ? (
              <div className="mb-4 rounded-xl border border-slate-200 bg-white p-4">
                <p className="text-sm font-semibold text-slate-900">Add a quick post-event note</p>
                <p className="mt-1 text-sm text-slate-600">No reflection has been saved for this event yet.</p>
              </div>
            ) : (
              <div className="mb-4 grid gap-3 md:grid-cols-2">
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
            <form action={saveEventReflectionAction} className="space-y-3">
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
          </DisclosurePanel>
        ) : null}
      </div>
    </Root>
  );
}
