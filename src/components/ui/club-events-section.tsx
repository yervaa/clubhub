import Link from "next/link";
import {
  createEventAction,
  saveEventReflectionAction,
} from "@/app/(app)/clubs/actions";
import { AttendanceChecklist } from "@/components/ui/attendance-checklist";
import { EventRsvpControls } from "@/components/ui/event-rsvp-controls";
import { ScrollToInputButton } from "@/components/ui/scroll-to-input-button";
import { EVENT_TYPE_OPTIONS } from "@/lib/events";
import type { ClubDetail } from "@/lib/clubs/queries";

type ClubEventsSectionProps = {
  club: ClubDetail;
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
};

export function ClubEventsSection({ club, query }: ClubEventsSectionProps) {
  const memberCount = club.memberCount;
  const duplicateEvent = club.currentUserRole === "officer" && query.duplicateEventId
    ? club.events.find((event) => event.id === query.duplicateEventId) ?? null
    : null;

  return (
    <div className="card-surface p-5" id="events">
      <div className="section-card-header">
        <div>
          <p className="section-kicker">Planning</p>
          <h3 className="mt-1 text-base font-semibold tracking-tight text-slate-900">Events</h3>
          <p className="mt-1 text-sm text-slate-600">Track what is coming up and collect responses from members.</p>
        </div>
        <span className="badge-soft">{club.events.length} scheduled</span>
      </div>
      {query.eventSuccess ? <p className="alert-success mt-4">{query.eventSuccess}</p> : null}
      {query.eventError ? <p className="alert-error mt-3">{query.eventError}</p> : null}
      {query.rsvpSuccess ? <p className="alert-success mt-3">{query.rsvpSuccess}</p> : null}
      {query.rsvpError ? <p className="alert-error mt-3">{query.rsvpError}</p> : null}
      {query.attendanceSuccess ? <p className="alert-success mt-3">{query.attendanceSuccess}</p> : null}
      {query.attendanceError ? <p className="alert-error mt-3">{query.attendanceError}</p> : null}

      {club.currentUserRole === "officer" ? (
        <form id="create-event" action={createEventAction} className="mt-4 space-y-3 rounded-xl border border-slate-200 bg-slate-50/70 p-4">
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
                <Link href={`/clubs/${club.id}/events`} className="btn-secondary whitespace-nowrap text-xs">
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
              className="input-control"
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
              className="input-control"
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
              className="textarea-control"
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
                className="input-control"
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
          <button type="submit" className="btn-primary">
            {duplicateEvent ? "Create duplicated event" : "Create event"}
          </button>
        </form>
      ) : null}

      {club.events.length === 0 ? (
        <div className="mt-4 rounded-lg border border-slate-200 bg-gradient-to-br from-indigo-50 to-slate-50 p-6">
          <p className="font-semibold text-slate-900">Schedule your first meeting</p>
          <p className="mt-1 text-sm text-slate-600">Create an event so members know when you&#39;re meeting and can RSVP.</p>
          {club.currentUserRole === "officer" && (
            <ScrollToInputButton
              inputSelector='input[id="event_title"]'
              className="btn-secondary mt-3"
            >
              Create First Event
            </ScrollToInputButton>
          )}
        </div>
      ) : (
        <div className="list-stack mt-4">
          {club.events.map((event) => {
            const now = new Date();
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

            return (
              <article key={event.id} className="event-card">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="max-w-2xl space-y-3">
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
                    </div>
                    <div>
                      <h4 className="text-xl font-semibold tracking-tight text-slate-950">{event.title}</h4>
                      <p className="mt-1 text-base font-medium text-slate-700">{event.eventDate}</p>
                    </div>
                    <p className="text-sm leading-6 text-slate-600">{event.description}</p>
                    <div className="event-meta-grid">
                      <div className="event-meta-item">
                        <span className="event-meta-label">Location</span>
                        <span className="event-meta-value">{event.location}</span>
                      </div>
                      <div className="event-meta-item">
                        <span className="event-meta-label">Response rate</span>
                        <span className="event-meta-value">
                          {memberCount > 0 ? `${responsePercent}% of members` : "No members yet"}
                        </span>
                      </div>
                    </div>
                  </div>
                  <div className="event-status-panel">
                    <span className={event.userRsvpStatus ? "badge-strong" : "badge-soft"}>
                      {event.userRsvpStatus ? `RSVP ${event.userRsvpStatus}` : "Awaiting RSVP"}
                    </span>
                    {club.currentUserRole === "officer" ? (
                      <Link href={`/clubs/${club.id}/events?duplicateEventId=${event.id}#create-event`} className="btn-secondary text-xs">
                        Duplicate
                      </Link>
                    ) : null}
                    <p className="text-right text-xs font-medium uppercase tracking-[0.12em] text-slate-500">
                      {totalResponses} {responseLabel}
                    </p>
                  </div>
                </div>
                <div className="event-metrics-grid">
                  <div className="event-metric-card">
                    <p className="event-metric-label">Going</p>
                    <p className="event-metric-value">{event.rsvpCounts.yes} {goingLabel}</p>
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
                <EventRsvpControls
                  clubId={club.id}
                  eventId={event.id}
                  selectedStatus={event.userRsvpStatus}
                  recentlySaved={Boolean(eventRsvpSaved)}
                />
                {isPast && club.currentUserRole === "officer" ? (
                  <div className="event-action-panel">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div>
                        <p className="text-sm font-semibold text-slate-900">Officer Reflection</p>
                        <p className="mt-1 text-sm text-slate-600">
                          Capture what happened so future events are easier to improve.
                        </p>
                      </div>
                      {event.reflection ? <span className="badge-soft">Updated {event.reflection.updatedAt}</span> : null}
                    </div>
                    {eventReflectionError ? <p className="alert-error mt-4">{query.reflectionError}</p> : null}
                    {!event.reflection ? (
                      <div className="mt-4 rounded-xl border border-slate-200 bg-white p-4">
                        <p className="text-sm font-semibold text-slate-900">Add a quick post-event note</p>
                        <p className="mt-1 text-sm text-slate-600">No reflection has been saved for this event yet.</p>
                      </div>
                    ) : (
                      <div className="mt-4 grid gap-3 md:grid-cols-2">
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
                {club.currentUserRole === "officer" ? (
                  <AttendanceChecklist
                    clubId={club.id}
                    eventId={event.id}
                    members={club.members}
                    presentMemberIds={event.presentMemberIds}
                    currentUserId={club.currentUserId}
                    recentlySavedUserId={query.attendanceEventId === event.id ? query.attendanceUserId : undefined}
                    recentlySavedPresent={query.attendanceEventId === event.id ? query.attendancePresent === "true" : undefined}
                  />
                ) : null}
              </article>
            );
          })}
        </div>
      )}
    </div>
  );
}
