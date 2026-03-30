import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import { getUserPermissions } from "@/lib/rbac/permissions";
import { ClubEventsSection } from "@/components/ui/club-events-section";
import { EventCalendarView } from "@/components/ui/event-calendar-view";
import { partitionEventsByLifecycle } from "@/lib/clubs/event-lifecycle";
import { getClubDetailForCurrentUser } from "@/lib/clubs/queries";

type ClubEventsPageProps = {
  params: Promise<{ clubId: string }>;
  searchParams: Promise<{
    view?: string;
    filter?: string;
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
  }>;
};

export default async function ClubEventsPage({ params, searchParams }: ClubEventsPageProps) {
  const { clubId } = await params;
  const query = await searchParams;
  const viewMode = query.view === "calendar" ? "calendar" : "list";
  const listFilter = query.filter === "needs-review" ? "needs-review" : "all";

  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const [club, userPermissions] = await Promise.all([
    getClubDetailForCurrentUser(clubId),
    getUserPermissions(user.id, clubId),
  ]);

  if (!club) {
    notFound();
  }

  const permissions = {
    canCreateEvents: userPermissions.has("events.create"),
    canMarkAttendance: userPermissions.has("attendance.mark"),
    canManageReflections: userPermissions.has("reflections.create"),
    canViewAggregatedStats:
      userPermissions.has("attendance.mark") ||
      userPermissions.has("attendance.edit") ||
      userPermissions.has("reflections.create") ||
      userPermissions.has("reflections.edit") ||
      userPermissions.has("events.edit"),
    canViewInsights: userPermissions.has("insights.view"),
  };

  const now = new Date();
  const { upcoming, recentlyHappened, past } = partitionEventsByLifecycle(club.events, now);
  const upcomingCount = upcoming.length;
  const recentCount = recentlyHappened.length;
  const pastCount = past.length;

  const calendarEvents = club.events.map((e) => ({
    id: e.id,
    title: e.title,
    eventType: e.eventType,
    eventDateIso: e.eventDateRaw.toISOString(),
    rsvpStatus: e.userRsvpStatus,
  }));

  return (
    <section className="space-y-6">
      {/* Page header */}
      <header className="card-surface border-2 border-slate-200 bg-gradient-to-br from-slate-50 to-blue-50 p-5 sm:p-8">
        <div className="max-w-4xl">
          <p className="section-kicker text-slate-600">Planning</p>
          <h1 className="section-title mt-2 text-2xl sm:mt-3 sm:text-3xl md:text-4xl">Events</h1>
          <p className="section-subtitle mt-3 max-w-2xl text-base sm:mt-4 sm:text-lg text-slate-700">
            {permissions.canCreateEvents
              ? "Create events, track RSVPs, mark attendance, and review reflections — with a clear path from upcoming to history."
              : "See upcoming events, your RSVP history, and the club timeline after each event ends."}
          </p>

          <div className="mt-6 grid grid-cols-2 gap-4 sm:mt-8 sm:flex sm:flex-wrap sm:items-center sm:gap-8">
            <div>
              <p className="text-2xl font-bold text-slate-900">{club.events.length}</p>
              <p className="mt-1 text-xs font-semibold uppercase tracking-[0.1em] text-slate-500">
                Total events
              </p>
            </div>
            {upcomingCount > 0 && (
              <>
                <div className="hidden h-8 w-px bg-slate-200 sm:block" />
                <div>
                  <p className="text-2xl font-bold text-blue-600">{upcomingCount}</p>
                  <p className="mt-1 text-xs font-semibold uppercase tracking-[0.1em] text-blue-500">Upcoming</p>
                </div>
              </>
            )}
            {recentCount > 0 && (
              <>
                <div className="hidden h-8 w-px bg-slate-200 sm:block" />
                <div>
                  <p className="text-2xl font-bold text-amber-600">{recentCount}</p>
                  <p className="mt-1 text-xs font-semibold uppercase tracking-[0.1em] text-amber-700">Recent</p>
                </div>
              </>
            )}
            {pastCount > 0 && (
              <>
                <div className="hidden h-8 w-px bg-slate-200 sm:block" />
                <div>
                  <p className="text-2xl font-bold text-slate-500">{pastCount}</p>
                  <p className="mt-1 text-xs font-semibold uppercase tracking-[0.1em] text-slate-400">Past</p>
                </div>
              </>
            )}
          </div>

          {viewMode === "list" ? (
            <nav className="mt-5 flex flex-wrap gap-2 text-sm font-semibold sm:mt-6" aria-label="Event sections">
              <a
                href="#upcoming"
                className="inline-flex min-h-10 items-center rounded-full border border-slate-200 bg-white px-3.5 py-2 text-slate-700 hover:border-slate-300"
              >
                Upcoming
              </a>
              <a
                href="#recent"
                className="inline-flex min-h-10 items-center rounded-full border border-slate-200 bg-white px-3.5 py-2 text-slate-700 hover:border-slate-300"
              >
                Recently happened
              </a>
              <a
                href="#history"
                className="inline-flex min-h-10 items-center rounded-full border border-slate-200 bg-white px-3.5 py-2 text-slate-700 hover:border-slate-300"
              >
                Past events
              </a>
              <Link
                href={`/clubs/${clubId}/events/history`}
                className="inline-flex min-h-10 items-center rounded-full border border-slate-200 bg-white px-3.5 py-2 text-slate-700 hover:border-slate-300"
              >
                Full history
              </Link>
              {permissions.canViewAggregatedStats ? (
                <Link
                  href={`/clubs/${clubId}/events?filter=needs-review#recent`}
                  className="inline-flex min-h-10 items-center rounded-full border border-amber-200 bg-amber-50 px-3.5 py-2 text-amber-950 hover:bg-amber-100"
                >
                  Needs review
                </Link>
              ) : null}
            </nav>
          ) : null}

          {/* View toggle + CTA */}
          <div className="mt-6 flex flex-col gap-3 sm:mt-8 sm:flex-row sm:flex-wrap sm:items-center">
            {permissions.canCreateEvents && (
              <a
                href="#create-event"
                className="btn-primary w-full px-6 py-3 text-center text-base font-semibold sm:w-auto"
              >
                Create Event
              </a>
            )}
            <a
              href={`/clubs/${clubId}/events/export`}
              download
              className="btn-secondary flex w-full items-center justify-center gap-1.5 px-4 py-2.5 text-sm sm:w-auto"
            >
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
              </svg>
              Export .ics
            </a>
            <div className="flex w-full rounded-lg border border-slate-200 bg-white p-0.5 sm:w-auto">
              <a
                href={`/clubs/${clubId}/events?view=list`}
                className={`flex min-h-10 flex-1 items-center justify-center gap-1.5 rounded-md px-3 py-2 text-xs font-semibold transition sm:flex-none sm:py-1.5 ${
                  viewMode === "list" ? "bg-slate-900 text-white" : "text-slate-500 hover:text-slate-700"
                }`}
              >
                <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 10h16M4 14h16M4 18h16" />
                </svg>
                List
              </a>
              <a
                href={`/clubs/${clubId}/events?view=calendar`}
                className={`flex min-h-10 flex-1 items-center justify-center gap-1.5 rounded-md px-3 py-2 text-xs font-semibold transition sm:flex-none sm:py-1.5 ${
                  viewMode === "calendar" ? "bg-slate-900 text-white" : "text-slate-500 hover:text-slate-700"
                }`}
              >
                <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                </svg>
                Calendar
              </a>
            </div>
          </div>
        </div>
      </header>

      {/* Calendar view */}
      {viewMode === "calendar" && (
        <EventCalendarView events={calendarEvents} clubId={clubId} />
      )}

      {/* List view (existing component) */}
      <ClubEventsSection club={club} query={query} permissions={permissions} listFilter={listFilter} />
    </section>
  );
}
