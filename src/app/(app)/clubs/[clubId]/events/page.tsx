import { notFound, redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import { getUserPermissions } from "@/lib/rbac/permissions";
import { ClubEventsSection } from "@/components/ui/club-events-section";
import { EventCalendarView } from "@/components/ui/event-calendar-view";
import { getClubDetailForCurrentUser } from "@/lib/clubs/queries";

type ClubEventsPageProps = {
  params: Promise<{ clubId: string }>;
  searchParams: Promise<{
    view?: string;
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
  };

  const now = new Date();
  const upcomingCount = club.events.filter((e) => e.eventDateRaw > now).length;
  const pastCount = club.events.filter((e) => e.eventDateRaw <= now).length;

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
      <header className="card-surface border-2 border-slate-200 bg-gradient-to-br from-slate-50 to-blue-50 p-8">
        <div className="max-w-4xl">
          <p className="section-kicker text-slate-600">Planning</p>
          <h1 className="section-title mt-3 text-3xl md:text-4xl">Events</h1>
          <p className="section-subtitle mt-4 max-w-2xl text-lg text-slate-700">
            {permissions.canCreateEvents
              ? "Create events, track RSVPs, mark attendance, and review reflections."
              : "See upcoming events and RSVP to let your club know your plans."}
          </p>

          <div className="mt-8 flex flex-wrap items-center gap-8">
            <div>
              <p className="text-2xl font-bold text-slate-900">{club.events.length}</p>
              <p className="mt-1 text-xs font-semibold uppercase tracking-[0.1em] text-slate-500">
                Total Events
              </p>
            </div>
            {upcomingCount > 0 && (
              <>
                <div className="h-8 w-px bg-slate-200" />
                <div>
                  <p className="text-2xl font-bold text-blue-600">{upcomingCount}</p>
                  <p className="mt-1 text-xs font-semibold uppercase tracking-[0.1em] text-blue-500">Upcoming</p>
                </div>
              </>
            )}
            {pastCount > 0 && (
              <>
                <div className="h-8 w-px bg-slate-200" />
                <div>
                  <p className="text-2xl font-bold text-slate-500">{pastCount}</p>
                  <p className="mt-1 text-xs font-semibold uppercase tracking-[0.1em] text-slate-400">Past</p>
                </div>
              </>
            )}
          </div>

          {/* View toggle + CTA */}
          <div className="mt-8 flex flex-wrap items-center gap-3">
            {permissions.canCreateEvents && (
              <a href="#create-event" className="btn-primary px-6 py-3 text-base font-semibold">
                Create Event
              </a>
            )}
            <a
              href={`/clubs/${clubId}/events/export`}
              download
              className="btn-secondary flex items-center gap-1.5 px-4 py-2.5 text-sm"
            >
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
              </svg>
              Export .ics
            </a>
            <div className="flex rounded-lg border border-slate-200 bg-white p-0.5">
              <a
                href={`/clubs/${clubId}/events?view=list`}
                className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold transition ${
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
                className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold transition ${
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
      <ClubEventsSection club={club} query={query} permissions={permissions} />
    </section>
  );
}
