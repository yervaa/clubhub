import Link from "next/link";
import { getDashboardData } from "@/lib/clubs/queries";

function getDashboardAlertLabel(type: Awaited<ReturnType<typeof getDashboardData>>["needsAttentionAlerts"][number]["type"]) {
  switch (type) {
    case "upcoming_event_low_rsvp":
      return "RSVP";
    case "attendance_not_marked":
      return "Attendance";
    case "no_upcoming_events":
      return "Schedule";
    case "no_recent_announcement":
      return "Updates";
    default:
      return "Alert";
  }
}

export default async function DashboardPage() {
  const { clubs, upcomingEvents, recentAnnouncements, needsAttentionAlerts } = await getDashboardData();
  const officerClubs = clubs.filter((club) => club.role === "officer").length;
  const now = new Date();
  const sevenDaysFromNow = new Date(now);
  sevenDaysFromNow.setDate(sevenDaysFromNow.getDate() + 7);

  const thisWeekEvents = upcomingEvents.filter((event) => {
    const eventDate = new Date(event.eventDateRaw);
    return eventDate >= now && eventDate <= sevenDaysFromNow;
  });

  const urgentEventCount = thisWeekEvents.filter((event) => {
    const eventDate = new Date(event.eventDateRaw);
    const hoursUntil = (eventDate.getTime() - now.getTime()) / (1000 * 60 * 60);
    return hoursUntil <= 48;
  }).length;

  const nextEvent = upcomingEvents[0] ?? null;

  return (
    <section className="space-y-8">
      {/* Hero */}
      <section className="dashboard-hero">
        <div className="flex flex-wrap items-start justify-between gap-5">
          <div className="max-w-3xl">
            <p className="section-kicker text-slate-600">Home Base</p>
            <h1 className="mt-3 text-3xl font-semibold tracking-tight text-slate-950 md:text-4xl">
              Your club control center
            </h1>
            <p className="mt-4 max-w-2xl text-base leading-7 text-slate-700">
              See what needs attention, check upcoming events, and jump into a club workspace.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Link href="/clubs/create" className="btn-primary">Create Club</Link>
            <Link href="/clubs/join" className="btn-secondary">Join Club</Link>
          </div>
        </div>

        <div className="dashboard-hero-grid mt-7">
          <div className="dashboard-focus-panel">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="dashboard-panel-kicker">Priority now</p>
                <h2 className="mt-2 text-xl font-semibold tracking-tight text-slate-950">
                  {nextEvent ? "Your week is active" : "Nothing pressing yet"}
                </h2>
                <p className="mt-2 text-sm leading-6 text-slate-600">
                  {nextEvent
                    ? `Next up: ${nextEvent.title} in ${nextEvent.clubName}.`
                    : "No immediate activity is scheduled. Create a meeting or post an update."}
                </p>
              </div>
              <span className={urgentEventCount > 0 ? "badge-strong" : "badge-soft"}>
                {urgentEventCount > 0 ? `${urgentEventCount} urgent` : "All clear"}
              </span>
            </div>

            <div className="dashboard-focus-grid mt-5">
              <div className="dashboard-focus-card is-strong">
                <p className="dashboard-focus-label">Next event</p>
                <p className="dashboard-focus-value">{nextEvent ? nextEvent.title : "No event scheduled"}</p>
                <p className="dashboard-focus-copy">
                  {nextEvent ? `${nextEvent.eventDate} · ${nextEvent.clubName}` : "Create or join a club to build momentum."}
                </p>
              </div>
              <div className="dashboard-focus-card">
                <p className="dashboard-focus-label">Officer spaces</p>
                <p className="dashboard-focus-value">{officerClubs}</p>
                <p className="dashboard-focus-copy">Clubs where you can post updates and plan events.</p>
              </div>
              <div className="dashboard-focus-card">
                <p className="dashboard-focus-label">Needs attention</p>
                <p className="dashboard-focus-value">{needsAttentionAlerts.length}</p>
                <p className="dashboard-focus-copy">Priority issues across your clubs right now.</p>
              </div>
            </div>
          </div>

          <div className="dashboard-side-rail">
            <div className="dashboard-rail-card">
              <p className="dashboard-panel-kicker">Overview</p>
              <div className="mt-4 space-y-3">
                <div className="dashboard-summary-row">
                  <span className="dashboard-summary-label">Clubs</span>
                  <span className="dashboard-summary-value">{clubs.length}</span>
                </div>
                <div className="dashboard-summary-row">
                  <span className="dashboard-summary-label">Officer roles</span>
                  <span className="dashboard-summary-value">{officerClubs}</span>
                </div>
                <div className="dashboard-summary-row">
                  <span className="dashboard-summary-label">Upcoming events</span>
                  <span className="dashboard-summary-value">{upcomingEvents.length}</span>
                </div>
                <div className="dashboard-summary-row">
                  <span className="dashboard-summary-label">Alerts</span>
                  <span className="dashboard-summary-value">{needsAttentionAlerts.length}</span>
                </div>
              </div>
            </div>

            <div className="dashboard-rail-card">
              <p className="dashboard-panel-kicker">Quick actions</p>
              <div className="mt-4 space-y-3">
                <Link href="/clubs/create" className="dashboard-next-link">
                  <span className="dashboard-next-title">Create a club</span>
                  <span className="dashboard-next-copy">Start a new space for members, events, and updates.</span>
                </Link>
                <Link href="/clubs/join" className="dashboard-next-link">
                  <span className="dashboard-next-title">Join with a code</span>
                  <span className="dashboard-next-copy">Use a join code to add an active club to your dashboard.</span>
                </Link>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Needs Attention */}
      <section className="card-surface p-6">
        <div className="section-card-header">
          <div>
            <p className="section-kicker">Needs Attention</p>
            <h2 className="mt-2 text-lg font-semibold tracking-tight text-slate-900">Issues worth acting on now</h2>
            <p className="mt-1 text-sm text-slate-600">A prioritized view across your clubs, with extra weight on the ones you manage.</p>
          </div>
          <span className="badge-soft">{needsAttentionAlerts.length} alerts</span>
        </div>

        {needsAttentionAlerts.length === 0 ? (
          <div className="mt-4 rounded-xl border border-emerald-200 bg-gradient-to-br from-emerald-50 to-white p-6">
            <p className="font-semibold text-slate-900">Everything looks on track.</p>
            <p className="mt-1 text-sm text-slate-600">There are no high-priority club issues to follow up on right now.</p>
          </div>
        ) : (
          <div className="list-stack mt-4">
            {needsAttentionAlerts.map((alert) => (
              <article key={alert.id} className="surface-subcard p-4">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                  <div className="max-w-2xl">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="badge-soft">{alert.clubName}</span>
                      <span className="badge-soft">{getDashboardAlertLabel(alert.type)}</span>
                      <h3 className="text-sm font-semibold text-slate-900">{alert.title}</h3>
                    </div>
                    <p className="mt-2 text-sm leading-6 text-slate-600">{alert.description}</p>
                  </div>
                  <Link href={alert.ctaHref} className="btn-secondary whitespace-nowrap">
                    {alert.ctaLabel}
                  </Link>
                </div>
              </article>
            ))}
          </div>
        )}
      </section>

      {/* My Clubs */}
      <section>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="section-kicker">Your Workspace</p>
            <h2 className="section-title mt-2">My Clubs</h2>
            <p className="section-subtitle">Jump into a club workspace to manage events, members, and announcements.</p>
          </div>
          <div className="flex gap-2">
            <Link href="/clubs/create" className="btn-primary">Create Club</Link>
            <Link href="/clubs/join" className="btn-secondary">Join Club</Link>
          </div>
        </div>

        {clubs.length === 0 ? (
          <div className="mt-6 rounded-lg border border-slate-200 bg-gradient-to-br from-blue-50 via-slate-50 to-slate-50 p-8">
            <div className="max-w-md">
              <p className="text-lg font-semibold text-slate-900">Ready to get started?</p>
              <p className="mt-2 text-sm text-slate-600">
                Create your first club to organize members, post announcements, and plan events. Or join an existing club using a code.
              </p>
              <div className="mt-6 flex flex-col gap-3 sm:flex-row">
                <Link href="/clubs/create" className="btn-primary flex-1 text-center">Create Club</Link>
                <Link href="/clubs/join" className="btn-secondary flex-1 text-center">Join Club</Link>
              </div>
            </div>
          </div>
        ) : (
          <div className="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {clubs.map((club) => (
              <article key={club.id} className={`dashboard-club-card ${club.role === "officer" ? "is-officer" : ""}`}>
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="section-kicker">Club</p>
                    <h3 className="mt-2 text-lg font-semibold tracking-tight text-slate-900">{club.name}</h3>
                  </div>
                  <span className={club.role === "officer" ? "badge-strong" : "badge-soft"}>{club.role}</span>
                </div>
                <p className="mt-3 min-h-16 text-sm leading-6 text-slate-600">{club.description}</p>
                <div className="dashboard-club-meta mt-4">
                  <div className="dashboard-club-meta-item">
                    <span className="dashboard-mini-label">Access</span>
                    <span className="dashboard-club-meta-value">
                      {club.role === "officer" ? "Can manage events and updates" : "Member view and activity"}
                    </span>
                  </div>
                  {club.role === "officer" ? (
                    <div className="dashboard-club-meta-item">
                      <span className="dashboard-mini-label">Join code</span>
                      <span className="dashboard-club-meta-value font-semibold tracking-[0.1em]">{club.joinCode}</span>
                    </div>
                  ) : null}
                </div>
                <Link href={`/clubs/${club.id}`} className="action-link mt-5">
                  Open club workspace →
                </Link>
              </article>
            ))}
          </div>
        )}
      </section>

      {/* Cross-club snapshot — only shown when there is something to display */}
      {(upcomingEvents.length > 0 || recentAnnouncements.length > 0) && (
        <div className="grid gap-4 lg:grid-cols-2">
          {/* Upcoming Events */}
          {upcomingEvents.length > 0 && (
            <section className="card-surface p-5">
              <div className="section-card-header">
                <div>
                  <p className="section-kicker">Schedule</p>
                  <h2 className="mt-1 text-base font-semibold tracking-tight text-slate-900">Upcoming Events</h2>
                </div>
                <span className="badge-soft">{upcomingEvents.length}</span>
              </div>
              <ul className="mt-4 space-y-2">
                {upcomingEvents.slice(0, 5).map((event) => {
                  const hoursUntil = (new Date(event.eventDateRaw).getTime() - now.getTime()) / (1000 * 60 * 60);
                  return (
                    <li key={event.id}>
                      <Link
                        href={`/clubs/${event.clubId}/events`}
                        className="flex items-start justify-between gap-3 rounded-lg px-3 py-2.5 transition hover:bg-slate-50"
                      >
                        <div className="min-w-0">
                          <p className="text-xs font-medium text-slate-500">{event.clubName}</p>
                          <p className="mt-0.5 truncate text-sm font-semibold text-slate-900">{event.title}</p>
                          <p className="mt-0.5 text-xs text-slate-500">{event.eventDate}</p>
                        </div>
                        {hoursUntil <= 48 && (
                          <span className="mt-0.5 flex-shrink-0 rounded-full bg-orange-100 px-2 py-0.5 text-xs font-semibold text-orange-700">
                            Soon
                          </span>
                        )}
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </section>
          )}

          {/* Recent Announcements */}
          {recentAnnouncements.length > 0 && (
            <section className="card-surface p-5">
              <div className="section-card-header">
                <div>
                  <p className="section-kicker">Updates</p>
                  <h2 className="mt-1 text-base font-semibold tracking-tight text-slate-900">Recent Announcements</h2>
                </div>
                <span className="badge-soft">{recentAnnouncements.length}</span>
              </div>
              <ul className="mt-4 space-y-2">
                {recentAnnouncements.slice(0, 5).map((announcement, index) => (
                  <li key={announcement.id}>
                    <Link
                      href={`/clubs/${announcement.clubId}/announcements`}
                      className="flex items-start justify-between gap-3 rounded-lg px-3 py-2.5 transition hover:bg-slate-50"
                    >
                      <div className="min-w-0">
                        <p className="text-xs font-medium text-slate-500">{announcement.clubName}</p>
                        <p className="mt-0.5 truncate text-sm font-semibold text-slate-900">{announcement.title}</p>
                        <p className="mt-0.5 text-xs text-slate-500">{announcement.createdAt}</p>
                      </div>
                      {index === 0 && (
                        <span className="mt-0.5 flex-shrink-0 rounded-full bg-blue-100 px-2 py-0.5 text-xs font-semibold text-blue-700">
                          New
                        </span>
                      )}
                    </Link>
                  </li>
                ))}
              </ul>
            </section>
          )}
        </div>
      )}
    </section>
  );
}
