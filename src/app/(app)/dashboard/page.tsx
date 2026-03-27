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
  const { clubs, recentAnnouncements, upcomingEvents, needsAttentionAlerts } = await getDashboardData();
  const officerClubs = clubs.filter((club) => club.role === "officer").length;
  const now = new Date();
  const sevenDaysAgo = new Date(now);
  sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
  const sevenDaysFromNow = new Date(now);
  sevenDaysFromNow.setDate(sevenDaysFromNow.getDate() + 7);

  const thisWeekEvents = upcomingEvents.filter((event) => {
    const eventDate = new Date(event.eventDateRaw);
    return eventDate >= now && eventDate <= sevenDaysFromNow;
  });

  const thisWeekAnnouncements = recentAnnouncements
    .filter((announcement) => {
      const createdAt = new Date(announcement.createdAtRaw);
      return createdAt >= sevenDaysAgo && createdAt <= now;
    })
    .slice(0, 5);

  const weeklyActivityCount = thisWeekEvents.length + thisWeekAnnouncements.length;
  const activeClubIds = new Set([
    ...thisWeekEvents.map((event) => event.clubId),
    ...thisWeekAnnouncements.map((announcement) => announcement.clubId),
  ]);
  const nextEvent = upcomingEvents[0] ?? null;
  const urgentEventCount = thisWeekEvents.filter((event) => {
    const eventDate = new Date(event.eventDateRaw);
    const hoursUntil = (eventDate.getTime() - now.getTime()) / (1000 * 60 * 60);
    return hoursUntil <= 48;
  }).length;

  return (
    <section className="space-y-8">
      <section className="dashboard-hero">
        <div className="flex flex-wrap items-start justify-between gap-5">
          <div className="max-w-3xl">
            <p className="section-kicker text-slate-600">Home Base</p>
            <h1 className="mt-3 text-3xl font-semibold tracking-tight text-slate-950 md:text-4xl">
              Your club control center
            </h1>
            <p className="mt-4 max-w-2xl text-base leading-7 text-slate-700">
              See what needs attention now, what is happening this week, and where to jump back in across the clubs you manage.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Link href="/clubs/create" className="btn-primary">
              Create Club
            </Link>
            <Link href="/clubs/join" className="btn-secondary">
              Join Club
            </Link>
            <Link href="/clubs" className="btn-secondary">
              View Clubs
            </Link>
          </div>
        </div>

        <div className="dashboard-hero-grid mt-7">
          <div className="dashboard-focus-panel">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="dashboard-panel-kicker">Priority now</p>
                <h2 className="mt-2 text-xl font-semibold tracking-tight text-slate-950">
                  {weeklyActivityCount > 0 ? "Your week is active" : "Nothing pressing yet"}
                </h2>
                <p className="mt-2 text-sm leading-6 text-slate-600">
                  {weeklyActivityCount > 0
                    ? `${weeklyActivityCount} updates across ${activeClubIds.size || clubs.length} clubs are worth a look this week.`
                    : "No immediate activity is scheduled. This is a good time to create a meeting or post an update."}
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
                <p className="dashboard-focus-copy">Clubs where you can post updates, plan events, and guide the week.</p>
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
                  <span className="dashboard-summary-label">Recent updates</span>
                  <span className="dashboard-summary-value">{recentAnnouncements.length}</span>
                </div>
              </div>
            </div>

            <div className="dashboard-rail-card">
              <p className="dashboard-panel-kicker">Go next</p>
              <div className="mt-4 space-y-3">
                <Link href={officerClubs > 0 ? "/clubs" : "/clubs/create"} className="dashboard-next-link">
                  <span className="dashboard-next-title">
                    {officerClubs > 0 ? "Open managed clubs" : "Create your first club"}
                  </span>
                  <span className="dashboard-next-copy">
                    {officerClubs > 0
                      ? "Review the clubs where you can post, schedule, and organize."
                      : "Start a new space for members, events, and updates."}
                  </span>
                </Link>
                <Link href={nextEvent ? `/clubs/${nextEvent.clubId}` : "/clubs/join"} className="dashboard-next-link">
                  <span className="dashboard-next-title">
                    {nextEvent ? "Review the next event" : "Join a club"}
                  </span>
                  <span className="dashboard-next-copy">
                    {nextEvent
                      ? `Jump into ${nextEvent.clubName} and prepare for what is coming up.`
                      : "Use a join code to add an active club to your dashboard."}
                  </span>
                </Link>
              </div>
            </div>
          </div>
        </div>
      </section>

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

      <section className="dashboard-week-panel">
        <div className="section-card-header">
          <div>
            <p className="section-kicker">This Week</p>
            <h2 className="mt-2 text-lg font-semibold tracking-tight text-slate-900">What needs your attention</h2>
            <p className="mt-1 text-sm text-slate-600">
              A focused view of the events, announcements, and movement most likely to matter over the next 7 days.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="badge-soft">{weeklyActivityCount} items</span>
            {urgentEventCount > 0 ? <span className="feedback-pill feedback-pill-urgent">{urgentEventCount} soon</span> : null}
          </div>
        </div>

        {thisWeekEvents.length === 0 && thisWeekAnnouncements.length === 0 ? (
          <div className="empty-state mt-4 p-6">
            <p className="empty-state-title">Nothing planned for this week yet.</p>
            <p className="empty-state-copy">Create a meeting or post a quick update so members have a reason to check back.</p>
            <div className="mt-4 flex flex-col gap-3 sm:flex-row">
              <Link href="/clubs/create" className="btn-primary text-center">
                Create Club
              </Link>
              <Link href="/clubs" className="btn-secondary text-center">
                View Clubs
              </Link>
            </div>
          </div>
        ) : (
          <div className="mt-5 grid gap-4 xl:grid-cols-[1.5fr,1fr]">
            <div className="dashboard-section-card is-primary">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="dashboard-panel-kicker">Upcoming</p>
                  <h3 className="mt-1 text-base font-semibold text-slate-900">Next 7 days</h3>
                </div>
                <span className="badge-soft">{thisWeekEvents.length} events</span>
              </div>
              {thisWeekEvents.length === 0 ? (
                <p className="mt-4 text-sm text-slate-600">No events in the next week. Add one from a club page to give members something to plan around.</p>
              ) : (
                <ul className="list-stack mt-4">
                  {thisWeekEvents.map((event) => {
                    const eventDate = new Date(event.eventDateRaw);
                    const hoursUntil = (eventDate.getTime() - now.getTime()) / (1000 * 60 * 60);
                    const urgencyLabel = hoursUntil <= 24 ? "Today / Tomorrow" : hoursUntil <= 48 ? "Soon" : "This week";

                    return (
                      <li key={event.id} className={`dashboard-timeline-card ${hoursUntil <= 48 ? "is-urgent" : ""}`}>
                        <div className="flex items-start justify-between gap-3">
                          <div>
                            <p className="text-xs font-semibold uppercase tracking-[0.08em] text-slate-500">{event.clubName}</p>
                            <p className="mt-2 text-base font-semibold text-slate-950">{event.title}</p>
                          </div>
                          <span className={hoursUntil <= 48 ? "feedback-pill feedback-pill-urgent" : "badge-soft"}>
                            {urgencyLabel}
                          </span>
                        </div>
                        <div className="mt-4 grid gap-3 sm:grid-cols-2">
                          <div>
                            <p className="dashboard-mini-label">When</p>
                            <p className="mt-1 text-sm font-semibold text-slate-900">{event.eventDate}</p>
                          </div>
                          <div>
                            <p className="dashboard-mini-label">Where</p>
                            <p className="mt-1 text-sm font-semibold text-slate-900">{event.location}</p>
                          </div>
                        </div>
                        <Link href={`/clubs/${event.clubId}`} className="action-link mt-4">
                          Open event club
                        </Link>
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>

            <div className="space-y-4">
              <div className="dashboard-section-card">
                <p className="dashboard-panel-kicker">Recent announcements</p>
                {thisWeekAnnouncements.length === 0 ? (
                  <p className="mt-3 text-sm text-slate-600">No new announcements this week.</p>
                ) : (
                  <ul className="list-stack mt-3">
                    {thisWeekAnnouncements.map((announcement, index) => (
                      <li key={announcement.id} className={`dashboard-feed-card ${index === 0 ? "is-fresh" : ""}`}>
                        <div className="flex items-start justify-between gap-3">
                          <div>
                            <p className="text-xs font-semibold uppercase tracking-[0.08em] text-slate-500">{announcement.clubName}</p>
                            <p className="mt-1 text-sm font-semibold text-slate-900">{announcement.title}</p>
                          </div>
                          <span className={index === 0 ? "feedback-pill feedback-pill-fresh" : "badge-soft"}>
                            {index === 0 ? "Newest" : "Recent"}
                          </span>
                        </div>
                        <p className="mt-2 text-xs text-slate-500">{announcement.createdAt}</p>
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              <div className="dashboard-section-card">
                <p className="dashboard-panel-kicker">Quick summary</p>
                <div className="mt-4 grid gap-3 sm:grid-cols-3">
                  <div className="dashboard-mini-stat">
                    <p className="text-xs font-medium text-slate-500">Events this week</p>
                    <p className="mt-1 text-lg font-semibold text-slate-900">{thisWeekEvents.length}</p>
                  </div>
                  <div className="dashboard-mini-stat">
                    <p className="text-xs font-medium text-slate-500">Announcements</p>
                    <p className="mt-1 text-lg font-semibold text-slate-900">{thisWeekAnnouncements.length}</p>
                  </div>
                  <div className="dashboard-mini-stat">
                    <p className="text-xs font-medium text-slate-500">Active clubs</p>
                    <p className="mt-1 text-lg font-semibold text-slate-900">{activeClubIds.size}</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </section>

      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="section-kicker">Your Workspace</p>
          <h2 className="section-title mt-2">My Clubs</h2>
          <p className="section-subtitle">Quick access to the clubs you manage or participate in.</p>
        </div>
      </div>

      {clubs.length === 0 ? (
        <div className="rounded-lg border border-slate-200 bg-gradient-to-br from-blue-50 via-slate-50 to-slate-50 p-8">
          <div className="max-w-md">
            <p className="text-lg font-semibold text-slate-900">Ready to get started?</p>
            <p className="mt-2 text-sm text-slate-600">
              Create your first club to organize members, post announcements, and plan events. Or join an existing club using a code.
            </p>
            <div className="mt-6 flex flex-col gap-3 sm:flex-row">
              <Link href="/clubs/create" className="btn-primary flex-1 text-center">
                Create Club
              </Link>
              <Link href="/clubs/join" className="btn-secondary flex-1 text-center">
                Join Club
              </Link>
            </div>
          </div>
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
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
                <div className="dashboard-club-meta-item">
                  <span className="dashboard-mini-label">Next step</span>
                  <span className="dashboard-club-meta-value">
                    {club.role === "officer" ? "Open the club page to organize" : "Open the club page to stay updated"}
                  </span>
                </div>
              </div>
              {club.role === "officer" ? (
                <div className="surface-subcard mt-4 p-3">
                  <p className="stat-label">Join code</p>
                  <p className="mt-1 text-sm font-semibold tracking-[0.12em] text-slate-900">{club.joinCode}</p>
                </div>
              ) : null}
              <Link href={`/clubs/${club.id}`} className="action-link mt-5">
                Open club page
              </Link>
            </article>
          ))}
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <section className="card-surface p-6">
          <div className="section-card-header">
            <div>
              <p className="section-kicker">Updates</p>
              <h2 className="mt-2 text-lg font-semibold tracking-tight text-slate-900">Recent Announcements</h2>
            </div>
          </div>
          {recentAnnouncements.length === 0 ? (
            <div className="mt-4 rounded-lg border border-slate-200 bg-slate-50/50 p-6">
              <p className="text-sm font-semibold text-slate-900">No updates yet</p>
              <p className="mt-1 text-xs text-slate-600">Club officers will post announcements here.</p>
            </div>
          ) : (
            <ul className="list-stack mt-4">
              {recentAnnouncements.map((announcement, index) => (
                <li key={announcement.id} className={`surface-subcard p-4 ${index === 0 ? "border-blue-200 bg-blue-50/50" : ""}`}>
                  <div className="flex items-start justify-between gap-3">
                    <p className="text-xs font-semibold uppercase tracking-[0.08em] text-slate-500">{announcement.clubName}</p>
                    <div className="flex items-center gap-2">
                      {index === 0 ? <span className="feedback-pill feedback-pill-fresh">Newest</span> : null}
                      <p className="text-xs text-slate-500">{announcement.createdAt}</p>
                    </div>
                  </div>
                  <p className="mt-2 text-sm font-semibold text-slate-900">{announcement.title}</p>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="card-surface p-6">
          <div className="section-card-header">
            <div>
              <p className="section-kicker">Schedule</p>
              <h2 className="mt-2 text-lg font-semibold tracking-tight text-slate-900">Upcoming Events</h2>
            </div>
          </div>
          {upcomingEvents.length === 0 ? (
            <div className="mt-4 rounded-lg border border-slate-200 bg-slate-50/50 p-6">
              <p className="text-sm font-semibold text-slate-900">No events scheduled</p>
              <p className="mt-1 text-xs text-slate-600">Check back soon for upcoming club meetings.</p>
            </div>
          ) : (
            <ul className="list-stack mt-4">
              {upcomingEvents.map((event) => {
                const eventDate = new Date(event.eventDateRaw);
                const hoursUntil = (eventDate.getTime() - now.getTime()) / (1000 * 60 * 60);

                return (
                  <li key={event.id} className={`surface-subcard p-4 ${hoursUntil <= 48 ? "border-orange-200 bg-orange-50/50" : ""}`}>
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <p className="text-xs font-semibold uppercase tracking-[0.08em] text-slate-500">{event.clubName}</p>
                        <p className="mt-2 text-sm font-semibold text-slate-900">{event.title}</p>
                      </div>
                      <span className={hoursUntil <= 48 ? "feedback-pill feedback-pill-urgent" : "badge-soft"}>
                        {hoursUntil <= 48 ? "Soon" : "Upcoming"}
                      </span>
                    </div>
                    <p className="mt-2 text-sm text-slate-600">{event.location}</p>
                    <p className="mt-1 text-xs text-slate-500">{event.eventDate}</p>
                  </li>
                );
              })}
            </ul>
          )}
        </section>
      </div>
    </section>
  );
}
