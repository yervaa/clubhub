import Link from "next/link";
import { getDashboardData } from "@/lib/clubs/queries";

export default async function DashboardPage() {
  const { clubs, recentAnnouncements, upcomingEvents } = await getDashboardData();
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

  const thisWeekAnnouncements = recentAnnouncements.filter((announcement) => {
    const createdAt = new Date(announcement.createdAtRaw);
    return createdAt >= sevenDaysAgo && createdAt <= now;
  }).slice(0, 5);

  const weeklyActivityCount = thisWeekEvents.length + thisWeekAnnouncements.length;

  return (
    <section className="space-y-7">
      <div className="card-surface p-7">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="max-w-2xl">
            <p className="section-kicker">Home Base</p>
            <h1 className="section-title mt-2">Dashboard</h1>
            <p className="section-subtitle">
              Stay on top of your clubs, see what needs attention, and jump back into the communities you manage.
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

        <div className="stat-grid mt-6 md:grid-cols-3">
          <div className="stat-card">
            <p className="stat-label">Clubs</p>
            <p className="stat-value">{clubs.length}</p>
            <p className="stat-copy">Spaces you currently belong to.</p>
          </div>
          <div className="stat-card">
            <p className="stat-label">Officer Roles</p>
            <p className="stat-value">{officerClubs}</p>
            <p className="stat-copy">Clubs where you can post and organize.</p>
          </div>
          <div className="stat-card">
            <p className="stat-label">Upcoming Events</p>
            <p className="stat-value">{upcomingEvents.length}</p>
            <p className="stat-copy">Events coming up soon across your clubs.</p>
          </div>
        </div>
      </div>

      <section className="card-surface border-blue-200 bg-gradient-to-r from-blue-50 via-white to-indigo-50 p-6">
        <div className="section-card-header">
          <div>
            <p className="section-kicker">This Week</p>
            <h2 className="mt-2 text-lg font-semibold tracking-tight text-slate-900">What needs your attention</h2>
            <p className="mt-1 text-sm text-slate-600">A fast view of the events, updates, and activity coming up in the next 7 days.</p>
          </div>
          <span className="badge-soft">{weeklyActivityCount} items</span>
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
          <div className="mt-4 grid gap-4 lg:grid-cols-[1.35fr,1fr]">
            <div className="surface-subcard p-4">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="text-xs font-semibold uppercase tracking-[0.08em] text-slate-500">Upcoming</p>
                  <h3 className="mt-1 text-sm font-semibold text-slate-900">Next 7 days</h3>
                </div>
                <span className="badge-soft">{thisWeekEvents.length} events</span>
              </div>
              {thisWeekEvents.length === 0 ? (
                <p className="mt-4 text-sm text-slate-600">No events in the next week. Add one from a club page to give members something to plan around.</p>
              ) : (
                <ul className="list-stack mt-4">
                  {thisWeekEvents.map((event) => (
                    <li key={event.id} className="rounded-lg border border-slate-200 bg-white p-4">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <p className="text-xs font-semibold uppercase tracking-[0.08em] text-slate-500">{event.clubName}</p>
                          <p className="mt-2 text-sm font-semibold text-slate-900">{event.title}</p>
                        </div>
                        <span className="badge-strong">This week</span>
                      </div>
                      <p className="mt-2 text-sm text-slate-600">{event.location}</p>
                      <p className="mt-1 text-xs text-slate-500">{event.eventDate}</p>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div className="space-y-4">
              <div className="surface-subcard p-4">
                <p className="text-xs font-semibold uppercase tracking-[0.08em] text-slate-500">Recent announcements</p>
                {thisWeekAnnouncements.length === 0 ? (
                  <p className="mt-3 text-sm text-slate-600">No new announcements this week.</p>
                ) : (
                  <ul className="list-stack mt-3">
                    {thisWeekAnnouncements.map((announcement) => (
                      <li key={announcement.id} className="rounded-lg border border-slate-200 bg-white p-3">
                        <p className="text-xs font-semibold uppercase tracking-[0.08em] text-slate-500">{announcement.clubName}</p>
                        <p className="mt-1 text-sm font-semibold text-slate-900">{announcement.title}</p>
                        <p className="mt-1 text-xs text-slate-500">{announcement.createdAt}</p>
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              <div className="surface-subcard p-4">
                <p className="text-xs font-semibold uppercase tracking-[0.08em] text-slate-500">Quick summary</p>
                <div className="mt-3 grid gap-3 sm:grid-cols-3">
                  <div className="rounded-lg border border-slate-200 bg-white p-3">
                    <p className="text-xs font-medium text-slate-500">Events this week</p>
                    <p className="mt-1 text-lg font-semibold text-slate-900">{thisWeekEvents.length}</p>
                  </div>
                  <div className="rounded-lg border border-slate-200 bg-white p-3">
                    <p className="text-xs font-medium text-slate-500">Announcements</p>
                    <p className="mt-1 text-lg font-semibold text-slate-900">{thisWeekAnnouncements.length}</p>
                  </div>
                  <div className="rounded-lg border border-slate-200 bg-white p-3">
                    <p className="text-xs font-medium text-slate-500">Active clubs</p>
                    <p className="mt-1 text-lg font-semibold text-slate-900">
                      {new Set([
                        ...thisWeekEvents.map((event) => event.clubId),
                        ...thisWeekAnnouncements.map((announcement) => announcement.clubId),
                      ]).size}
                    </p>
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
            <article key={club.id} className="card-surface p-5">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="section-kicker">Club</p>
                  <h3 className="mt-2 text-lg font-semibold tracking-tight text-slate-900">{club.name}</h3>
                </div>
                <span className={club.role === "officer" ? "badge-strong" : "badge-soft"}>{club.role}</span>
              </div>
              <p className="mt-3 text-sm leading-6 text-slate-600">{club.description}</p>
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
              {recentAnnouncements.map((announcement) => (
                <li key={announcement.id} className="surface-subcard p-4">
                  <div className="flex items-start justify-between gap-3">
                    <p className="text-xs font-semibold uppercase tracking-[0.08em] text-slate-500">{announcement.clubName}</p>
                    <p className="text-xs text-slate-500">{announcement.createdAt}</p>
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
              {upcomingEvents.map((event) => (
                <li key={event.id} className="surface-subcard p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="text-xs font-semibold uppercase tracking-[0.08em] text-slate-500">{event.clubName}</p>
                      <p className="mt-2 text-sm font-semibold text-slate-900">{event.title}</p>
                    </div>
                    <span className="badge-soft">Upcoming</span>
                  </div>
                  <p className="mt-2 text-sm text-slate-600">{event.location}</p>
                  <p className="mt-1 text-xs text-slate-500">{event.eventDate}</p>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </section>
  );
}
