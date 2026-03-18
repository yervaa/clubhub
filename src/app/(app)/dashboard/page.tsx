import Link from "next/link";
import { getDashboardData } from "@/lib/clubs/queries";

export default async function DashboardPage() {
  const { clubs, recentAnnouncements, upcomingEvents } = await getDashboardData();
  const officerClubs = clubs.filter((club) => club.role === "officer").length;

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

      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="section-kicker">Your Workspace</p>
          <h2 className="section-title mt-2">My Clubs</h2>
          <p className="section-subtitle">Quick access to the clubs you manage or participate in.</p>
        </div>
      </div>

      {clubs.length === 0 ? (
        <div className="empty-state">
          <p className="empty-state-title">Your workspace is empty.</p>
          <p className="empty-state-copy">Join an existing club with a code or create one and start organizing right away.</p>
          <div className="mt-5 flex flex-wrap items-center justify-center gap-2">
            <Link href="/clubs/join" className="btn-secondary">
              Join your first club
            </Link>
            <Link href="/clubs/create" className="btn-primary">
              Create a club
            </Link>
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
            <div className="empty-state mt-4 p-6">
              <p className="empty-state-title">No announcements yet.</p>
              <p className="empty-state-copy">When club officers post updates, they will show up here first.</p>
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
            <div className="empty-state mt-4 p-6">
              <p className="empty-state-title">Nothing on the calendar yet.</p>
              <p className="empty-state-copy">Upcoming events from your clubs will appear here in date order.</p>
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
