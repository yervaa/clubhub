import Link from "next/link";
import { getDashboardData } from "@/lib/clubs/queries";

export default async function DashboardPage() {
  const { clubs, recentAnnouncements, upcomingEvents } = await getDashboardData();

  return (
    <section className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="section-title">Dashboard</h1>
          <p className="section-subtitle">Your clubs, updates, and upcoming activities in one view.</p>
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

      {clubs.length === 0 ? (
        <div className="empty-state">
          <p className="text-sm text-slate-600">You are not a member of any clubs yet.</p>
          <Link href="/clubs/join" className="btn-secondary mt-4">
            Join your first club
          </Link>
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {clubs.map((club) => (
            <article key={club.id} className="card-surface p-5">
              <div className="flex items-start justify-between gap-3">
                <h2 className="text-base font-semibold text-slate-900">{club.name}</h2>
                <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-700">
                  {club.role}
                </span>
              </div>
              <p className="mt-2 text-sm text-slate-600">{club.description}</p>
              {club.role === "officer" ? (
                <p className="mt-4 text-xs font-semibold uppercase tracking-[0.08em] text-slate-500">
                  Join code: {club.joinCode}
                </p>
              ) : null}
              <Link href={`/clubs/${club.id}`} className="mt-4 inline-flex text-sm font-semibold text-slate-900 hover:text-slate-700">
                Open club page
              </Link>
            </article>
          ))}
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <section className="card-surface p-6">
          <h2 className="text-lg font-semibold tracking-tight text-slate-900">Recent Announcements</h2>
          {recentAnnouncements.length === 0 ? (
            <p className="mt-3 text-sm text-slate-600">No announcements yet from your clubs.</p>
          ) : (
            <ul className="mt-3 space-y-2">
              {recentAnnouncements.map((announcement) => (
                <li key={announcement.id} className="rounded-md border border-slate-200 bg-white p-3">
                  <p className="text-xs font-semibold uppercase tracking-[0.08em] text-slate-500">{announcement.clubName}</p>
                  <p className="mt-1 text-sm font-semibold text-slate-900">{announcement.title}</p>
                  <p className="mt-1 text-xs text-slate-500">{announcement.createdAt}</p>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="card-surface p-6">
          <h2 className="text-lg font-semibold tracking-tight text-slate-900">Upcoming Events</h2>
          {upcomingEvents.length === 0 ? (
            <p className="mt-3 text-sm text-slate-600">No upcoming events from your clubs.</p>
          ) : (
            <ul className="mt-3 space-y-2">
              {upcomingEvents.map((event) => (
                <li key={event.id} className="rounded-md border border-slate-200 bg-white p-3">
                  <p className="text-xs font-semibold uppercase tracking-[0.08em] text-slate-500">{event.clubName}</p>
                  <p className="mt-1 text-sm font-semibold text-slate-900">{event.title}</p>
                  <p className="mt-1 text-sm text-slate-600">{event.location}</p>
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
