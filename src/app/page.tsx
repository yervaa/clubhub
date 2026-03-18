import Link from "next/link";
import { Navbar } from "@/components/layout/navbar";
import { getDashboardData } from "@/lib/clubs/queries";
import { createClient } from "@/lib/supabase/server";

function EmptySignedInState() {
  return (
    <div className="empty-state p-7 text-left">
      <p className="empty-state-title">Your workspace is ready.</p>
      <p className="empty-state-copy">
        Create a club to start organizing officers, announcements, and events in one place, or join one with a code.
      </p>
      <div className="mt-5 flex flex-wrap gap-2">
        <Link href="/clubs/create" className="btn-primary">
          Create a club
        </Link>
        <Link href="/clubs/join" className="btn-secondary">
          Join with a code
        </Link>
      </div>
    </div>
  );
}

export default async function Home() {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  const dashboardData = user ? await getDashboardData() : null;
  const clubs = dashboardData?.clubs ?? [];
  const recentAnnouncements = dashboardData?.recentAnnouncements ?? [];
  const upcomingEvents = dashboardData?.upcomingEvents ?? [];

  return (
    <div className="min-h-screen bg-slate-50">
      <Navbar />
      <main className="mx-auto flex w-full max-w-7xl flex-col gap-8 px-4 py-12 sm:px-6 sm:py-16">
        <section className="card-surface overflow-hidden p-8 sm:p-10">
          <div className="grid gap-8 lg:grid-cols-[minmax(0,1.2fr)_minmax(0,0.8fr)] lg:items-center">
            <div className="max-w-3xl">
              <p className="section-kicker">{user ? "Welcome Back" : "Club Operations, Simplified"}</p>
              <h1 className="mt-3 max-w-3xl text-4xl font-semibold tracking-tight text-slate-900 sm:text-5xl">
                Keep every club update, event, and member action in one place.
              </h1>
              <p className="mt-4 max-w-2xl text-base leading-7 text-slate-600 sm:text-lg">
                ClubHub gives student leaders one clean home for announcements, event planning, and member engagement so
                clubs stop relying on scattered chats, docs, and spreadsheets.
              </p>

              <div className="mt-8 flex flex-wrap gap-3">
                {user ? (
                  <>
                    <Link href="/dashboard" className="btn-primary">
                      Go to Dashboard
                    </Link>
                    <Link href="/clubs" className="btn-secondary">
                      View Clubs
                    </Link>
                    <Link href="/clubs/create" className="btn-secondary">
                      Create a Club
                    </Link>
                  </>
                ) : (
                  <>
                    <Link href="/signup" className="btn-primary">
                      Get Started
                    </Link>
                    <Link href="/login" className="btn-secondary">
                      Log In
                    </Link>
                  </>
                )}
              </div>
            </div>

            <div className="grid gap-3">
              <div className="stat-card">
                <p className="stat-label">Why schools use ClubHub</p>
                <p className="mt-3 text-base font-semibold text-slate-900">A single shared workflow for officers and members</p>
                <p className="mt-2 text-sm leading-6 text-slate-600">
                  Officers can post updates, schedule events, and manage club activity without juggling disconnected tools.
                </p>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="stat-card">
                  <p className="stat-label">Announcements</p>
                  <p className="mt-2 text-sm font-semibold text-slate-900">Clear updates for the whole club</p>
                </div>
                <div className="stat-card">
                  <p className="stat-label">Events + RSVP</p>
                  <p className="mt-2 text-sm font-semibold text-slate-900">Simple planning and attendance signals</p>
                </div>
              </div>
            </div>
          </div>
        </section>

        {user ? (
          <section className="grid gap-4 xl:grid-cols-[minmax(0,1.1fr)_minmax(0,0.9fr)]">
            <div className="card-surface p-6">
              <div className="section-card-header">
                <div>
                  <p className="section-kicker">Your Workspace</p>
                  <h2 className="mt-2 text-xl font-semibold tracking-tight text-slate-900">Start from where you left off</h2>
                  <p className="mt-1 text-sm text-slate-600">
                    Jump into your clubs, review what changed, and get back to organizing quickly.
                  </p>
                </div>
                <Link href="/dashboard" className="action-link">
                  Open full dashboard
                </Link>
              </div>

              {clubs.length === 0 ? (
                <div className="mt-5">
                  <EmptySignedInState />
                </div>
              ) : (
                <div className="mt-5 grid gap-4 md:grid-cols-2">
                  {clubs.slice(0, 4).map((club) => (
                    <article key={club.id} className="surface-subcard p-4">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <p className="section-kicker">Club</p>
                          <h3 className="mt-2 text-base font-semibold text-slate-900">{club.name}</h3>
                        </div>
                        <span className={club.role === "officer" ? "badge-strong" : "badge-soft"}>{club.role}</span>
                      </div>
                      <p className="mt-3 text-sm leading-6 text-slate-600">{club.description}</p>
                      <Link href={`/clubs/${club.id}`} className="action-link mt-4">
                        Open club page
                      </Link>
                    </article>
                  ))}
                </div>
              )}
            </div>

            <div className="card-surface p-6">
              <div className="section-card-header">
                <div>
                  <p className="section-kicker">Quick Actions</p>
                  <h2 className="mt-2 text-xl font-semibold tracking-tight text-slate-900">Keep momentum going</h2>
                </div>
              </div>

              <div className="mt-5 grid gap-3">
                <Link href="/clubs/create" className="surface-subcard p-4 transition hover:border-slate-300">
                  <p className="text-sm font-semibold text-slate-900">Create a club</p>
                  <p className="mt-1 text-sm text-slate-600">Set up a new organization and generate a join code for members.</p>
                </Link>
                <Link href="/clubs/join" className="surface-subcard p-4 transition hover:border-slate-300">
                  <p className="text-sm font-semibold text-slate-900">Join with a code</p>
                  <p className="mt-1 text-sm text-slate-600">Use an officer’s join code to enter an existing club.</p>
                </Link>
                <Link href="/clubs" className="surface-subcard p-4 transition hover:border-slate-300">
                  <p className="text-sm font-semibold text-slate-900">Manage your clubs</p>
                  <p className="mt-1 text-sm text-slate-600">See your officer roles, join codes, and club pages in one place.</p>
                </Link>
              </div>
            </div>
          </section>
        ) : (
          <section className="grid gap-4 md:grid-cols-3">
            <article className="card-surface p-6">
              <p className="section-kicker">Announcements</p>
              <h2 className="mt-2 text-lg font-semibold tracking-tight text-slate-900">Give every member one update stream</h2>
              <p className="mt-3 text-sm leading-6 text-slate-600">
                Replace scattered reminders with a single source of truth for club-wide news and meeting updates.
              </p>
            </article>
            <article className="card-surface p-6">
              <p className="section-kicker">Events</p>
              <h2 className="mt-2 text-lg font-semibold tracking-tight text-slate-900">Plan events without extra tools</h2>
              <p className="mt-3 text-sm leading-6 text-slate-600">
                Create events, collect RSVPs, and keep upcoming activities visible for everyone in the club.
              </p>
            </article>
            <article className="card-surface p-6">
              <p className="section-kicker">Dashboard</p>
              <h2 className="mt-2 text-lg font-semibold tracking-tight text-slate-900">Give students a real home base</h2>
              <p className="mt-3 text-sm leading-6 text-slate-600">
                Members see their clubs, the latest announcements, and what is happening next without digging through chats.
              </p>
            </article>
          </section>
        )}

        <section className="grid gap-4 lg:grid-cols-2">
          <div className="card-surface p-6">
            <div className="section-card-header">
              <div>
                <p className="section-kicker">What This Solves</p>
                <h2 className="mt-2 text-xl font-semibold tracking-tight text-slate-900">Built for the real club workflow</h2>
              </div>
            </div>
            <div className="mt-5 grid gap-3">
              <div className="surface-subcard p-4">
                <p className="text-sm font-semibold text-slate-900">Officers stay organized</p>
                <p className="mt-1 text-sm text-slate-600">Post announcements, manage events, and keep club operations in one clean workspace.</p>
              </div>
              <div className="surface-subcard p-4">
                <p className="text-sm font-semibold text-slate-900">Members stay informed</p>
                <p className="mt-1 text-sm text-slate-600">See updates, RSVP quickly, and understand what is happening without chasing multiple tools.</p>
              </div>
              <div className="surface-subcard p-4">
                <p className="text-sm font-semibold text-slate-900">Everything stays connected</p>
                <p className="mt-1 text-sm text-slate-600">Clubs, events, announcements, and responses all live in one system instead of disconnected apps.</p>
              </div>
            </div>
          </div>

          <div className="card-surface p-6">
            <div className="section-card-header">
              <div>
                <p className="section-kicker">{user ? "Live Snapshot" : "Inside The Product"}</p>
                <h2 className="mt-2 text-xl font-semibold tracking-tight text-slate-900">
                  {user ? "What matters right now" : "A cleaner way to run school clubs"}
                </h2>
              </div>
            </div>

            {user ? (
              recentAnnouncements.length === 0 && upcomingEvents.length === 0 ? (
                <div className="empty-state mt-5 p-6 text-left">
                  <p className="empty-state-title">No recent activity yet.</p>
                  <p className="empty-state-copy">
                    As your clubs start posting announcements and scheduling events, this snapshot will show the latest movement.
                  </p>
                </div>
              ) : (
                <div className="mt-5 grid gap-3">
                  {recentAnnouncements.slice(0, 2).map((announcement) => (
                    <article key={announcement.id} className="surface-subcard p-4">
                      <p className="section-kicker">{announcement.clubName}</p>
                      <p className="mt-2 text-sm font-semibold text-slate-900">{announcement.title}</p>
                      <p className="mt-1 text-xs text-slate-500">{announcement.createdAt}</p>
                    </article>
                  ))}
                  {upcomingEvents.slice(0, 2).map((event) => (
                    <article key={event.id} className="surface-subcard p-4">
                      <p className="section-kicker">{event.clubName}</p>
                      <p className="mt-2 text-sm font-semibold text-slate-900">{event.title}</p>
                      <p className="mt-1 text-sm text-slate-600">{event.location}</p>
                      <p className="mt-1 text-xs text-slate-500">{event.eventDate}</p>
                    </article>
                  ))}
                </div>
              )
            ) : (
              <div className="mt-5 grid gap-3">
                <div className="surface-subcard p-4">
                  <p className="text-sm font-semibold text-slate-900">One dashboard for all club activity</p>
                  <p className="mt-1 text-sm text-slate-600">Members can see their clubs, recent updates, and upcoming events in one view.</p>
                </div>
                <div className="surface-subcard p-4">
                  <p className="text-sm font-semibold text-slate-900">Officer-only controls where they belong</p>
                  <p className="mt-1 text-sm text-slate-600">Club pages include just enough admin tooling to post updates and schedule events without clutter.</p>
                </div>
                <div className="surface-subcard p-4">
                  <p className="text-sm font-semibold text-slate-900">Simple, student-friendly workflows</p>
                  <p className="mt-1 text-sm text-slate-600">Join with a code, RSVP with one click, and keep the experience clean enough for everyday use.</p>
                </div>
              </div>
            )}
          </div>
        </section>
      </main>
    </div>
  );
}
