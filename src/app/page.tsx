import Link from "next/link";
import { Navbar } from "@/components/layout/navbar";
import { getDashboardData } from "@/lib/clubs/queries";
import { createClient } from "@/lib/supabase/server";

function EmptyWorkspace() {
  return (
    <div className="empty-state p-7 text-left">
      <p className="empty-state-title">No clubs yet.</p>
      <p className="empty-state-copy">Create one or join with a code.</p>
      <div className="mt-5 flex flex-wrap gap-2">
        <Link href="/clubs/create" className="btn-primary">
          Create a Club
        </Link>
        <Link href="/clubs/join" className="btn-secondary">
          Join with a Code
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

  return (
    <div className="min-h-screen bg-slate-50">
      <Navbar />
      <main className="mx-auto flex w-full max-w-7xl flex-col gap-8 px-4 py-12 sm:px-6 sm:py-16">
        <section className="card-surface p-8 sm:p-10">
          <div className="max-w-3xl">
            <p className="section-kicker">{user ? "Welcome Back" : "ClubHub"}</p>
            <h1 className="mt-3 text-4xl font-semibold tracking-tight text-slate-900 sm:text-5xl">
              One place to run your school clubs.
            </h1>
            <p className="mt-4 max-w-2xl text-base text-slate-600 sm:text-lg">
              Announcements, events, clubs, and RSVPs in one clean workspace.
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              <Link href={user ? "/dashboard" : "/signup"} className="btn-primary">
                {user ? "Go to Dashboard" : "Get Started"}
              </Link>
              <Link href="/clubs/create" className="btn-secondary">
                Create a Club
              </Link>
              <Link href="/clubs/join" className="btn-secondary">
                Join with a Code
              </Link>
            </div>
          </div>
        </section>

        <section className="grid gap-4 xl:grid-cols-[minmax(0,1.15fr)_minmax(0,0.85fr)]">
          <div className="card-surface p-6">
            <div className="section-card-header">
              <div>
                <p className="section-kicker">Your Workspace</p>
                <h2 className="mt-2 text-xl font-semibold tracking-tight text-slate-900">Your clubs</h2>
              </div>
              {user ? (
                <Link href="/clubs" className="action-link">
                  View all
                </Link>
              ) : null}
            </div>

            {!user ? (
              <div className="empty-state mt-5 p-7 text-left">
                <p className="empty-state-title">Sign in to see your clubs.</p>
                <p className="empty-state-copy">Your dashboard and club pages will appear here.</p>
                <div className="mt-5 flex flex-wrap gap-2">
                  <Link href="/login" className="btn-primary">
                    Log In
                  </Link>
                  <Link href="/signup" className="btn-secondary">
                    Create Account
                  </Link>
                </div>
              </div>
            ) : clubs.length === 0 ? (
              <div className="mt-5">
                <EmptyWorkspace />
              </div>
            ) : (
              <div className="mt-5 grid gap-4 md:grid-cols-2">
                {clubs.slice(0, 4).map((club) => (
                  <article key={club.id} className="surface-subcard p-4">
                    <div className="flex items-start justify-between gap-3">
                      <h3 className="text-base font-semibold text-slate-900">{club.name}</h3>
                      <span className={club.role === "officer" ? "badge-strong" : "badge-soft"}>{club.role}</span>
                    </div>
                    <p className="mt-3 text-sm leading-6 text-slate-600">{club.description}</p>
                    <Link href={`/clubs/${club.id}`} className="action-link mt-4">
                      Open club
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
                <h2 className="mt-2 text-xl font-semibold tracking-tight text-slate-900">Start here</h2>
              </div>
            </div>

            <div className="mt-5 grid gap-3">
              <Link href="/dashboard" className="surface-subcard p-4 transition hover:border-slate-300">
                <p className="text-sm font-semibold text-slate-900">Dashboard</p>
                <p className="mt-1 text-sm text-slate-600">See clubs, updates, and events.</p>
              </Link>
              <Link href="/clubs/create" className="surface-subcard p-4 transition hover:border-slate-300">
                <p className="text-sm font-semibold text-slate-900">Create a Club</p>
                <p className="mt-1 text-sm text-slate-600">Start a new club and invite members.</p>
              </Link>
              <Link href="/clubs/join" className="surface-subcard p-4 transition hover:border-slate-300">
                <p className="text-sm font-semibold text-slate-900">Join with a Code</p>
                <p className="mt-1 text-sm text-slate-600">Enter an officer’s join code.</p>
              </Link>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
