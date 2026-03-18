import Link from "next/link";
import { getCurrentUserClubs } from "@/lib/clubs/queries";

type ClubsPageProps = {
  searchParams: Promise<{ success?: string }>;
};

export default async function ClubsPage({ searchParams }: ClubsPageProps) {
  const params = await searchParams;
  const clubs = await getCurrentUserClubs();
  const officerCount = clubs.filter((club) => club.role === "officer").length;

  return (
    <section className="space-y-7">
      <div className="card-surface p-7">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="max-w-2xl">
            <p className="section-kicker">Clubs</p>
            <h1 className="section-title mt-2">My Clubs</h1>
            <p className="section-subtitle">
              Everything you belong to in one place, with quick access to officer tools and member spaces.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Link href="/clubs/create" className="btn-primary">
              Create Club
            </Link>
            <Link href="/clubs/join" className="btn-secondary">
              Join Club
            </Link>
          </div>
        </div>

        <div className="stat-grid mt-6 md:grid-cols-3">
          <div className="stat-card">
            <p className="stat-label">Total Clubs</p>
            <p className="stat-value">{clubs.length}</p>
            <p className="stat-copy">Communities you can jump into right now.</p>
          </div>
          <div className="stat-card">
            <p className="stat-label">Officer Seats</p>
            <p className="stat-value">{officerCount}</p>
            <p className="stat-copy">Clubs where you can manage posts and events.</p>
          </div>
          <div className="stat-card">
            <p className="stat-label">Next Move</p>
            <p className="stat-copy">Create a new club or join one using a code from an officer.</p>
          </div>
        </div>
      </div>

      {params.success ? <p className="alert-success">{params.success}</p> : null}

      {clubs.length === 0 ? (
        <div className="empty-state">
          <p className="empty-state-title">No clubs yet.</p>
          <p className="empty-state-copy">Create your own club or join one with a code to start seeing updates, members, and events here.</p>
          <div className="mt-5 flex flex-wrap items-center justify-center gap-2">
            <Link href="/clubs/create" className="btn-primary">
              Create your first club
            </Link>
            <Link href="/clubs/join" className="btn-secondary">
              Join with a code
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
                  <h2 className="mt-2 text-lg font-semibold tracking-tight text-slate-900">{club.name}</h2>
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
    </section>
  );
}
