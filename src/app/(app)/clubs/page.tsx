import Link from "next/link";
import { getCurrentUserClubs } from "@/lib/clubs/queries";

type ClubsPageProps = {
  searchParams: Promise<{ success?: string }>;
};

export default async function ClubsPage({ searchParams }: ClubsPageProps) {
  const params = await searchParams;
  const clubs = await getCurrentUserClubs();

  return (
    <section className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="section-title">My Clubs</h1>
          <p className="section-subtitle">Create a club or join one using a code from an officer.</p>
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

      {params.success ? <p className="alert-success">{params.success}</p> : null}

      {clubs.length === 0 ? (
        <div className="empty-state">
          <p className="text-sm text-slate-600">You are not a member of any clubs yet.</p>
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2">
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
    </section>
  );
}
