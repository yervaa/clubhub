import Link from "next/link";
import { ClubJoinCodeRow } from "@/components/ui/club-join-code-row";
import { PageIntro } from "@/components/ui/page-intro";
import { PageEmptyState } from "@/components/ui/page-patterns";
import { getCurrentUserClubs } from "@/lib/clubs/queries";

export default async function MyClubsPage() {
  const clubs = await getCurrentUserClubs();

  return (
    <section className="space-y-4 lg:space-y-6">
      <PageIntro
        kicker="Global"
        title="My Clubs"
        description="Your club workspaces in one place. Join another club or start a new one when needed."
        actions={
          <>
            <Link href="/clubs/join" className="btn-secondary">
              Join Club
            </Link>
            <Link href="/clubs/create" className="btn-primary">
              Start a Club
            </Link>
          </>
        }
      />

      {clubs.length === 0 ? (
        <PageEmptyState
          title="Your club list is empty"
          copy="Join with an invite code to jump into a live workspace, or start your own club to organize events, announcements, and members."
          action={
            <Link href="/clubs/join" className="btn-primary">
              Join your first club
            </Link>
          }
        />
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {clubs.map((club) => (
            <article
              key={club.id}
              className={`dashboard-club-card flex flex-col rounded-xl border border-slate-200 bg-white ${club.role === "officer" ? "is-officer" : ""}`}
            >
              <div className="flex min-w-0 items-start justify-between gap-2">
                <h2 className="truncate text-base font-semibold tracking-tight text-slate-900">{club.name}</h2>
                <span
                  className={`shrink-0 rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide ${
                    club.role === "officer"
                      ? "bg-blue-100 text-blue-900 ring-1 ring-blue-200/80"
                      : "bg-slate-100 text-slate-600 ring-1 ring-slate-200/80"
                  }`}
                >
                  {club.role === "officer" ? "Officer" : "Member"}
                </span>
              </div>
              <p className="mt-2 line-clamp-1 text-sm leading-snug text-slate-600">{club.description}</p>
              {club.role === "officer" ? <ClubJoinCodeRow joinCode={club.joinCode} /> : null}
              <Link href={`/clubs/${club.id}`} className="btn-primary mt-auto w-full py-2.5 text-center text-sm font-semibold">
                Open Workspace
              </Link>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}
