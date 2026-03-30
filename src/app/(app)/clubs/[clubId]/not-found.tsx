import Link from "next/link";

/**
 * Shown when `notFound()` runs for this segment — usually no membership row for the
 * URL’s club id (wrong link, stale bookmark after re-seed, or account never joined).
 */
export default function ClubNotFound() {
  return (
    <section className="mx-auto max-w-lg space-y-6 px-4 py-16 text-center">
      <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-slate-100 text-slate-500">
        <svg className="h-7 w-7" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden>
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={1.5}
            d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"
          />
        </svg>
      </div>
      <div className="space-y-2">
        <h1 className="text-xl font-semibold tracking-tight text-slate-900">This club workspace isn’t available</h1>
        <p className="text-sm leading-relaxed text-slate-600">
          The address has to match a club you belong to. If you used an old bookmark, opened someone else’s link, or
          re-ran demo seeding (which issues new club IDs), this page will show until you open the club from your
          dashboard again or join with the club’s code.
        </p>
      </div>
      <div className="flex flex-col gap-2 sm:flex-row sm:justify-center">
        <Link href="/dashboard" className="btn-primary text-center">
          Back to dashboard
        </Link>
        <Link href="/clubs/join" className="btn-secondary text-center">
          Join a club
        </Link>
      </div>
    </section>
  );
}
