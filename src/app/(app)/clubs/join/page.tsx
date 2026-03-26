import Link from "next/link";
import { joinClubAction } from "@/app/(app)/clubs/actions";

type JoinClubPageProps = {
  searchParams: Promise<{ error?: string }>;
};

export default async function JoinClubPage({ searchParams }: JoinClubPageProps) {
  const params = await searchParams;

  return (
    <section className="space-y-6">
      <div className="card-surface max-w-2xl p-8">
        <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">Membership</p>
        <h1 className="section-title mt-2">Join a Club</h1>
        <p className="section-subtitle">Ask an officer for the join code and enter it below.</p>

        {params.error ? (
          <div className="mt-6 rounded-lg bg-red-50 border border-red-200 p-4">
            <p className="text-sm font-semibold text-red-900">{params.error}</p>
          </div>
        ) : null}

        <form action={joinClubAction} className="mt-7 space-y-4">
          <div>
            <label htmlFor="join_code" className="mb-2 block text-sm font-semibold text-slate-900">
              Join Code
            </label>
            <input
              id="join_code"
              name="join_code"
              type="text"
              required
              maxLength={8}
              className="input-control text-center text-lg uppercase tracking-wider font-semibold"
              placeholder="ABC12345"
              autoComplete="off"
            />
            <p className="mt-2 text-xs text-slate-600">
              Enter the 6-8 character code from an officer
            </p>
          </div>

          <button type="submit" className="btn-primary w-full">
            Join Club
          </button>
        </form>
      </div>

      <div className="max-w-2xl">
        <p className="text-sm font-semibold text-slate-900">First time here?</p>
        <div className="mt-4 rounded-lg border border-slate-200 bg-gradient-to-br from-blue-50 to-slate-50 p-6">
          <p className="font-semibold text-slate-900">Can&#39;t find a club?</p>
          <p className="mt-2 text-sm text-slate-600">
            Create your own club and start inviting members. You&#39;ll get a join code to share.
          </p>
          <Link href="/clubs/create" className="btn-secondary mt-4 inline-block">
            Create a New Club
          </Link>
        </div>
      </div>
    </section>
  );
}
