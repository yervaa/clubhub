import Link from "next/link";
import { joinClubAction } from "@/app/(app)/clubs/actions";

type JoinClubPageProps = {
  searchParams: Promise<{ error?: string }>;
};

export default async function JoinClubPage({ searchParams }: JoinClubPageProps) {
  const params = await searchParams;

  return (
    <section className="card-surface max-w-2xl p-8">
      <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">Membership</p>
      <h1 className="section-title mt-2">Join Club</h1>
      <p className="section-subtitle">Enter the join code shared by a club officer.</p>

      {params.error ? <p className="alert-error mt-6">{params.error}</p> : null}

      <form action={joinClubAction} className="mt-7 space-y-4">
        <div>
          <label htmlFor="join_code" className="mb-1.5 block text-sm font-medium text-slate-700">
            Join code
          </label>
          <input id="join_code" name="join_code" type="text" required className="input-control uppercase tracking-wider" placeholder="ABC12345" />
        </div>

        <button type="submit" className="btn-primary">
          Join club
        </button>
      </form>

      <p className="mt-6 text-sm text-slate-600">
        Need to create one?{" "}
        <Link href="/clubs/create" className="font-semibold text-slate-900 hover:text-slate-700">
          Create a club
        </Link>
      </p>
    </section>
  );
}
