import Link from "next/link";
import { unstable_noStore as noStore } from "next/cache";
import { joinClubAction } from "@/app/(app)/clubs/actions";
import { Navbar } from "@/components/layout/navbar";
import { CopyInviteLinkButton } from "@/components/ui/copy-invite-link-button";
import { getSafeNextPath } from "@/lib/auth/redirects";
import { createClient } from "@/lib/supabase/server";

type JoinPageProps = {
  searchParams: Promise<{
    code?: string;
    error?: string;
    success?: string;
    clubId?: string;
    pending?: string;
  }>;
};

export default async function JoinPage({ searchParams }: JoinPageProps) {
  noStore();

  const params = await searchParams;
  const joinCode = typeof params.code === "string" ? params.code.toUpperCase() : "";

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  const nextPath = getSafeNextPath(joinCode ? `/join?code=${encodeURIComponent(joinCode)}` : "/join");

  if (!user) {
    return (
      <div className="min-h-screen bg-slate-50">
        <Navbar />
        <main className="page-shell">
          <section className="space-y-6">
            <div className="card-surface max-w-2xl p-8">
              <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">Club Invite</p>
              <h1 className="section-title mt-2">Join this club</h1>
              <p className="section-subtitle">Log in or create an account to join with the code you were given.</p>

              {joinCode ? (
                <div className="mt-6 rounded-xl border border-slate-200 bg-slate-50 p-5">
                  <p className="text-sm font-medium text-slate-700">Invite code</p>
                  <p className="mt-2 text-2xl font-bold tracking-[0.2em] text-slate-900">{joinCode}</p>
                </div>
              ) : null}

              <div className="mt-6 flex flex-col gap-3 sm:flex-row">
                <Link href={`/login?next=${encodeURIComponent(nextPath)}`} className="btn-primary text-center">
                  Log in to join
                </Link>
                <Link href={`/signup?next=${encodeURIComponent(nextPath)}`} className="btn-secondary text-center">
                  Create account
                </Link>
              </div>
            </div>
          </section>
        </main>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50">
      <Navbar />
      <main className="page-shell">
        <section className="space-y-6">
          <div className="card-surface max-w-2xl p-8">
            <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">Membership</p>
            <h1 className="section-title mt-2">Join a Club</h1>
            <p className="section-subtitle">Use a club code or a shared invite link to join in one step.</p>

            {params.success ? (
              <div className="mt-6 rounded-xl border border-emerald-200 bg-emerald-50 p-5">
                <p className="text-sm font-semibold text-emerald-900">
                  {decodeURIComponent(params.success.replace(/\+/g, " "))}
                </p>
                {params.pending === "1" ? (
                  <p className="mt-2 text-sm text-emerald-900/90">
                    You are not a member yet. After an officer approves your request, this club will show up on your
                    dashboard.
                  </p>
                ) : (
                  <p className="mt-1 text-sm text-emerald-800">
                    Know someone else who should join? Send them the same invite link.
                  </p>
                )}
                <div className="mt-4 flex flex-col gap-3 sm:flex-row">
                  {params.clubId && params.pending !== "1" ? (
                    <Link href={`/clubs/${params.clubId}`} className="btn-primary text-center">
                      Open club
                    </Link>
                  ) : null}
                  {joinCode ? (
                    <CopyInviteLinkButton joinCode={joinCode} className="btn-secondary">
                      Invite your friends
                    </CopyInviteLinkButton>
                  ) : null}
                </div>
              </div>
            ) : null}

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
                  defaultValue={joinCode}
                  className="input-control text-center text-lg uppercase tracking-wider font-semibold"
                  placeholder="ABC12345"
                  autoComplete="off"
                />
                <p className="mt-2 text-xs text-slate-600">
                  Paste a shared code or open an invite link to prefill it.
                </p>
              </div>

              <button type="submit" className="btn-primary w-full">
                Join Club
              </button>
            </form>
          </div>

          <div className="max-w-2xl">
            <div className="rounded-lg border border-slate-200 bg-gradient-to-br from-blue-50 to-slate-50 p-6">
              <p className="font-semibold text-slate-900">Need a club to join?</p>
              <p className="mt-2 text-sm text-slate-600">
                Create one, invite people with a link, and start meeting.
              </p>
              <div className="mt-4 flex flex-wrap gap-3">
                <Link href="/clubs/create" className="btn-secondary">
                  Create a Club
                </Link>
                <Link href="/clubs" className="btn-secondary">
                  View Your Clubs
                </Link>
              </div>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
