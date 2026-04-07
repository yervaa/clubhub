import Link from "next/link";
import { unstable_noStore as noStore } from "next/cache";
import { joinClubAction } from "@/app/(app)/clubs/actions";
import { Navbar } from "@/components/layout/navbar";
import { CopyInviteLinkButton } from "@/components/ui/copy-invite-link-button";
import { getSafeNextPath } from "@/lib/auth/redirects";
import { decodeJoinPageMessage, joinMessageIsAlreadyMember } from "@/lib/clubs/join-flow";
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

  const successMessage = decodeJoinPageMessage(params.success);
  const errorMessage = decodeJoinPageMessage(params.error);
  const isPendingOutcome = params.pending === "1";
  const clubIdParam = typeof params.clubId === "string" ? params.clubId : "";

  if (!user) {
    return (
      <div className="min-h-screen bg-slate-50">
        <Navbar />
        <main className="page-shell">
          <section className="space-y-6">
            <div className="card-surface max-w-2xl p-8">
              <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">Join a club</p>
              <h1 className="section-title mt-2">You&apos;re invited</h1>
              <p className="section-subtitle">
                Sign in or create an account, then enter the join code (or use the link again after you&apos;re logged in).
              </p>

              {joinCode ? (
                <div className="mt-6 rounded-xl border border-slate-200 bg-slate-50 p-5">
                  <p className="text-sm font-medium text-slate-700">Join code</p>
                  <p className="mt-2 text-2xl font-bold tracking-[0.2em] text-slate-900">{joinCode}</p>
                  <p className="mt-2 text-xs text-slate-500">
                    If this club requires approval, you&apos;ll submit a request after you sign in — not an instant join.
                  </p>
                </div>
              ) : null}

              <div className="mt-6 flex flex-col gap-3 sm:flex-row">
                <Link href={`/login?next=${encodeURIComponent(nextPath)}`} className="btn-primary text-center">
                  Log in to continue
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

  const showAlreadyMemberInfo = Boolean(errorMessage && joinMessageIsAlreadyMember(errorMessage));

  return (
    <div className="min-h-screen bg-slate-50">
      <Navbar />
      <main className="page-shell">
        <section className="space-y-6">
          <div className="card-surface max-w-2xl p-8">
            <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">Membership</p>
            <h1 className="section-title mt-2">Join a club</h1>
            <p className="section-subtitle">
              Enter the join code from your club, or open an invite link to fill it in automatically.
            </p>

            {successMessage ? (
              <div
                className={`mt-6 rounded-xl border p-5 ${
                  isPendingOutcome
                    ? "border-amber-200 bg-amber-50/90"
                    : "border-emerald-200 bg-emerald-50"
                }`}
                role="status"
              >
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-600">
                  {isPendingOutcome ? "Awaiting approval" : "Welcome"}
                </p>
                <p
                  className={`mt-2 text-sm font-semibold ${isPendingOutcome ? "text-amber-950" : "text-emerald-950"}`}
                >
                  {successMessage}
                </p>
                {isPendingOutcome ? (
                  <div className="mt-3 space-y-2 text-sm leading-relaxed text-amber-950/90">
                    <p>You are not a member yet. An officer will approve or decline your request.</p>
                    <p className="text-amber-950/85">
                      Check <span className="font-semibold">Dashboard</span> or <span className="font-semibold">Your clubs</span>{" "}
                      — the club appears after approval.
                    </p>
                  </div>
                ) : (
                  <p className="mt-2 text-sm text-emerald-900/90">
                    You&apos;re on the roster. Open the club anytime, or share the same invite link with others.
                  </p>
                )}
                <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:flex-wrap">
                  {!isPendingOutcome && clubIdParam ? (
                    <Link href={`/clubs/${clubIdParam}`} className="btn-primary text-center">
                      Open club
                    </Link>
                  ) : null}
                  {isPendingOutcome ? (
                    <>
                      <Link href="/dashboard" className="btn-primary text-center">
                        Go to dashboard
                      </Link>
                      <Link href="/clubs" className="btn-secondary text-center">
                        Your clubs
                      </Link>
                    </>
                  ) : null}
                  {joinCode ? (
                    <CopyInviteLinkButton joinCode={joinCode} className="btn-secondary">
                      Copy invite link
                    </CopyInviteLinkButton>
                  ) : null}
                </div>
              </div>
            ) : showAlreadyMemberInfo ? (
              <div
                className="mt-6 rounded-xl border border-sky-200 bg-sky-50/90 p-5"
                role="status"
                aria-live="polite"
              >
                <p className="text-xs font-semibold uppercase tracking-wide text-sky-900/80">Already a member</p>
                <p className="mt-2 text-sm font-medium text-sky-950">{errorMessage}</p>
                <p className="mt-2 text-sm text-sky-900/85">No need to join again — head to the club or your dashboard.</p>
                <div className="mt-4 flex flex-col gap-3 sm:flex-row">
                  {clubIdParam ? (
                    <Link href={`/clubs/${clubIdParam}`} className="btn-primary text-center">
                      Open club
                    </Link>
                  ) : null}
                  <Link href="/clubs" className="btn-secondary text-center">
                    Your clubs
                  </Link>
                </div>
              </div>
            ) : errorMessage ? (
              <div className="mt-6 rounded-lg border border-red-200 bg-red-50 p-4" role="alert">
                <p className="text-sm font-semibold text-red-900">{errorMessage}</p>
                <p className="mt-2 text-xs text-red-800/90">
                  Double-check the code, ask your officer for a new link, or try again in a moment.
                </p>
              </div>
            ) : null}

            <form action={joinClubAction} className="mt-7 space-y-4">
              <div>
                <label htmlFor="join_code" className="mb-2 block text-sm font-semibold text-slate-900">
                  Join code
                </label>
                <input
                  id="join_code"
                  name="join_code"
                  type="text"
                  required
                  maxLength={8}
                  defaultValue={joinCode}
                  className="input-control text-center text-lg font-semibold uppercase tracking-wider"
                  placeholder="ABC12345"
                  autoComplete="off"
                />
                <p className="mt-2 text-xs text-slate-600">
                  8 characters, letters and numbers. If the club requires approval, submitting adds a pending request — not
                  an instant join.
                </p>
              </div>

              <button type="submit" className="btn-primary w-full">
                Join club
              </button>
            </form>
          </div>

          <div className="max-w-2xl">
            <div className="rounded-lg border border-slate-200 bg-gradient-to-br from-blue-50 to-slate-50 p-6">
              <p className="font-semibold text-slate-900">Starting something new?</p>
              <p className="mt-2 text-sm text-slate-600">Create a club, share a join code or link, and invite your group.</p>
              <div className="mt-4 flex flex-wrap gap-3">
                <Link href="/clubs/create" className="btn-secondary">
                  Create a club
                </Link>
                <Link href="/clubs" className="btn-secondary">
                  Your clubs
                </Link>
              </div>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
