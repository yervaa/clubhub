import Link from "next/link";
import { joinClubAction } from "@/app/(app)/clubs/actions";
import { CopyInviteLinkButton } from "@/components/ui/copy-invite-link-button";

type JoinClubAuthenticatedContentProps = {
  joinCode: string;
  successMessage: string | null;
  errorMessage: string | null;
  isPendingOutcome: boolean;
  clubIdParam: string;
  showAlreadyMemberInfo: boolean;
};

export function JoinClubAuthenticatedContent({
  joinCode,
  successMessage,
  errorMessage,
  isPendingOutcome,
  clubIdParam,
  showAlreadyMemberInfo,
}: JoinClubAuthenticatedContentProps) {
  return (
    <section className="space-y-5">
      <div className="card-surface max-w-2xl p-5 sm:p-7">
        <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">Membership</p>
        <h1 className="section-title mt-2">Join a club</h1>
        <p className="section-subtitle">
          Enter the join code from your club, or open an invite link to fill it in automatically.
        </p>

        {successMessage ? (
          <div
            className={`mt-6 rounded-xl border p-5 ${
              isPendingOutcome ? "border-amber-200 bg-amber-50/90" : "border-emerald-200 bg-emerald-50"
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

        <form action={joinClubAction} className="mt-6 space-y-4">
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
              className="input-control min-h-11 text-center text-lg font-semibold uppercase tracking-wider"
              placeholder="ABC12345"
              autoComplete="off"
            />
            <p className="mt-2 text-xs text-slate-600">
              8 characters, letters and numbers. If the club requires approval, submitting adds a pending request — not an
              instant join.
            </p>
          </div>

          <button type="submit" className="btn-primary w-full">
            Join club
          </button>
        </form>
      </div>

      <div className="max-w-2xl">
        <div className="rounded-lg border border-slate-200 bg-gradient-to-br from-blue-50 to-slate-50 p-5 sm:p-6">
          <p className="font-semibold text-slate-900">Starting something new?</p>
          <p className="mt-2 text-sm text-slate-600">Create a club, share a join code or link, and invite your group.</p>
          <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:flex-wrap">
            <Link href="/clubs/create" className="btn-secondary w-full text-center sm:w-auto">
              Create a club
            </Link>
            <Link href="/clubs" className="btn-secondary w-full text-center sm:w-auto">
              Your clubs
            </Link>
          </div>
        </div>
      </div>
    </section>
  );
}
