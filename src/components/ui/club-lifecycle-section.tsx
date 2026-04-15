"use client";

import Link from "next/link";
import { useState } from "react";
import {
  archiveClubAction,
  deleteClubAction,
  leaveClubAction,
  updateClubJoinPolicyAction,
} from "@/app/(app)/clubs/club-lifecycle-actions";
import { CardSection } from "@/components/ui/page-patterns";
import { PageIntro } from "@/components/ui/page-intro";

type ClubLifecycleSectionProps = {
  clubId: string;
  clubName: string;
  clubStatus: "active" | "archived";
  isPresident: boolean;
  presidentCount: number;
  canArchive: boolean;
  canDelete: boolean;
  query: {
    success?: string;
    error?: string;
  };
  requireJoinApproval: boolean;
  canManageJoinPolicy: boolean;
};

export function ClubLifecycleSection({
  clubId,
  clubName,
  clubStatus,
  isPresident,
  presidentCount,
  canArchive,
  canDelete,
  query,
  requireJoinApproval,
  canManageJoinPolicy,
}: ClubLifecycleSectionProps) {
  const [leaveOpen, setLeaveOpen] = useState(false);
  const [archiveOpen, setArchiveOpen] = useState(false);
  const [deleteStep, setDeleteStep] = useState<0 | 1 | 2>(0);
  const [confirmName, setConfirmName] = useState("");

  const isActiveClub = clubStatus === "active";
  const lastPresidentBlocked = isPresident && presidentCount <= 1 && isActiveClub;

  return (
    <section className="space-y-4 lg:space-y-6">
      <PageIntro
        kicker="Settings"
        title="Club & membership"
        description="Leave this club, or if you are a President, archive or permanently delete it."
      />

      {query.success && (
        <div className="flex items-center gap-3 rounded-lg border border-emerald-200 bg-emerald-50 px-5 py-3.5 text-sm font-medium text-emerald-800">
          {decodeURIComponent(query.success.replace(/\+/g, " "))}
        </div>
      )}
      {query.error && (
        <div className="flex items-center gap-3 rounded-lg border border-red-200 bg-red-50 px-5 py-3.5 text-sm font-medium text-red-800">
          {decodeURIComponent(query.error.replace(/\+/g, " "))}
        </div>
      )}

      {!isActiveClub && (
        <div className="rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
          This club is <strong>archived</strong>. It stays in the database for history, but operational actions are
          disabled. You can still leave or delete the club if you have permission.
        </div>
      )}

      {isActiveClub && canManageJoinPolicy && (
        <CardSection className="surface-subcard border border-slate-200/90 sm:p-6">
          <h2 className="text-lg font-semibold text-slate-900">How people join</h2>
          <p className="mt-1 text-sm text-slate-600">
            Control whether the join code and invite link add members immediately or wait for officer approval.
          </p>
          <form action={updateClubJoinPolicyAction} className="mt-4 space-y-4">
            <input type="hidden" name="club_id" value={clubId} />
            <fieldset className="space-y-3">
              <legend className="sr-only">Join policy</legend>
              <label className="flex cursor-pointer gap-3 rounded-lg border border-slate-200 bg-white p-4 has-[:checked]:border-violet-400 has-[:checked]:ring-2 has-[:checked]:ring-violet-100">
                <input
                  type="radio"
                  name="require_join_approval"
                  value="false"
                  defaultChecked={!requireJoinApproval}
                  className="mt-1"
                />
                <span>
                  <span className="font-semibold text-slate-900">Instant join</span>
                  <span className="mt-1 block text-sm text-slate-600">
                    Anyone with the code or link becomes a member right away (current default).
                  </span>
                </span>
              </label>
              <label className="flex cursor-pointer gap-3 rounded-lg border border-slate-200 bg-white p-4 has-[:checked]:border-violet-400 has-[:checked]:ring-2 has-[:checked]:ring-violet-100">
                <input
                  type="radio"
                  name="require_join_approval"
                  value="true"
                  defaultChecked={requireJoinApproval}
                  className="mt-1"
                />
                <span>
                  <span className="font-semibold text-slate-900">Require approval</span>
                  <span className="mt-1 block text-sm text-slate-600">
                    New join attempts appear under Members → Pending join requests until an officer approves them.
                  </span>
                </span>
              </label>
            </fieldset>
            <button suppressHydrationWarning
              type="submit"
              className="inline-flex items-center justify-center rounded-lg bg-slate-900 px-4 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-slate-800"
            >
              Save join policy
            </button>
          </form>
        </CardSection>
      )}

      {/* Leave */}
      <CardSection className="surface-subcard border border-slate-200/90 sm:p-6">
        <h2 className="text-lg font-semibold text-slate-900">Leave club</h2>
        <p className="mt-1 text-sm text-slate-600">
          Removes your membership. Historical records (such as RSVPs you submitted) stay with the club where they
          already exist.
        </p>

        {lastPresidentBlocked ? (
          <div className="mt-4 space-y-4 rounded-lg border border-amber-200 bg-amber-50/90 p-4 text-sm text-amber-950">
            <p className="font-semibold">You are the last President of this active club</p>
            <p>
              An active club must keep at least one President. Choose one of the following before you can leave:
            </p>
            <ul className="list-inside list-disc space-y-2 text-amber-950/90">
              <li>
                <Link href={`/clubs/${clubId}/settings/governance`} className="font-semibold text-violet-700 underline">
                  Transfer presidency
                </Link>{" "}
                or add another President in Governance.
              </li>
              {canArchive && (
                <li>
                  <button suppressHydrationWarning
                    type="button"
                    className="font-semibold text-violet-700 underline"
                    onClick={() => setArchiveOpen(true)}
                  >
                    Archive the club
                  </button>{" "}
                  (inactive, read-only history) — then you can leave.
                </li>
              )}
              {canDelete && (
                <li>
                  <button suppressHydrationWarning
                    type="button"
                    className="font-semibold text-red-700 underline"
                    onClick={() => setDeleteStep(1)}
                  >
                    Permanently delete the club
                  </button>{" "}
                  (destructive).
                </li>
              )}
            </ul>
          </div>
        ) : (
          <>
            {!leaveOpen ? (
              <button suppressHydrationWarning
                type="button"
                onClick={() => setLeaveOpen(true)}
                className="mt-4 inline-flex items-center justify-center rounded-lg border border-slate-300 bg-white px-4 py-2.5 text-sm font-semibold text-slate-800 shadow-sm transition hover:bg-slate-50"
              >
                Leave club…
              </button>
            ) : (
              <form className="mt-4 space-y-3 rounded-lg border border-slate-200 bg-slate-50 p-4" action={leaveClubAction}>
                <input type="hidden" name="club_id" value={clubId} />
                <p className="text-sm font-medium text-slate-800">
                  {isPresident && isActiveClub
                    ? "You will lose President access and leave this club. Continue?"
                    : "Leave this club? You will need a new invite or join code to return."}
                </p>
                <div className="flex flex-wrap gap-2">
                  <button suppressHydrationWarning
                    type="submit"
                    className="inline-flex items-center justify-center rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800"
                  >
                    Yes, leave club
                  </button>
                  <button suppressHydrationWarning
                    type="button"
                    onClick={() => setLeaveOpen(false)}
                    className="rounded-lg px-4 py-2 text-sm font-semibold text-slate-600 hover:bg-slate-100"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            )}
          </>
        )}
      </CardSection>

      {/* Archive */}
      {isActiveClub && canArchive && (
        <div className="surface-subcard border border-amber-200/80 bg-amber-50/40 p-4 sm:p-6">
          <h2 className="text-lg font-semibold text-amber-950">Archive club</h2>
          <p className="mt-1 text-sm text-amber-950/80">
            The club disappears from active dashboards and lists. Joining via code or link is disabled. Members can
            still open it for read-only history until they leave.
          </p>
          {!archiveOpen ? (
            <button suppressHydrationWarning
              type="button"
              onClick={() => setArchiveOpen(true)}
              className="mt-4 inline-flex rounded-lg border border-amber-300 bg-white px-4 py-2.5 text-sm font-semibold text-amber-950 shadow-sm hover:bg-amber-100/60"
            >
              Archive club…
            </button>
          ) : (
            <form
              action={archiveClubAction}
              className="mt-4 space-y-3 rounded-lg border border-amber-200 bg-white p-4 shadow-sm"
            >
              <input type="hidden" name="club_id" value={clubId} />
              <p className="text-sm font-medium text-slate-900">Archive &ldquo;{clubName}&rdquo;?</p>
              <p className="text-sm text-slate-600">This cannot be undone from the member UI (contact support if needed).</p>
              <div className="flex flex-wrap gap-2">
                <button suppressHydrationWarning
                  type="submit"
                  className="inline-flex rounded-lg bg-amber-800 px-4 py-2 text-sm font-semibold text-white hover:bg-amber-900"
                >
                  Yes, archive this club
                </button>
                <button suppressHydrationWarning
                  type="button"
                  onClick={() => setArchiveOpen(false)}
                  className="rounded-lg px-4 py-2 text-sm font-semibold text-slate-600 hover:bg-slate-100"
                >
                  Cancel
                </button>
              </div>
            </form>
          )}
        </div>
      )}

      {/* Delete */}
      {canDelete && (
        <div className="surface-subcard border-2 border-red-200 bg-red-50/50 p-4 sm:p-6">
          <h2 className="text-lg font-semibold text-red-900">Delete club permanently</h2>
          <p className="mt-1 text-sm text-red-900/85">
            Deletes the club and related data according to your database rules (cascaded tables). This is far more
            destructive than archiving.
          </p>

          {deleteStep === 0 && (
            <button suppressHydrationWarning
              type="button"
              onClick={() => setDeleteStep(1)}
              className="mt-4 inline-flex rounded-lg border border-red-300 bg-white px-4 py-2.5 text-sm font-semibold text-red-800 shadow-sm hover:bg-red-100/60"
            >
              Delete club…
            </button>
          )}

          {deleteStep === 1 && (
            <div className="mt-4 space-y-3 rounded-lg border border-red-200 bg-white p-4 shadow-sm">
              <p className="text-sm font-semibold text-red-950">Step 1 — Warning</p>
              <p className="text-sm text-slate-700">
                You are about to delete <strong>{clubName}</strong>. Events, announcements, tasks, memberships, and
                other club-scoped data will be removed with the club.
              </p>
              <div className="flex flex-wrap gap-2">
                <button suppressHydrationWarning
                  type="button"
                  onClick={() => {
                    setDeleteStep(2);
                    setConfirmName("");
                  }}
                  className="inline-flex rounded-lg bg-red-700 px-4 py-2 text-sm font-semibold text-white hover:bg-red-800"
                >
                  I understand — continue
                </button>
                <button suppressHydrationWarning
                  type="button"
                  onClick={() => setDeleteStep(0)}
                  className="rounded-lg px-4 py-2 text-sm font-semibold text-slate-600 hover:bg-slate-100"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          {deleteStep === 2 && (
            <form action={deleteClubAction} className="mt-4 space-y-3 rounded-lg border border-red-300 bg-white p-4 shadow-sm">
              <input type="hidden" name="club_id" value={clubId} />
              <p className="text-sm font-semibold text-red-950">Step 2 — Type the club name</p>
              <p className="text-sm text-slate-700">
                Type <strong>{clubName}</strong> exactly to confirm.
              </p>
              <label htmlFor="confirm-club-delete-name" className="block text-sm font-medium text-slate-800">
                Club name
              </label>
              <input
                id="confirm-club-delete-name"
                name="confirm_name"
                value={confirmName}
                onChange={(e) => setConfirmName(e.target.value)}
                autoComplete="off"
                className="w-full max-w-md rounded-lg border border-slate-300 px-3 py-2 text-sm shadow-sm focus:border-red-400 focus:outline-none focus:ring-2 focus:ring-red-100"
                placeholder={clubName}
              />
              <div className="flex flex-wrap gap-2 pt-1">
                <button suppressHydrationWarning
                  type="submit"
                  disabled={confirmName.trim() !== clubName.trim()}
                  className="inline-flex rounded-lg bg-red-800 px-4 py-2 text-sm font-semibold text-white hover:bg-red-900 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  Permanently delete club
                </button>
                <button suppressHydrationWarning
                  type="button"
                  onClick={() => {
                    setDeleteStep(0);
                    setConfirmName("");
                  }}
                  className="rounded-lg px-4 py-2 text-sm font-semibold text-slate-600 hover:bg-slate-100"
                >
                  Cancel
                </button>
              </div>
            </form>
          )}
        </div>
      )}
    </section>
  );
}
