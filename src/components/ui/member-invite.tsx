"use client";

import { CopyJoinCodeButton } from "@/components/ui/copy-join-code-button";
import { CopyInviteLinkButton } from "@/components/ui/copy-invite-link-button";

type MemberInviteProps = {
  joinCode: string;
  membersCount: number;
  requireJoinApproval?: boolean;
};

export function MemberInvite({ joinCode, membersCount, requireJoinApproval = false }: MemberInviteProps) {
  const isLowMembers = membersCount <= 5;

  return (
    <div className="card-surface p-6">
      <div className="section-card-header">
        <div>
          <p className="section-kicker">Invite</p>
          <h3 className="mt-1 text-base font-semibold tracking-tight text-slate-900">Add Members</h3>
          <p className="mt-1 text-sm text-slate-600">
            Share these details to invite people into your club.
          </p>
          {requireJoinApproval ? (
            <p className="mt-2 rounded-lg border border-amber-200 bg-amber-50/90 px-3 py-2 text-xs font-medium text-amber-950">
              This club requires officer approval before new members are added. Invitees will appear in{" "}
              <strong>Pending join requests</strong> until someone approves them.
            </p>
          ) : null}
        </div>
        {isLowMembers && (
          <span className="feedback-pill feedback-pill-fresh">Let&apos;s grow</span>
        )}
      </div>

      <div className="mt-5 space-y-4">
        <div>
          <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Join Code</p>
          <div className="rounded-xl border border-slate-200 bg-gradient-to-b from-slate-50 to-white px-6 py-5 text-center shadow-inner">
            <p className="font-mono text-3xl font-bold tracking-[0.22em] text-slate-900 select-all">
              {joinCode}
            </p>
          </div>
        </div>

        <div className="flex flex-col gap-2.5 sm:flex-row">
          <CopyJoinCodeButton joinCode={joinCode} className="btn-secondary flex-1" />
          <CopyInviteLinkButton joinCode={joinCode} className="btn-secondary flex-1">
            Copy Invite Link
          </CopyInviteLinkButton>
        </div>

        {isLowMembers && (
          <p className="rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            <strong className="text-slate-900">Tip:</strong> Share the code in class or post the invite link to grow your membership quickly.
          </p>
        )}
      </div>
    </div>
  );
}
