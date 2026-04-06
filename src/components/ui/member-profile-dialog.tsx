"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useId, useState } from "react";
import { createPortal } from "react-dom";
import { markMemberAlumniAction, removeMemberAction, updateMemberRoleAction } from "@/app/(app)/clubs/actions";
import {
  assignClubCommitteeMemberAction,
  removeClubCommitteeMemberAction,
} from "@/app/(app)/clubs/club-committee-actions";
import {
  assignClubTeamMemberAction,
  removeClubTeamMemberAction,
} from "@/app/(app)/clubs/club-team-actions";
import {
  assignClubMemberTagAction,
  createClubMemberTagAction,
  deleteClubMemberTagAction,
  removeClubMemberTagAction,
} from "@/app/(app)/clubs/member-tag-actions";
import type { ClubMember, ClubCommitteeSummary, ClubMemberTag, ClubTeamSummary } from "@/lib/clubs/queries";
import { getMemberRosterDisplayName, getMemberRosterInitials } from "@/lib/member-display";
import type { MemberWithRoles } from "@/lib/rbac/role-actions";

type MemberProfileDialogProps = {
  open: boolean;
  onClose: () => void;
  member: ClubMember | null;
  clubId: string;
  currentUserId: string;
  rbacRoles: MemberWithRoles["rbacRoles"];
  isPresident: boolean;
  isArchived: boolean;
  canAssignRoles: boolean;
  canRemoveMembers: boolean;
  memberTagDefinitions: ClubMemberTag[];
  canManageMemberTags: boolean;
  clubCommittees: ClubCommitteeSummary[];
  canManageCommittees: boolean;
  clubTeams: ClubTeamSummary[];
  canManageTeams: boolean;
};

function formatJoinedAt(iso: string | null): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return d.toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function MemberProfileTagsBlock({
  clubId,
  member,
  memberTagDefinitions,
  canManage,
}: {
  clubId: string;
  member: ClubMember;
  memberTagDefinitions: ClubMemberTag[];
  canManage: boolean;
}) {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const tags = member.tags ?? [];
  const assignedIds = new Set(tags.map((t) => t.id));
  const availableToAdd = memberTagDefinitions.filter((t) => !assignedIds.has(t.id));

  return (
    <section className="mb-5">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Tags</h3>
      <p className="mt-1 text-xs text-slate-500">Club labels for organizing members — separate from roles.</p>
      {tags.length > 0 ? (
        <ul className="mt-2 flex flex-wrap gap-2">
          {tags.map((tag) => (
            <li
              key={tag.id}
              className="inline-flex items-center gap-0.5 rounded-full border border-sky-200 bg-sky-50 px-2.5 py-1 text-xs font-semibold text-sky-900"
            >
              <span>{tag.name}</span>
              {canManage ? (
                <button
                  type="button"
                  className="ml-0.5 rounded px-1 text-sky-700 hover:bg-sky-100"
                  aria-label={`Remove ${tag.name}`}
                  onClick={async () => {
                    const fd = new FormData();
                    fd.set("club_id", clubId);
                    fd.set("tag_id", tag.id);
                    fd.set("user_id", member.userId);
                    setError(null);
                    const r = await removeClubMemberTagAction(fd);
                    if (r.ok) router.refresh();
                    else setError(r.error);
                  }}
                >
                  ×
                </button>
              ) : null}
            </li>
          ))}
        </ul>
      ) : !canManage ? (
        <p className="mt-2 text-sm text-slate-500">No tags yet.</p>
      ) : null}

      {error ? <p className="mt-2 text-xs text-red-600">{error}</p> : null}

      {canManage ? (
        <div className="mt-4 space-y-3 border-t border-slate-100 pt-4">
          {availableToAdd.length > 0 ? (
            <form
              className="flex flex-wrap items-end gap-2"
              action={async (fd) => {
                setError(null);
                const r = await assignClubMemberTagAction(fd);
                if (r.ok) router.refresh();
                else setError(r.error);
              }}
            >
              <input type="hidden" name="club_id" value={clubId} />
              <input type="hidden" name="user_id" value={member.userId} />
              <label className="sr-only" htmlFor={`add-tag-${member.userId}`}>
                Add tag
              </label>
              <select
                id={`add-tag-${member.userId}`}
                name="tag_id"
                className="rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-sm text-slate-900"
                defaultValue=""
                required
              >
                <option value="" disabled>
                  Add a tag…
                </option>
                {availableToAdd.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name}
                  </option>
                ))}
              </select>
              <button type="submit" className="btn-secondary text-xs">
                Add
              </button>
            </form>
          ) : null}

          <form
            className="flex flex-wrap items-end gap-2"
            action={async (fd) => {
              setError(null);
              const r = await createClubMemberTagAction(fd);
              if (r.ok) router.refresh();
              else setError(r.error);
            }}
          >
            <input type="hidden" name="club_id" value={clubId} />
            <label className="sr-only" htmlFor={`new-tag-${member.userId}`}>
              New tag name
            </label>
            <input
              id={`new-tag-${member.userId}`}
              name="name"
              placeholder="New tag name"
              className="min-w-[160px] flex-1 rounded-lg border border-slate-200 px-2 py-1.5 text-sm text-slate-900"
              maxLength={40}
              autoComplete="off"
            />
            <button type="submit" className="btn-secondary text-xs">
              Create tag
            </button>
          </form>

          {memberTagDefinitions.length > 0 ? (
            <details className="text-xs text-slate-600">
              <summary className="cursor-pointer font-semibold text-slate-700">Remove tags from club</summary>
              <ul className="mt-2 space-y-1.5">
                {memberTagDefinitions.map((t) => (
                  <li key={t.id} className="flex items-center justify-between gap-2 rounded-lg bg-slate-50 px-2 py-1">
                    <span className="font-medium text-slate-800">{t.name}</span>
                    <button
                      type="button"
                      className="shrink-0 font-semibold text-red-700 hover:underline"
                      onClick={async () => {
                        if (!confirm(`Remove “${t.name}” from this club for all members?`)) return;
                        const fd = new FormData();
                        fd.set("club_id", clubId);
                        fd.set("tag_id", t.id);
                        setError(null);
                        const r = await deleteClubMemberTagAction(fd);
                        if (r.ok) router.refresh();
                        else setError(r.error);
                      }}
                    >
                      Remove
                    </button>
                  </li>
                ))}
              </ul>
            </details>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}

function MemberProfileCommitteesBlock({
  clubId,
  member,
  clubCommittees,
  canManage,
}: {
  clubId: string;
  member: ClubMember;
  clubCommittees: ClubCommitteeSummary[];
  canManage: boolean;
}) {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const assigned = member.committees ?? [];
  const assignedIds = new Set(assigned.map((c) => c.id));
  const availableToAdd = clubCommittees.filter((c) => !assignedIds.has(c.id));

  if (clubCommittees.length === 0 && assigned.length === 0 && !canManage) {
    return null;
  }

  return (
    <section className="mb-5">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Committees</h3>
      <p className="mt-1 text-xs text-slate-500">
        Club subgroups — create and rename committees from the Members page.
      </p>
      {assigned.length > 0 ? (
        <ul className="mt-2 flex flex-wrap gap-2">
          {assigned.map((c) => (
            <li
              key={c.id}
              className="inline-flex items-center gap-0.5 rounded-full border border-teal-200 bg-teal-50 px-2.5 py-1 text-xs font-semibold text-teal-900"
            >
              <span>{c.name}</span>
              {canManage ? (
                <button
                  type="button"
                  className="ml-0.5 rounded px-1 text-teal-800 hover:bg-teal-100"
                  aria-label={`Remove ${c.name}`}
                  onClick={async () => {
                    const fd = new FormData();
                    fd.set("club_id", clubId);
                    fd.set("committee_id", c.id);
                    fd.set("user_id", member.userId);
                    setError(null);
                    const r = await removeClubCommitteeMemberAction(fd);
                    if (r.ok) router.refresh();
                    else setError(r.error);
                  }}
                >
                  ×
                </button>
              ) : null}
            </li>
          ))}
        </ul>
      ) : !canManage ? (
        <p className="mt-2 text-sm text-slate-500">Not assigned to any committees.</p>
      ) : null}

      {error ? <p className="mt-2 text-xs text-red-600">{error}</p> : null}

      {canManage && clubCommittees.length === 0 ? (
        <p className="mt-3 text-xs text-slate-500">Create a committee on the Members page to assign this person.</p>
      ) : null}

      {canManage && availableToAdd.length > 0 ? (
        <form
          className="mt-4 flex flex-wrap items-end gap-2 border-t border-slate-100 pt-4"
          action={async (fd) => {
            setError(null);
            const r = await assignClubCommitteeMemberAction(fd);
            if (r.ok) router.refresh();
            else setError(r.error);
          }}
        >
          <input type="hidden" name="club_id" value={clubId} />
          <input type="hidden" name="user_id" value={member.userId} />
          <label className="sr-only" htmlFor={`add-committee-${member.userId}`}>
            Add to committee
          </label>
          <select
            id={`add-committee-${member.userId}`}
            name="committee_id"
            className="rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-sm text-slate-900"
            defaultValue=""
            required
          >
            <option value="" disabled>
              Add to committee…
            </option>
            {availableToAdd.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </select>
          <button type="submit" className="btn-secondary text-xs">
            Add
          </button>
        </form>
      ) : null}
    </section>
  );
}

function MemberProfileTeamsBlock({
  clubId,
  member,
  clubTeams,
  canManage,
}: {
  clubId: string;
  member: ClubMember;
  clubTeams: ClubTeamSummary[];
  canManage: boolean;
}) {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const assigned = member.teams ?? [];
  const assignedIds = new Set(assigned.map((t) => t.id));
  const availableToAdd = clubTeams.filter((t) => !assignedIds.has(t.id));

  if (clubTeams.length === 0 && assigned.length === 0 && !canManage) {
    return null;
  }

  return (
    <section className="mb-5">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Teams</h3>
      <p className="mt-1 text-xs text-slate-500">
        Distinct from committees — create and rename teams from the Members page.
      </p>
      {assigned.length > 0 ? (
        <ul className="mt-2 flex flex-wrap gap-2">
          {assigned.map((t) => (
            <li
              key={t.id}
              className="inline-flex items-center gap-0.5 rounded-full border border-rose-200 bg-rose-50 px-2.5 py-1 text-xs font-semibold text-rose-900"
            >
              <span>{t.name}</span>
              {canManage ? (
                <button
                  type="button"
                  className="ml-0.5 rounded px-1 text-rose-800 hover:bg-rose-100"
                  aria-label={`Remove ${t.name}`}
                  onClick={async () => {
                    const fd = new FormData();
                    fd.set("club_id", clubId);
                    fd.set("team_id", t.id);
                    fd.set("user_id", member.userId);
                    setError(null);
                    const r = await removeClubTeamMemberAction(fd);
                    if (r.ok) router.refresh();
                    else setError(r.error);
                  }}
                >
                  ×
                </button>
              ) : null}
            </li>
          ))}
        </ul>
      ) : !canManage ? (
        <p className="mt-2 text-sm text-slate-500">Not on any teams.</p>
      ) : null}

      {error ? <p className="mt-2 text-xs text-red-600">{error}</p> : null}

      {canManage && clubTeams.length === 0 ? (
        <p className="mt-3 text-xs text-slate-500">Create a team on the Members page to assign this person.</p>
      ) : null}

      {canManage && availableToAdd.length > 0 ? (
        <form
          className="mt-4 flex flex-wrap items-end gap-2 border-t border-slate-100 pt-4"
          action={async (fd) => {
            setError(null);
            const r = await assignClubTeamMemberAction(fd);
            if (r.ok) router.refresh();
            else setError(r.error);
          }}
        >
          <input type="hidden" name="club_id" value={clubId} />
          <input type="hidden" name="user_id" value={member.userId} />
          <label className="sr-only" htmlFor={`add-team-${member.userId}`}>
            Add to team
          </label>
          <select
            id={`add-team-${member.userId}`}
            name="team_id"
            className="rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-sm text-slate-900"
            defaultValue=""
            required
          >
            <option value="" disabled>
              Add to team…
            </option>
            {availableToAdd.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name}
              </option>
            ))}
          </select>
          <button type="submit" className="btn-secondary text-xs">
            Add
          </button>
        </form>
      ) : null}
    </section>
  );
}

/**
 * Lightweight member profile: modal overlay (portal) for roster.
 * Email is shown only for the signed-in member’s own profile (privacy).
 */
export function MemberProfileDialog({
  open,
  onClose,
  member,
  clubId,
  currentUserId,
  rbacRoles,
  isPresident,
  isArchived,
  canAssignRoles,
  canRemoveMembers,
  memberTagDefinitions,
  canManageMemberTags,
  clubCommittees,
  canManageCommittees,
  clubTeams,
  canManageTeams,
}: MemberProfileDialogProps) {
  const [mounted, setMounted] = useState(false);
  const titleId = useId();

  useEffect(() => setMounted(true), []);

  useEffect(() => {
    if (!open) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = prev;
    };
  }, [open]);

  useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!mounted || !open || !member) {
    return null;
  }

  const isCurrentUser = member.userId === currentUserId;
  const isAlumni = member.membershipStatus === "alumni";
  const isOfficer = member.role === "officer" && !isAlumni;
  const significantRbacRoles = rbacRoles.filter(
    (r) => !(r.isSystem && (r.roleName === "Officer" || r.roleName === "Member")),
  );
  const showManagement = !isArchived && !isCurrentUser && (canAssignRoles || canRemoveMembers);
  const showTagManagement = canManageMemberTags && !isArchived;
  const showCommitteeManagement = canManageCommittees && !isArchived;
  const showTeamManagement = canManageTeams && !isArchived;
  const joinedLabel = formatJoinedAt(member.joinedAt);

  const panel = (
    <div
      className="fixed inset-0 z-[100] flex items-end justify-center p-0 sm:items-center sm:p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby={titleId}
    >
      <button
        type="button"
        className="absolute inset-0 bg-slate-900/50 backdrop-blur-[2px]"
        aria-label="Close profile"
        onClick={onClose}
      />

      <div className="relative z-10 flex max-h-[min(90vh,720px)] w-full max-w-lg flex-col overflow-hidden rounded-t-2xl border border-slate-200 bg-white shadow-2xl sm:rounded-2xl">
        <div className="flex items-start justify-between gap-3 border-b border-slate-100 bg-gradient-to-br from-slate-50 to-indigo-50/40 px-5 py-4 sm:px-6">
          <div className="flex min-w-0 items-start gap-3">
            <div
              className={`flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl text-lg font-bold text-white shadow-sm ${
                isOfficer ? "bg-gradient-to-br from-indigo-600 to-violet-600" : "bg-gradient-to-br from-slate-600 to-slate-700"
              } ${isCurrentUser ? "ring-2 ring-indigo-300 ring-offset-2" : ""}`}
            >
              {getMemberRosterInitials(member)}
            </div>
            <div className="min-w-0 pt-0.5">
              <p className="section-kicker text-slate-600">Member</p>
              <h2 id={titleId} className="text-lg font-bold tracking-tight text-slate-900 sm:text-xl">
                {getMemberRosterDisplayName(member)}
              </h2>
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <span className={`member-role-pill ${isOfficer ? "is-officer" : "is-member"}`}>{member.role}</span>
                {isAlumni ? (
                  <span className="inline-flex items-center rounded-full border border-amber-200 bg-amber-50 px-2 py-0.5 text-[11px] font-semibold text-amber-900">
                    Alumni
                  </span>
                ) : (
                  <span className="inline-flex items-center rounded-full border border-emerald-200 bg-emerald-50 px-2 py-0.5 text-[11px] font-semibold text-emerald-800">
                    Active
                  </span>
                )}
                {isCurrentUser ? <span className="member-you-pill">You</span> : null}
              </div>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="flex h-10 min-w-10 shrink-0 items-center justify-center rounded-xl text-slate-500 transition hover:bg-slate-200/80 hover:text-slate-800"
            aria-label="Close"
          >
            <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4 sm:px-6">
          {isCurrentUser && member.email ? (
            <section className="mb-5">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Your account</h3>
              <p className="mt-1 break-all text-sm text-slate-800">{member.email}</p>
            </section>
          ) : !isCurrentUser ? (
            <p className="mb-5 text-xs leading-relaxed text-slate-500">
              Other members’ contact details are not shown here to protect privacy.
            </p>
          ) : null}

          {joinedLabel ? (
            <section className="mb-5">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">In this club since</h3>
              <p className="mt-1 text-sm font-medium text-slate-800">{joinedLabel}</p>
            </section>
          ) : null}

          {significantRbacRoles.length > 0 ? (
            <section className="mb-5">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Roles</h3>
              <ul className="mt-2 flex flex-wrap gap-2">
                {significantRbacRoles.map((r) => (
                  <li
                    key={r.roleId}
                    className={`inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-semibold ${
                      r.roleName === "President"
                        ? "border-violet-200 bg-violet-50 text-violet-700"
                        : "border-emerald-200 bg-emerald-50 text-emerald-700"
                    }`}
                  >
                    {r.roleName}
                  </li>
                ))}
              </ul>
            </section>
          ) : null}

          <MemberProfileTagsBlock
            clubId={clubId}
            member={member}
            memberTagDefinitions={memberTagDefinitions}
            canManage={showTagManagement}
          />

          <MemberProfileCommitteesBlock
            clubId={clubId}
            member={member}
            clubCommittees={clubCommittees}
            canManage={showCommitteeManagement}
          />

          <MemberProfileTeamsBlock
            clubId={clubId}
            member={member}
            clubTeams={clubTeams}
            canManage={showTeamManagement}
          />

          <section className="mb-2">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Attendance (tracked events)</h3>
            {member.totalTrackedEvents > 0 ? (
              <div className="mt-2">
                <p className="text-sm font-medium text-slate-800">
                  {member.attendanceCount} of {member.totalTrackedEvents} events · {member.attendanceRate}%
                </p>
                <div className="mt-2 h-2 overflow-hidden rounded-full bg-slate-100">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-emerald-400 to-emerald-500"
                    style={{ width: `${member.attendanceRate}%` }}
                  />
                </div>
              </div>
            ) : (
              <p className="mt-1 text-sm text-slate-500">No tracked past events yet for this club.</p>
            )}
          </section>

          {isPresident && !isAlumni ? (
            <p className="mt-4 text-xs text-slate-500">
              <Link href={`/clubs/${clubId}/settings`} className="font-semibold text-indigo-700 underline-offset-2 hover:underline">
                Manage roles in Settings
              </Link>
            </p>
          ) : null}
        </div>

        {showManagement ? (
          <div className="border-t border-slate-100 bg-slate-50/80 px-5 py-4 sm:px-6">
            <p className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-500">Actions</p>
            <div className="flex flex-wrap gap-2">
              {canAssignRoles && member.membershipStatus === "active" &&
                (member.role === "member" ? (
                  <form action={updateMemberRoleAction}>
                    <input type="hidden" name="club_id" value={clubId} />
                    <input type="hidden" name="user_id" value={member.userId} />
                    <input type="hidden" name="role" value="officer" />
                    <button type="submit" className="btn-secondary text-xs">
                      Promote to Officer
                    </button>
                  </form>
                ) : (
                  <form action={updateMemberRoleAction}>
                    <input type="hidden" name="club_id" value={clubId} />
                    <input type="hidden" name="user_id" value={member.userId} />
                    <input type="hidden" name="role" value="member" />
                    <button type="submit" className="btn-secondary text-xs">
                      Demote to Member
                    </button>
                  </form>
                ))}
              {canRemoveMembers && member.membershipStatus === "active" && (
                <form action={markMemberAlumniAction}>
                  <input type="hidden" name="club_id" value={clubId} />
                  <input type="hidden" name="user_id" value={member.userId} />
                  <button type="submit" className="btn-secondary text-xs">
                    Mark as alumni
                  </button>
                </form>
              )}
              {canRemoveMembers && (
                <form action={removeMemberAction}>
                  <input type="hidden" name="club_id" value={clubId} />
                  <input type="hidden" name="user_id" value={member.userId} />
                  <button type="submit" className="btn-danger text-xs">
                    {isAlumni ? "Remove from roster" : "Remove from club"}
                  </button>
                </form>
              )}
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );

  return createPortal(panel, document.body);
}
