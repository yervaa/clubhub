import Link from "next/link";
import { removeMemberAction, updateMemberRoleAction } from "@/app/(app)/clubs/actions";
import { GettingStartedChecklist } from "@/components/ui/getting-started-checklist";
import { MemberInvite } from "@/components/ui/member-invite";
import type { ClubDetail } from "@/lib/clubs/queries";
import { getMemberDisplayName, getMemberInitials, getMemberSecondaryText } from "@/lib/member-display";
import type { MemberWithRoles } from "@/lib/rbac/role-actions";

type ClubMembersPermissions = {
  canInviteMembers: boolean;
  canRemoveMembers: boolean;
  canAssignRoles: boolean;
  canViewInsights?: boolean;
};

type ClubMembersSectionProps = {
  club: ClubDetail;
  query: {
    memberError?: string;
    memberSuccess?: string;
  };
  rbacByUser?: Record<string, MemberWithRoles["rbacRoles"]>;
  isPresident?: boolean;
  permissions?: ClubMembersPermissions;
};

export function ClubMembersSection({ club, query, rbacByUser = {}, isPresident = false, permissions }: ClubMembersSectionProps) {
  const memberCount = club.memberCount;
  const officerCount = club.members.filter((m) => m.role === "officer").length;
  const regularMemberCount = memberCount - officerCount;
  const setupDone = memberCount > 1 && club.announcements.length > 0 && club.events.length > 0;

  // RBAC-based permission checks with legacy officer fallback.
  const legacyIsOfficer = club.currentUserRole === "officer";
  const canInviteMembers = permissions?.canInviteMembers ?? legacyIsOfficer;
  const canRemoveMembers = permissions?.canRemoveMembers ?? legacyIsOfficer;
  const canAssignRoles = permissions?.canAssignRoles ?? legacyIsOfficer;

  // A user can see management controls if they have at least one management permission.
  const hasAnyManagementPermission = canInviteMembers || canRemoveMembers || canAssignRoles;

  return (
    <section className="space-y-6">

      {/* Page header */}
      <header className="card-surface border-2 border-slate-200 bg-gradient-to-br from-slate-50 to-indigo-50 p-5 sm:p-8">
        <div className="max-w-4xl">
          <p className="section-kicker text-slate-600">People</p>
          <h1 className="section-title mt-2 text-2xl sm:mt-3 sm:text-3xl md:text-4xl">Members</h1>
          <p className="section-subtitle mt-3 max-w-2xl text-base sm:mt-4 sm:text-lg text-slate-700">
            {hasAnyManagementPermission
              ? "Manage who is in this club, review attendance history, and invite new members."
              : "See who is part of this club and how everyone is doing."}
          </p>

          <div className="mt-6 grid grid-cols-2 gap-4 sm:mt-8 sm:flex sm:flex-wrap sm:items-center sm:gap-8">
            <div>
              <p className="text-2xl font-bold text-slate-900">{memberCount}</p>
              <p className="mt-1 text-xs font-semibold uppercase tracking-[0.1em] text-slate-500">
                {memberCount === 1 ? "Member" : "Members"}
              </p>
            </div>

            <div className="hidden h-8 w-px bg-slate-200 sm:block" aria-hidden />

            <div>
              <p className="text-2xl font-bold text-slate-900">{officerCount}</p>
              <p className="mt-1 text-xs font-semibold uppercase tracking-[0.1em] text-slate-500">
                {officerCount === 1 ? "Officer" : "Officers"}
              </p>
            </div>

            {club.totalTrackedEvents > 0 && (
              <>
                <div className="hidden h-8 w-px bg-slate-200 sm:block" aria-hidden />
                <div className="col-span-2 sm:col-span-1">
                  <p className="text-2xl font-bold text-slate-900">{club.clubAverageAttendance}%</p>
                  <p className="mt-1 text-xs font-semibold uppercase tracking-[0.1em] text-slate-500">Avg. Attendance</p>
                </div>
              </>
            )}
          </div>

          {canInviteMembers && (
            <div className="mt-6 sm:mt-8">
              <a
                href="#invite-members"
                className="btn-primary block w-full px-6 py-3 text-center text-base font-semibold sm:inline-block sm:w-auto"
              >
                Invite Members
              </a>
            </div>
          )}
        </div>
      </header>

      {/* Invite tools — requires members.invite permission */}
      {canInviteMembers && (
        <section id="invite-members">
          <MemberInvite joinCode={club.joinCode} membersCount={memberCount} />
        </section>
      )}

      {/* Getting started — management users only, hidden once all steps are done */}
      {hasAnyManagementPermission && !setupDone && (
        <GettingStartedChecklist
          clubId={club.id}
          membersCount={memberCount}
          announcementsCount={club.announcements.length}
          eventsCount={club.events.length}
        />
      )}

      {/* Member roster */}
      <div className="card-surface p-5" id="members">
        <div className="section-card-header">
          <div>
            <p className="section-kicker">Roster</p>
            <h2 className="mt-1 text-base font-semibold tracking-tight text-slate-900">All Members</h2>
            <p className="mt-1 text-sm text-slate-600">
              {officerCount} {officerCount === 1 ? "officer" : "officers"}
              {regularMemberCount > 0
                ? ` · ${regularMemberCount} ${regularMemberCount === 1 ? "member" : "members"}`
                : null}
              {hasAnyManagementPermission ? " — officers are listed first" : null}
            </p>
          </div>
          <span className="badge-soft">{memberCount} total</span>
        </div>

        {query.memberSuccess ? <p className="alert-success mt-4">{query.memberSuccess}</p> : null}
        {query.memberError ? <p className="alert-error mt-3">{query.memberError}</p> : null}

        {memberCount === 0 ? (
          <div className="mt-4 rounded-xl border border-dashed border-slate-200 bg-slate-50/60 p-8 text-center">
            <p className="font-semibold text-slate-900">No members yet</p>
            <p className="mt-1 text-sm text-slate-500">
              {canInviteMembers
                ? "Share your join code above to invite people."
                : "You're the first one here."}
            </p>
          </div>
        ) : (
          <ul className="list-stack mt-4">
            {club.members.map((member) => {
              const isCurrentUser = member.userId === club.currentUserId;
              const isOfficer = member.role === "officer";

              const rbacRoles = rbacByUser[member.userId] ?? [];
              // Show non-redundant RBAC badges: skip the "Officer"/"Member" system
              // roles since the legacy role pill already communicates that.
              const significantRbacRoles = rbacRoles.filter(
                (r) => !(r.isSystem && (r.roleName === "Officer" || r.roleName === "Member")),
              );

              return (
                <li
                  key={member.userId}
                  className={`member-card ${isOfficer ? "is-officer" : ""} ${isCurrentUser ? "is-current-user" : ""}`}
                >
                  {/* Identity row */}
                  <div className="flex items-start gap-3">
                    <div className={`member-avatar ${isOfficer ? "is-officer" : ""} ${isCurrentUser ? "is-current-user" : ""}`}>
                      {getMemberInitials(member)}
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <p className="text-base font-semibold tracking-tight text-slate-950">
                          {getMemberDisplayName(member)}
                        </p>
                        <span className={`member-role-pill ${isOfficer ? "is-officer" : "is-member"}`}>
                          {member.role}
                        </span>
                        {isCurrentUser ? <span className="member-you-pill">You</span> : null}

                        {/* RBAC role badges (President + custom roles only) */}
                        {significantRbacRoles.map((r) => (
                          <span
                            key={r.roleId}
                            className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold ${
                              r.roleName === "President"
                                ? "border-violet-200 bg-violet-50 text-violet-700"
                                : "border-emerald-200 bg-emerald-50 text-emerald-700"
                            }`}
                          >
                            {r.roleName}
                          </span>
                        ))}
                      </div>
                      <p className="mt-1 truncate text-sm text-slate-500">{getMemberSecondaryText(member)}</p>
                    </div>

                    {/* Manage roles link — Presidents only */}
                    {isPresident && (
                      <Link
                        href={`/clubs/${club.id}/settings`}
                        className="ml-auto shrink-0 text-xs font-semibold text-slate-400 transition-colors hover:text-slate-700"
                        title="Manage roles in Settings"
                      >
                        <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                        </svg>
                      </Link>
                    )}
                  </div>

                  {/* Attendance */}
                  <div className="mt-3 pl-14">
                    {member.totalTrackedEvents > 0 ? (
                      <div>
                        <div className="mb-1.5 flex items-center justify-between gap-2">
                          <span className="text-xs font-semibold uppercase tracking-[0.1em] text-slate-400">Attendance</span>
                          <span className="text-xs font-semibold text-slate-600">
                            {member.attendanceCount}/{member.totalTrackedEvents} events · {member.attendanceRate}%
                          </span>
                        </div>
                        <div className="h-1.5 overflow-hidden rounded-full bg-slate-100">
                          <div
                            className="h-full rounded-full bg-gradient-to-r from-emerald-400 to-emerald-500 transition-[width] duration-300"
                            style={{ width: `${member.attendanceRate}%` }}
                          />
                        </div>
                      </div>
                    ) : (
                      <p className="text-xs text-slate-400">No tracked events yet</p>
                    )}
                  </div>

                  {/* Member management actions — gated per permission */}
                  {!isCurrentUser && (canAssignRoles || canRemoveMembers) ? (
                    <div className="member-card-actions">
                      {/* Role promotion/demotion — requires members.assign_roles */}
                      {canAssignRoles && (
                        member.role === "member" ? (
                          <form action={updateMemberRoleAction}>
                            <input type="hidden" name="club_id" value={club.id} />
                            <input type="hidden" name="user_id" value={member.userId} />
                            <input type="hidden" name="role" value="officer" />
                            <button type="submit" className="btn-secondary text-xs">
                              Promote to Officer
                            </button>
                          </form>
                        ) : (
                          <form action={updateMemberRoleAction}>
                            <input type="hidden" name="club_id" value={club.id} />
                            <input type="hidden" name="user_id" value={member.userId} />
                            <input type="hidden" name="role" value="member" />
                            <button type="submit" className="btn-secondary text-xs">
                              Demote to Member
                            </button>
                          </form>
                        )
                      )}
                      {/* Remove — requires members.remove */}
                      {canRemoveMembers && (
                        <form action={removeMemberAction}>
                          <input type="hidden" name="club_id" value={club.id} />
                          <input type="hidden" name="user_id" value={member.userId} />
                          <button type="submit" className="btn-danger text-xs">
                            Remove from Club
                          </button>
                        </form>
                      )}
                    </div>
                  ) : null}
                </li>
              );
            })}
          </ul>
        )}
      </div>

    </section>
  );
}
