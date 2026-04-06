"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { markMemberAlumniAction, removeMemberAction, updateMemberRoleAction } from "@/app/(app)/clubs/actions";
import { ClubCommitteesPanel } from "@/components/ui/club-committees-panel";
import { ClubTeamsPanel } from "@/components/ui/club-teams-panel";
import { GettingStartedChecklist } from "@/components/ui/getting-started-checklist";
import { ClubJoinRequestsPanel } from "@/components/ui/club-join-requests-panel";
import { MemberInvite } from "@/components/ui/member-invite";
import { MemberProfileDialog } from "@/components/ui/member-profile-dialog";
import type { ClubDetail, ClubMember, PendingJoinRequest } from "@/lib/clubs/queries";
import { getMemberRosterDisplayName, getMemberRosterInitials } from "@/lib/member-display";
import type { MemberWithRoles } from "@/lib/rbac/role-actions";

/** Role filter uses real data only: legacy `club_members.role` + RBAC President. */
type RosterRoleFilter = "all" | "president" | "officer" | "member";

/** Membership lifecycle filter (active vs alumni). */
type RosterStatusFilter = "all" | "active" | "alumni";

function hasRbacPresident(rbacRoles: MemberWithRoles["rbacRoles"]): boolean {
  return rbacRoles.some((r) => r.roleName === "President" && r.isSystem);
}

function memberMatchesStatusFilter(member: ClubMember, filter: RosterStatusFilter): boolean {
  if (filter === "all") return true;
  if (filter === "active") return member.membershipStatus === "active";
  if (filter === "alumni") return member.membershipStatus === "alumni";
  return true;
}

function memberMatchesRoleFilter(
  member: ClubMember,
  rbacRoles: MemberWithRoles["rbacRoles"],
  filter: RosterRoleFilter,
): boolean {
  if (filter === "all") return true;
  const isPres = hasRbacPresident(rbacRoles);
  if (filter === "president") return isPres;
  if (filter === "officer") return member.role === "officer" && !isPres;
  if (filter === "member") return member.role === "member";
  return true;
}

function memberMatchesRosterSearch(
  member: ClubMember,
  rbacRoles: MemberWithRoles["rbacRoles"],
  queryLower: string,
): boolean {
  const name = member.fullName?.trim().toLowerCase() ?? "";
  const email = member.email?.trim().toLowerCase() ?? "";
  const legacyRole = member.role.toLowerCase();
  const display = getMemberRosterDisplayName(member).toLowerCase();
  const rbacNames = rbacRoles.map((r) => r.roleName.toLowerCase()).join(" ");
  const status = member.membershipStatus === "alumni" ? "alumni" : "";
  const tagNames = (member.tags ?? []).map((t) => t.name.toLowerCase()).join(" ");
  const committeeNames = (member.committees ?? []).map((c) => c.name.toLowerCase()).join(" ");
  const teamNames = (member.teams ?? []).map((t) => t.name.toLowerCase()).join(" ");
  const haystack = [name, email, legacyRole, display, rbacNames, status, tagNames, committeeNames, teamNames].join(" ");
  return haystack.includes(queryLower);
}

type ClubMembersPermissions = {
  canInviteMembers: boolean;
  canRemoveMembers: boolean;
  canAssignRoles: boolean;
  canViewInsights?: boolean;
  canManageMemberTags?: boolean;
  canManageCommittees?: boolean;
  canManageTeams?: boolean;
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
  pendingJoinRequests?: PendingJoinRequest[];
};

export function ClubMembersSection({
  club,
  query,
  rbacByUser = {},
  isPresident = false,
  permissions,
  pendingJoinRequests = [],
}: ClubMembersSectionProps) {
  const [rosterSearch, setRosterSearch] = useState("");
  const [roleFilter, setRoleFilter] = useState<RosterRoleFilter>("all");
  const [statusFilter, setStatusFilter] = useState<RosterStatusFilter>("all");
  const [profileUserId, setProfileUserId] = useState<string | null>(null);

  const activeMembers = club.members.filter((m) => m.membershipStatus === "active");
  const alumniCount = club.members.length - activeMembers.length;
  const memberCount = activeMembers.length;
  const officerCount = activeMembers.filter((m) => m.role === "officer").length;
  const regularMemberCount = activeMembers.filter((m) => m.role === "member").length;
  const rosterTotalCount = club.members.length;
  const setupDone = memberCount > 1 && club.announcements.length > 0 && club.events.length > 0;

  // RBAC-based permission checks with legacy officer fallback.
  const legacyIsOfficer = club.currentUserRole === "officer";
  const canInviteMembers = permissions?.canInviteMembers ?? legacyIsOfficer;
  const canRemoveMembers = permissions?.canRemoveMembers ?? legacyIsOfficer;
  const canAssignRoles = permissions?.canAssignRoles ?? legacyIsOfficer;
  const canManageMemberTags = permissions?.canManageMemberTags ?? legacyIsOfficer;
  const canManageCommittees = permissions?.canManageCommittees ?? legacyIsOfficer;
  const canManageTeams = permissions?.canManageTeams ?? legacyIsOfficer;

  // A user can see management controls if they have at least one management permission.
  const hasAnyManagementPermission =
    canInviteMembers
    || canRemoveMembers
    || canAssignRoles
    || canManageMemberTags
    || canManageCommittees
    || canManageTeams;
  const isArchived = club.status === "archived";
  const showInvite = canInviteMembers && !isArchived;
  const showManagement = hasAnyManagementPermission && !isArchived;

  const rosterQuery = rosterSearch.trim().toLowerCase();
  const hasActiveFilters = Boolean(rosterQuery) || roleFilter !== "all" || statusFilter !== "all";

  const filteredMembers = useMemo(() => {
    let list = club.members;
    if (statusFilter !== "all") {
      list = list.filter((m) => memberMatchesStatusFilter(m, statusFilter));
    }
    if (roleFilter !== "all") {
      list = list.filter((m) =>
        memberMatchesRoleFilter(m, rbacByUser[m.userId] ?? [], roleFilter),
      );
    }
    if (!rosterQuery) return list;
    return list.filter((m) => memberMatchesRosterSearch(m, rbacByUser[m.userId] ?? [], rosterQuery));
  }, [club.members, rbacByUser, rosterQuery, roleFilter, statusFilter]);

  function clearRosterFilters() {
    setRosterSearch("");
    setRoleFilter("all");
    setStatusFilter("all");
  }

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
                Active {memberCount === 1 ? "member" : "members"}
              </p>
              {alumniCount > 0 ? (
                <p className="mt-1 text-xs font-medium text-slate-500">{alumniCount} alumni</p>
              ) : null}
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

          {showInvite && (
            <div className="mt-6 sm:mt-8">
              <a
                href="#invite-members"
                className="btn-primary block w-full px-6 py-3 text-center text-base font-semibold sm:inline-block sm:w-auto"
              >
                Invite Members
              </a>
            </div>
          )}
          {isArchived && (
            <p className="mt-6 text-sm font-medium text-amber-900">
              This club is archived — inviting new members is disabled.
            </p>
          )}
        </div>
      </header>

      {/* Invite tools — requires members.invite permission */}
      {showInvite && (
        <section id="invite-members">
          <MemberInvite
            joinCode={club.joinCode}
            membersCount={memberCount}
            requireJoinApproval={club.requireJoinApproval}
          />
        </section>
      )}

      {pendingJoinRequests.length > 0 ? (
        <ClubJoinRequestsPanel clubId={club.id} requests={pendingJoinRequests} />
      ) : null}

      {/* Getting started — management users only, hidden once all steps are done */}
      {showManagement && !setupDone && (
        <GettingStartedChecklist
          clubId={club.id}
          membersCount={memberCount}
          announcementsCount={club.announcements.length}
          eventsCount={club.events.length}
        />
      )}

      <ClubCommitteesPanel
        clubId={club.id}
        committees={club.clubCommittees}
        canManage={canManageCommittees}
        isArchived={isArchived}
      />

      <ClubTeamsPanel
        clubId={club.id}
        teams={club.clubTeams}
        canManage={canManageTeams}
        isArchived={isArchived}
      />

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
          <span className="badge-soft">
            {hasActiveFilters
              ? `${filteredMembers.length} of ${rosterTotalCount}`
              : `${rosterTotalCount} total (${memberCount} active${alumniCount > 0 ? `, ${alumniCount} alumni` : ""})`}
          </span>
        </div>

        {rosterTotalCount > 0 && (
          <div className="mt-4 space-y-3">
            <div className="rounded-xl border border-slate-200/90 bg-slate-50/80 p-3 sm:p-4">
              <p className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-500">Find members</p>
              <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:gap-4">
                <div className="relative min-w-0 flex-1">
                  <svg
                    className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                    aria-hidden
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                  </svg>
                  <input
                    type="search"
                    value={rosterSearch}
                    onChange={(e) => setRosterSearch(e.target.value)}
                    placeholder="Search members…"
                    className="input-control min-h-11 w-full pl-9 text-sm sm:min-h-10"
                    aria-label="Search members in roster"
                    autoComplete="off"
                  />
                </div>
                <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:gap-3">
                  <div className="w-full sm:min-w-[180px]">
                    <label htmlFor="roster-status-filter" className="mb-1 block text-xs font-semibold text-slate-600">
                      Status
                    </label>
                    <select
                      id="roster-status-filter"
                      value={statusFilter}
                      onChange={(e) => setStatusFilter(e.target.value as RosterStatusFilter)}
                      className="input-control min-h-11 w-full text-sm sm:min-h-10"
                      aria-label="Filter roster by membership status"
                    >
                      <option value="all">All</option>
                      <option value="active">Active only</option>
                      <option value="alumni">Alumni only</option>
                    </select>
                  </div>
                  <div className="w-full sm:min-w-[220px]">
                    <label htmlFor="roster-role-filter" className="mb-1 block text-xs font-semibold text-slate-600">
                      Role
                    </label>
                    <select
                      id="roster-role-filter"
                      value={roleFilter}
                      onChange={(e) => setRoleFilter(e.target.value as RosterRoleFilter)}
                      className="input-control min-h-11 w-full text-sm sm:min-h-10"
                      aria-label="Filter roster by role"
                    >
                      <option value="all">All roles</option>
                      <option value="president">President</option>
                      <option value="officer">Officer (not President)</option>
                      <option value="member">Member</option>
                    </select>
                  </div>
                  {hasActiveFilters ? (
                    <button
                      type="button"
                      onClick={clearRosterFilters}
                      className="inline-flex min-h-11 shrink-0 items-center justify-center rounded-lg border border-slate-300 bg-white px-4 text-sm font-semibold text-slate-800 shadow-sm transition hover:bg-slate-50 sm:min-h-10"
                    >
                      Clear filters
                    </button>
                  ) : null}
                </div>
              </div>
              <p className="mt-3 border-t border-slate-200/90 pt-3 text-xs leading-relaxed text-slate-500">
                <span className="font-semibold text-slate-600">Grade &amp; class year:</span> not in the database yet
                (profiles only store name and email). This page can filter by{" "}
                <span className="text-slate-600">role</span> using membership and RBAC data only.
              </p>
            </div>
          </div>
        )}

        {query.memberSuccess ? <p className="alert-success mt-4">{query.memberSuccess}</p> : null}
        {query.memberError ? <p className="alert-error mt-3">{query.memberError}</p> : null}

        {rosterTotalCount === 0 ? (
          <div className="mt-4 rounded-xl border border-dashed border-slate-200 bg-slate-50/60 p-8 text-center">
            <p className="font-semibold text-slate-900">No members yet</p>
            <p className="mt-1 text-sm text-slate-500">
              {canInviteMembers
                ? "Share your join code above to invite people."
                : "You're the first one here."}
            </p>
          </div>
        ) : filteredMembers.length === 0 ? (
          <div className="mt-4 rounded-xl border border-dashed border-slate-200 bg-slate-50/60 p-8 text-center">
            <p className="font-semibold text-slate-900">No members match your filters</p>
            <p className="mt-1 text-sm text-slate-500">
              Try another search term, change the role filter, or clear filters to see the full roster.
            </p>
            {hasActiveFilters ? (
              <button
                type="button"
                onClick={clearRosterFilters}
                className="btn-primary mt-4 inline-flex items-center justify-center px-4 py-2 text-sm font-semibold"
              >
                Clear filters
              </button>
            ) : null}
          </div>
        ) : (
          <ul className="list-stack mt-4">
            {filteredMembers.map((member) => {
              const isCurrentUser = member.userId === club.currentUserId;
              const isAlumni = member.membershipStatus === "alumni";
              const isOfficer = member.role === "officer" && !isAlumni;

              const rbacRoles = rbacByUser[member.userId] ?? [];
              // Show non-redundant RBAC badges: skip the "Officer"/"Member" system
              // roles since the legacy role pill already communicates that.
              const significantRbacRoles = rbacRoles.filter(
                (r) => !(r.isSystem && (r.roleName === "Officer" || r.roleName === "Member")),
              );

              return (
                <li
                  key={member.userId}
                  className={`member-card ${isOfficer ? "is-officer" : ""} ${isCurrentUser ? "is-current-user" : ""} ${isAlumni ? "border-dashed border-slate-200/90 bg-slate-50/40" : ""}`}
                >
                  {/* Identity row */}
                  <div className="flex items-start gap-3">
                    <div className={`member-avatar ${isOfficer ? "is-officer" : ""} ${isCurrentUser ? "is-current-user" : ""}`}>
                      {getMemberRosterInitials(member)}
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <p className="text-base font-semibold tracking-tight text-slate-950">
                          {getMemberRosterDisplayName(member)}
                        </p>
                        <span className={`member-role-pill ${isOfficer ? "is-officer" : "is-member"}`}>
                          {member.role}
                        </span>
                        {isAlumni ? (
                          <span className="inline-flex items-center rounded-full border border-amber-200 bg-amber-50 px-2 py-0.5 text-[11px] font-semibold text-amber-900">
                            Alumni
                          </span>
                        ) : null}
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
                        {(member.tags ?? []).slice(0, 3).map((t) => (
                          <span
                            key={t.id}
                            className="inline-flex items-center rounded-full border border-sky-200 bg-sky-50 px-2 py-0.5 text-[11px] font-semibold text-sky-800"
                          >
                            {t.name}
                          </span>
                        ))}
                        {(member.tags ?? []).length > 3 ? (
                          <span className="text-[11px] font-medium text-slate-500">
                            +{(member.tags ?? []).length - 3}
                          </span>
                        ) : null}
                        {(member.committees ?? []).slice(0, 2).map((c) => (
                          <span
                            key={c.id}
                            className="inline-flex items-center rounded-full border border-teal-200 bg-teal-50 px-2 py-0.5 text-[11px] font-semibold text-teal-900"
                          >
                            {c.name}
                          </span>
                        ))}
                        {(member.committees ?? []).length > 2 ? (
                          <span className="text-[11px] font-medium text-slate-500">
                            +{(member.committees ?? []).length - 2}
                          </span>
                        ) : null}
                        {(member.teams ?? []).slice(0, 2).map((t) => (
                          <span
                            key={t.id}
                            className="inline-flex items-center rounded-full border border-rose-200 bg-rose-50 px-2 py-0.5 text-[11px] font-semibold text-rose-900"
                          >
                            {t.name}
                          </span>
                        ))}
                        {(member.teams ?? []).length > 2 ? (
                          <span className="text-[11px] font-medium text-slate-500">
                            +{(member.teams ?? []).length - 2}
                          </span>
                        ) : null}
                      </div>
                      <button
                        type="button"
                        onClick={() => setProfileUserId(member.userId)}
                        className="mt-2 text-left text-xs font-semibold text-indigo-600 underline-offset-2 hover:underline"
                      >
                        View profile
                      </button>
                    </div>

                    {/* Manage roles link — Presidents only; alumni have no RBAC roles to manage here */}
                    {isPresident && !isAlumni && (
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
                  {!isArchived && !isCurrentUser && (canAssignRoles || canRemoveMembers) ? (
                    <div className="member-card-actions">
                      {/* Role promotion/demotion — requires members.assign_roles; alumni are read-only */}
                      {canAssignRoles && member.membershipStatus === "active" &&
                        (member.role === "member" ? (
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
                        ))}
                      {canRemoveMembers && member.membershipStatus === "active" && (
                        <form action={markMemberAlumniAction}>
                          <input type="hidden" name="club_id" value={club.id} />
                          <input type="hidden" name="user_id" value={member.userId} />
                          <button type="submit" className="btn-secondary text-xs">
                            Mark as alumni
                          </button>
                        </form>
                      )}
                      {canRemoveMembers && (
                        <form action={removeMemberAction}>
                          <input type="hidden" name="club_id" value={club.id} />
                          <input type="hidden" name="user_id" value={member.userId} />
                          <button type="submit" className="btn-danger text-xs">
                            {isAlumni ? "Remove from roster" : "Remove from Club"}
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

      <MemberProfileDialog
        open={profileUserId !== null}
        onClose={() => setProfileUserId(null)}
        member={
          profileUserId ? (club.members.find((m) => m.userId === profileUserId) ?? null) : null
        }
        clubId={club.id}
        currentUserId={club.currentUserId}
        rbacRoles={profileUserId ? rbacByUser[profileUserId] ?? [] : []}
        isPresident={isPresident}
        isArchived={isArchived}
        canAssignRoles={canAssignRoles}
        canRemoveMembers={canRemoveMembers}
        memberTagDefinitions={club.memberTagDefinitions}
        canManageMemberTags={canManageMemberTags}
        clubCommittees={club.clubCommittees}
        canManageCommittees={canManageCommittees}
        clubTeams={club.clubTeams}
        canManageTeams={canManageTeams}
      />

    </section>
  );
}
