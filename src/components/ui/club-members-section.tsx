"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { markMemberAlumniAction, removeMemberAction, updateMemberRoleAction } from "@/app/(app)/clubs/actions";
import { ClubCommitteesPanel } from "@/components/ui/club-committees-panel";
import { ClubTeamsPanel } from "@/components/ui/club-teams-panel";
import { GettingStartedChecklist } from "@/components/ui/getting-started-checklist";
import { ClubJoinRequestsPanel } from "@/components/ui/club-join-requests-panel";
import { MemberInvite } from "@/components/ui/member-invite";
import { MemberBulkActionsToolbar } from "@/components/ui/member-bulk-actions-toolbar";
import { MemberImportPanel } from "@/components/ui/member-import-panel";
import { MemberProfileDialog } from "@/components/ui/member-profile-dialog";
import { formatVolunteerHoursAmount } from "@/components/ui/volunteer-hours-panel";
import type { ClubMembersPagePermissionGates } from "@/lib/clubs/member-management-access";
import {
  formatTrackedAttendanceSummary,
  participationScoreCompactTitle,
  trackedAttendanceEmptyCopy,
} from "@/lib/clubs/member-engagement-copy";
import { formatMemberLastEngagementDisplay, MEMBER_INACTIVITY } from "@/lib/clubs/member-inactivity";
import { computeParticipationScore, participationScoreBand } from "@/lib/clubs/participation-score";
import type {
  ClubDetail,
  ClubMember,
  ClubMemberAttendanceHistoryEntry,
  ClubMemberDuesRecord,
  PendingJoinRequest,
} from "@/lib/clubs/queries";
import { getMemberRosterDisplayName, getMemberRosterInitials } from "@/lib/member-display";
import type { MemberWithRoles } from "@/lib/rbac/role-actions";

/** Role filter uses real data only: legacy `club_members.role` + RBAC President. */
type RosterRoleFilter = "all" | "president" | "officer" | "member";

/** Membership lifecycle filter (active vs alumni). */
type RosterStatusFilter = "all" | "active" | "alumni";

/** Engagement hint filter (leadership / insights only). */
type RosterEngagementFilter = "all" | "likely_inactive";

function hasRbacPresident(rbacRoles: MemberWithRoles["rbacRoles"]): boolean {
  return rbacRoles.some((r) => r.roleName === "President" && r.isSystem);
}

function duesRosterPillClasses(status: ClubMemberDuesRecord["status"]): { label: string; className: string } {
  switch (status) {
    case "paid":
      return {
        label: "Dues paid",
        className: "border-emerald-200 bg-emerald-50 text-emerald-900",
      };
    case "unpaid":
      return {
        label: "Dues unpaid",
        className: "border-red-200 bg-red-50 text-red-900",
      };
    case "partial":
      return {
        label: "Dues partial",
        className: "border-amber-200 bg-amber-50 text-amber-900",
      };
    case "exempt":
      return {
        label: "Dues exempt",
        className: "border-slate-200 bg-slate-100 text-slate-700",
      };
    case "waived":
      return {
        label: "Dues waived",
        className: "border-slate-200 bg-slate-100 text-slate-700",
      };
    default:
      return {
        label: "Dues",
        className: "border-slate-200 bg-slate-100 text-slate-700",
      };
  }
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
  const skillInterestLabels = (member.skillInterestEntries ?? []).map((e) => e.label.toLowerCase()).join(" ");
  const haystack = [
    name,
    email,
    legacyRole,
    display,
    rbacNames,
    status,
    tagNames,
    committeeNames,
    teamNames,
    skillInterestLabels,
  ].join(" ");
  return haystack.includes(queryLower);
}

function memberMatchesEngagementFilter(
  member: ClubMember,
  filter: RosterEngagementFilter,
  canSee: boolean,
): boolean {
  if (!canSee || filter === "all") return true;
  return Boolean(member.likelyInactive);
}

function rosterParticipationPill(member: ClubMember) {
  const { score, attendanceSignalLimited } = computeParticipationScore({
    attendanceRate: member.attendanceRate,
    totalTrackedEvents: member.totalTrackedEvents,
    volunteerHoursTotal: member.volunteerHoursTotal,
  });
  const band = participationScoreBand(score);
  const cls =
    band === "high"
      ? "border-emerald-200 bg-emerald-50 text-emerald-800"
      : band === "mid"
        ? "border-amber-200 bg-amber-50 text-amber-900"
        : "border-slate-200 bg-slate-100 text-slate-700";

  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold ${cls}`}
      title={participationScoreCompactTitle({ score, attendanceSignalLimited })}
    >
      Score {score}
    </span>
  );
}

/** Server-built gates plus async import check from `member-import-auth`. */
export type ClubMembersSectionPermissions = ClubMembersPagePermissionGates & {
  canImportMemberList?: boolean;
};

type ClubMembersSectionProps = {
  club: ClubDetail;
  query: {
    memberError?: string;
    memberSuccess?: string;
  };
  rbacByUser?: Record<string, MemberWithRoles["rbacRoles"]>;
  isPresident?: boolean;
  permissions?: ClubMembersSectionPermissions;
  pendingJoinRequests?: PendingJoinRequest[];
  /** Populated only for users who may manage officer notes; never sent to regular members. */
  officerNotesByUserId?: Record<string, string>;
  /** Populated only for users who may manage dues; never sent to regular members. */
  duesByUserId?: Record<string, ClubMemberDuesRecord>;
  /**
   * Per-member past attendance rows; members page only.
   * Server loads all members’ rows only when `canViewOthersMemberAttendanceHistory`; otherwise the viewer’s user id only.
   */
  attendanceHistoryByUserId?: Record<string, ClubMemberAttendanceHistoryEntry[]>;
};

export function ClubMembersSection({
  club,
  query,
  rbacByUser = {},
  isPresident = false,
  permissions,
  pendingJoinRequests = [],
  officerNotesByUserId,
  duesByUserId,
  attendanceHistoryByUserId,
}: ClubMembersSectionProps) {
  const [rosterSearch, setRosterSearch] = useState("");
  const [roleFilter, setRoleFilter] = useState<RosterRoleFilter>("all");
  const [statusFilter, setStatusFilter] = useState<RosterStatusFilter>("all");
  const [engagementFilter, setEngagementFilter] = useState<RosterEngagementFilter>("all");
  const [profileUserId, setProfileUserId] = useState<string | null>(null);
  const [rosterImportOpen, setRosterImportOpen] = useState(false);
  const [bulkSelected, setBulkSelected] = useState<Set<string>>(() => new Set());

  const activeMembers = club.members.filter((m) => m.membershipStatus === "active");
  const alumniCount = club.members.length - activeMembers.length;
  const memberCount = activeMembers.length;
  const officerCount = activeMembers.filter((m) => m.role === "officer").length;
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
  const canSeeInactiveEngagement = permissions?.canSeeInactiveEngagement ?? false;
  const canManageVolunteerHours = permissions?.canManageVolunteerHours ?? false;
  const canManageMemberSkillsForOthers = permissions?.canManageMemberSkillsForOthers ?? legacyIsOfficer;
  const canManageMemberAvailabilityForOthers =
    permissions?.canManageMemberAvailabilityForOthers ?? legacyIsOfficer;
  const canManageOfficerNotes = permissions?.canManageOfficerNotes ?? false;
  const canManageMemberDues = permissions?.canManageMemberDues ?? false;
  const canExportMemberRoster = permissions?.canExportMemberRoster ?? false;
  const canImportMemberList = permissions?.canImportMemberList ?? false;
  const canViewMemberContact = permissions?.canViewMemberContact ?? false;
  const canViewOthersMemberAttendanceHistory = permissions?.canViewOthersMemberAttendanceHistory ?? false;

  // A user can see management controls if they have at least one management permission.
  const hasAnyManagementPermission =
    canInviteMembers
    || canRemoveMembers
    || canAssignRoles
    || canManageMemberTags
    || canManageCommittees
    || canManageTeams;
  const isArchived = club.status === "archived";
  const showBulkMemberChrome =
    !isArchived
    && (canManageMemberTags || canManageCommittees || canManageTeams || canRemoveMembers);
  const showInvite = canInviteMembers && !isArchived;
  const showManagement = hasAnyManagementPermission && !isArchived;

  const rosterQuery = rosterSearch.trim().toLowerCase();
  const hasActiveFilters =
    Boolean(rosterQuery)
    || roleFilter !== "all"
    || statusFilter !== "all"
    || (canSeeInactiveEngagement && engagementFilter !== "all");

  const likelyInactiveCount = canSeeInactiveEngagement
    ? activeMembers.filter((m) => m.likelyInactive).length
    : 0;

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
    list = list.filter((m) => memberMatchesEngagementFilter(m, engagementFilter, canSeeInactiveEngagement));
    if (!rosterQuery) return list;
    return list.filter((m) => memberMatchesRosterSearch(m, rbacByUser[m.userId] ?? [], rosterQuery));
  }, [
    club.members,
    rbacByUser,
    rosterQuery,
    roleFilter,
    statusFilter,
    engagementFilter,
    canSeeInactiveEngagement,
  ]);

  useEffect(() => {
    const visible = new Set(filteredMembers.map((m) => m.userId));
    setBulkSelected((prev) => {
      const next = new Set<string>();
      for (const id of prev) {
        if (visible.has(id)) next.add(id);
      }
      return next;
    });
  }, [filteredMembers]);

  function clearRosterFilters() {
    setRosterSearch("");
    setRoleFilter("all");
    setStatusFilter("all");
    setEngagementFilter("all");
  }

  function selectAllVisibleMembers() {
    const ids = filteredMembers.filter((m) => m.userId !== club.currentUserId).map((m) => m.userId);
    setBulkSelected(new Set(ids));
  }

  function toggleBulkMember(userId: string) {
    setBulkSelected((prev) => {
      const next = new Set(prev);
      if (next.has(userId)) next.delete(userId);
      else next.add(userId);
      return next;
    });
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
      <div className="card-surface p-5 sm:p-6" id="members">
        <div className="flex flex-col gap-4 border-b border-slate-100 pb-5 sm:flex-row sm:items-start sm:justify-between sm:gap-6">
          <div className="min-w-0 flex-1">
            <p className="section-kicker">Roster</p>
            <div className="mt-1 flex flex-wrap items-baseline gap-x-3 gap-y-1">
              <h2 className="text-lg font-semibold tracking-tight text-slate-900 sm:text-xl">Member directory</h2>
              <span className="badge-soft text-[11px]">
                {hasActiveFilters
                  ? `${filteredMembers.length} / ${rosterTotalCount} shown`
                  : `${rosterTotalCount} total`}
              </span>
            </div>
            <p className="mt-2 text-sm text-slate-600">
              {memberCount} active
              {alumniCount > 0 ? ` · ${alumniCount} alumni` : ""} · {officerCount}{" "}
              {officerCount === 1 ? "officer" : "officers"}
              {hasAnyManagementPermission ? " · Officers listed first" : null}
              {canSeeInactiveEngagement &&
              club.totalTrackedEvents >= MEMBER_INACTIVITY.MIN_TRACKED_EVENTS_FOR_LABEL &&
              likelyInactiveCount > 0
                ? ` · ${likelyInactiveCount} likely inactive`
                : null}
            </p>
            <p className="mt-1.5 text-xs leading-relaxed text-slate-500">
              Open a member for full detail — tags, committees, skills, availability, volunteer hours, and attendance.
            </p>
          </div>
          {(canImportMemberList && !isArchived) || canExportMemberRoster ? (
            <div className="flex shrink-0 flex-col gap-2 sm:items-end">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Roster files</p>
              <div className="flex flex-wrap gap-2">
                {canImportMemberList && !isArchived ? (
                  <button
                    type="button"
                    className="btn-secondary inline-flex items-center justify-center gap-2 px-3 py-2 text-xs font-semibold sm:text-sm"
                    aria-expanded={rosterImportOpen}
                    onClick={() => setRosterImportOpen((open) => !open)}
                  >
                    <svg className="h-4 w-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden>
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M9 19l3 3m0 0l3-3m-3 3V10"
                      />
                    </svg>
                    {rosterImportOpen ? "Hide import" : "Import CSV"}
                  </button>
                ) : null}
                {canExportMemberRoster ? (
                  <a
                    href={`/clubs/${club.id}/members/export`}
                    title="Downloads every member in this club as CSV. Roster search and filters do not apply."
                    className="btn-secondary inline-flex items-center justify-center gap-2 px-3 py-2 text-xs font-semibold sm:text-sm"
                  >
                    <svg className="h-4 w-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden>
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"
                      />
                    </svg>
                    Export CSV
                  </a>
                ) : null}
              </div>
            </div>
          ) : null}
        </div>

        {rosterImportOpen && canImportMemberList && !isArchived ? <MemberImportPanel clubId={club.id} /> : null}

        {rosterTotalCount > 0 && (
          <div className="mt-5 space-y-3">
            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm sm:p-5">
              <div className="mb-3 flex flex-wrap items-end justify-between gap-2">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Find members</p>
                {showBulkMemberChrome ? (
                  <p className="text-[10px] font-semibold uppercase tracking-wider text-indigo-600/80">Bulk</p>
                ) : null}
              </div>
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
                  {canSeeInactiveEngagement ? (
                    <div className="w-full sm:min-w-[200px]">
                      <label htmlFor="roster-engagement-filter" className="mb-1 block text-xs font-semibold text-slate-600">
                        Engagement
                      </label>
                      <select
                        id="roster-engagement-filter"
                        value={engagementFilter}
                        onChange={(e) => setEngagementFilter(e.target.value as RosterEngagementFilter)}
                        className="input-control min-h-11 w-full text-sm sm:min-h-10"
                        aria-label="Filter roster by engagement"
                      >
                        <option value="all">All members</option>
                        <option value="likely_inactive">Likely inactive</option>
                      </select>
                    </div>
                  ) : null}
                  <div className="flex flex-wrap items-center gap-2 border-t border-slate-100 pt-3 sm:border-t-0 sm:border-l sm:pl-3 sm:pt-0">
                    {canSeeInactiveEngagement &&
                    likelyInactiveCount > 0 &&
                    engagementFilter === "all" &&
                    club.totalTrackedEvents >= MEMBER_INACTIVITY.MIN_TRACKED_EVENTS_FOR_LABEL ? (
                      <button
                        type="button"
                        onClick={() => setEngagementFilter("likely_inactive")}
                        className="inline-flex min-h-10 shrink-0 items-center justify-center rounded-lg border border-amber-200/90 bg-amber-50/80 px-3 text-xs font-semibold text-amber-950 transition hover:bg-amber-100/80 sm:min-h-10 sm:px-4 sm:text-sm"
                        aria-label={`Filter roster to ${likelyInactiveCount} likely inactive members`}
                      >
                        {likelyInactiveCount} likely inactive
                      </button>
                    ) : null}
                    {hasActiveFilters ? (
                      <button
                        type="button"
                        onClick={clearRosterFilters}
                        className="inline-flex min-h-10 shrink-0 items-center justify-center rounded-lg border border-slate-200 bg-slate-50 px-3 text-xs font-semibold text-slate-800 transition hover:bg-slate-100 sm:px-4 sm:text-sm"
                      >
                        Clear filters
                      </button>
                    ) : null}
                    {showBulkMemberChrome && filteredMembers.length > 0 ? (
                      <button
                        type="button"
                        onClick={selectAllVisibleMembers}
                        className="inline-flex min-h-10 shrink-0 items-center justify-center rounded-lg border border-indigo-200/90 bg-indigo-50/60 px-3 text-xs font-semibold text-indigo-950 transition hover:bg-indigo-100/70 sm:px-4 sm:text-sm"
                      >
                        Select visible (
                        {filteredMembers.filter((m) => m.userId !== club.currentUserId).length})
                      </button>
                    ) : null}
                  </div>
                </div>
              </div>
              <details className="mt-3 border-t border-slate-200/90 pt-3">
                <summary className="cursor-pointer list-none text-xs font-semibold text-slate-600 hover:text-slate-900 [&::-webkit-details-marker]:hidden">
                  About search &amp; filters
                </summary>
                <div className="mt-2 space-y-3 text-xs leading-relaxed text-slate-500">
                  <p>
                    The list shows a short engagement summary; skills, availability, notes, and full attendance history
                    are in each member&apos;s profile.
                  </p>
                  <p>
                    <span className="font-semibold text-slate-600">Grade &amp; class year</span> are not stored yet
                    (profiles only include name and email). Filters use membership role and RBAC roles only.
                  </p>
                  {canSeeInactiveEngagement ? (
                    <p>
                      <span className="font-semibold text-slate-600">Likely inactive</span> uses RSVP and event signals
                      (leadership recency), not the same as attendance % or participation score. No RSVP or attended-event
                      signal in {MEMBER_INACTIVITY.INACTIVITY_DAYS} days after a {MEMBER_INACTIVITY.NEW_MEMBER_GRACE_DAYS}
                      -day join grace; needs {MEMBER_INACTIVITY.MIN_TRACKED_EVENTS_FOR_LABEL}+ tracked past events
                      club-wide. Nothing changes automatically.
                    </p>
                  ) : null}
                </div>
              </details>
            </div>
          </div>
        )}

        {rosterTotalCount > 0 && hasActiveFilters ? (
          <p className="mt-3 text-xs text-slate-600" role="status">
            Showing{" "}
            <span className="font-semibold text-slate-900">{filteredMembers.length}</span> of {rosterTotalCount}{" "}
            members
          </p>
        ) : null}

        {query.memberSuccess ? <p className="alert-success mt-4">{query.memberSuccess}</p> : null}
        {query.memberError ? <p className="alert-error mt-3">{query.memberError}</p> : null}

        {showBulkMemberChrome ? (
          <MemberBulkActionsToolbar
            clubId={club.id}
            clubName={club.name}
            currentUserId={club.currentUserId}
            selectedUserIds={Array.from(bulkSelected)}
            onClearSelection={() => setBulkSelected(new Set())}
            canManageMemberTags={canManageMemberTags}
            canManageCommittees={canManageCommittees}
            canManageTeams={canManageTeams}
            canRemoveMembers={canRemoveMembers}
            memberTagDefinitions={club.memberTagDefinitions}
            clubCommittees={club.clubCommittees}
            clubTeams={club.clubTeams}
          />
        ) : null}

        {rosterTotalCount === 0 ? (
          <div className="mt-6 flex flex-col items-center rounded-xl border border-dashed border-slate-200 bg-slate-50/50 px-6 py-12 text-center">
            <div
              className="flex h-12 w-12 items-center justify-center rounded-2xl border border-slate-200 bg-white text-slate-400"
              aria-hidden
            >
              <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M18 18.72a9.094 9.094 0 003.741-.479 3 3 0 00-4.682-2.72m.94 3.198l.001.031c0 .225-.012.447-.037.666A11.944 11.944 0 0112 21c-2.17 0-4.207-.576-5.963-1.584A6.062 6.062 0 016 18.719m12 0a5.971 5.971 0 00-.941-3.197m0 0A5.995 5.995 0 0012 12.75a5.995 5.995 0 00-5.058 2.772m0 0a3 3 0 00-4.681 2.72 8.986 8.986 0 003.74.477m.94-3.197a5.971 5.971 0 00-.94 3.197M15 6.75a3 3 0 11-6 0 3 3 0 016 0zm6 3a2.25 2.25 0 11-4.5 0 2.25 2.25 0 014.5 0zm-13.5 0a2.25 2.25 0 11-4.5 0 2.25 2.25 0 014.5 0z"
                />
              </svg>
            </div>
            <p className="mt-4 font-semibold text-slate-900">No members yet</p>
            <p className="mt-1 max-w-sm text-sm text-slate-500">
              {canInviteMembers
                ? "Share your join code above to invite people."
                : "You're the first one here."}
            </p>
          </div>
        ) : filteredMembers.length === 0 ? (
          <div className="mt-6 flex flex-col items-center rounded-xl border border-dashed border-slate-200 bg-slate-50/50 px-6 py-12 text-center">
            <div
              className="flex h-12 w-12 items-center justify-center rounded-2xl border border-slate-200 bg-white text-slate-400"
              aria-hidden
            >
              <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z"
                />
              </svg>
            </div>
            <p className="mt-4 font-semibold text-slate-900">No members match</p>
            <p className="mt-1 max-w-sm text-sm text-slate-500">
              {engagementFilter === "likely_inactive" && canSeeInactiveEngagement
                ? "No one is flagged as likely inactive right now, or another filter is hiding everyone."
                : "Try a different search, adjust status or role, or clear filters."}
            </p>
            {hasActiveFilters ? (
              <button
                type="button"
                onClick={clearRosterFilters}
                className="btn-primary mt-5 inline-flex items-center justify-center px-4 py-2 text-sm font-semibold"
              >
                Clear filters
              </button>
            ) : null}
          </div>
        ) : (
          <ul className="list-stack member-roster-list mt-4" aria-label="Club member roster">
            {filteredMembers.map((member) => {
              const isCurrentUser = member.userId === club.currentUserId;
              const isAlumni = member.membershipStatus === "alumni";
              const isOfficer = member.role === "officer" && !isAlumni;

              const rbacRoles = rbacByUser[member.userId] ?? [];
              const significantRbacRoles = rbacRoles.filter(
                (r) => !(r.isSystem && (r.roleName === "Officer" || r.roleName === "Member")),
              );

              const duesPill =
                canManageMemberDues && duesByUserId?.[member.userId]
                  ? duesRosterPillClasses(duesByUserId[member.userId].status)
                  : null;

              const hasAffiliationChips =
                significantRbacRoles.length > 0
                || (member.tags?.length ?? 0) > 0
                || (member.committees?.length ?? 0) > 0
                || (member.teams?.length ?? 0) > 0;

              return (
                <li
                  key={member.userId}
                  className={`member-card ${isOfficer ? "is-officer" : ""} ${isCurrentUser ? "is-current-user" : ""} ${isAlumni ? "border-dashed border-slate-200/90 bg-slate-50/40" : ""}`}
                >
                  <div className="flex items-start gap-3">
                    {showBulkMemberChrome ? (
                      <div className="flex shrink-0 items-start pt-1">
                        <input
                          type="checkbox"
                          className="h-4 w-4 rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
                          checked={bulkSelected.has(member.userId)}
                          onChange={() => toggleBulkMember(member.userId)}
                          disabled={isCurrentUser}
                          title={isCurrentUser ? "You cannot bulk-change your own account from here." : undefined}
                          aria-label={
                            isCurrentUser
                              ? "Your account (not available for bulk selection)"
                              : `Select ${getMemberRosterDisplayName(member)} for bulk actions`
                          }
                        />
                      </div>
                    ) : null}
                    <div className={`member-avatar ${isOfficer ? "is-officer" : ""} ${isCurrentUser ? "is-current-user" : ""}`}>
                      {getMemberRosterInitials(member)}
                    </div>

                    <div className="min-w-0 flex-1 space-y-2.5">
                      <div className="flex flex-col gap-2.5 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
                        <div className="min-w-0 flex-1">
                          <div className="flex items-start justify-between gap-2">
                            <h3 className="text-base font-semibold tracking-tight text-slate-950">
                              {getMemberRosterDisplayName(member)}
                            </h3>
                            {isPresident && !isAlumni ? (
                              <Link
                                href={`/clubs/${club.id}/settings`}
                                className="shrink-0 rounded-lg p-1.5 text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-700"
                                title="Manage roles in Settings"
                                aria-label="Manage roles in Settings"
                              >
                                <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                  <path
                                    strokeLinecap="round"
                                    strokeLinejoin="round"
                                    strokeWidth={2}
                                    d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"
                                  />
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                </svg>
                              </Link>
                            ) : null}
                          </div>
                          <div className="mt-2 flex flex-wrap items-center gap-1.5">
                            <span className={`member-role-pill ${isOfficer ? "is-officer" : "is-member"}`}>
                              {member.role}
                            </span>
                            {isAlumni ? (
                              <span className="inline-flex items-center rounded-full border border-amber-200 bg-amber-50 px-2 py-0.5 text-[11px] font-semibold text-amber-900">
                                Alumni
                              </span>
                            ) : null}
                            {duesPill ? (
                              <span
                                className={`inline-flex max-w-full items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold ${duesPill.className}`}
                                title="Visible only to leadership — open profile for details"
                              >
                                {duesPill.label}
                              </span>
                            ) : null}
                            {canSeeInactiveEngagement && !isAlumni && member.likelyInactive ? (
                              <span
                                className="inline-flex max-w-full items-center rounded-full border border-slate-200 bg-slate-100 px-2 py-0.5 text-[11px] font-semibold text-slate-700"
                                title={
                                  (() => {
                                    const last = formatMemberLastEngagementDisplay(member.lastEngagementAt);
                                    return last
                                      ? `Leadership recency (RSVP / events): last signal ${last}. Nothing in ${MEMBER_INACTIVITY.INACTIVITY_DAYS}d — separate from attendance % and participation score.`
                                      : `Leadership recency: no RSVP or attended-event signal in loaded history; nothing in ${MEMBER_INACTIVITY.INACTIVITY_DAYS}d — separate from attendance % and score.`;
                                  })()
                                }
                              >
                                Likely inactive
                              </span>
                            ) : null}
                            {isCurrentUser ? <span className="member-you-pill">You</span> : null}
                          </div>
                        </div>
                        <div className="flex w-full shrink-0 flex-col gap-2 sm:w-auto sm:items-end">
                          <button
                            type="button"
                            onClick={() => setProfileUserId(member.userId)}
                            className="inline-flex min-h-9 w-full items-center justify-center rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-semibold text-slate-800 shadow-sm transition hover:border-slate-300 hover:bg-slate-50 sm:w-auto sm:text-sm"
                          >
                            Profile
                          </button>
                        </div>
                      </div>

                      {hasAffiliationChips ? (
                        <div
                          className="flex flex-wrap items-center gap-1.5 border-t border-slate-100/90 pt-2.5"
                          aria-label="Roles, tags, committees, and teams"
                        >
                          {significantRbacRoles.map((r) => (
                            <span
                              key={r.roleId}
                              className={`inline-flex max-w-full items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold ${
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
                              className="inline-flex max-w-full items-center rounded-full border border-sky-200 bg-sky-50 px-2 py-0.5 text-[11px] font-semibold text-sky-800"
                            >
                              {t.name}
                            </span>
                          ))}
                          {(member.tags ?? []).length > 3 ? (
                            <span className="text-[11px] font-medium text-slate-500">
                              +{(member.tags ?? []).length - 3} tags
                            </span>
                          ) : null}
                          {(member.committees ?? []).slice(0, 2).map((c) => (
                            <span
                              key={c.id}
                              className="inline-flex max-w-full items-center rounded-full border border-teal-200 bg-teal-50 px-2 py-0.5 text-[11px] font-semibold text-teal-900"
                            >
                              {c.name}
                            </span>
                          ))}
                          {(member.committees ?? []).length > 2 ? (
                            <span className="text-[11px] font-medium text-slate-500">
                              +{(member.committees ?? []).length - 2} committees
                            </span>
                          ) : null}
                          {(member.teams ?? []).slice(0, 2).map((t) => (
                            <span
                              key={t.id}
                              className="inline-flex max-w-full items-center rounded-full border border-rose-200 bg-rose-50 px-2 py-0.5 text-[11px] font-semibold text-rose-900"
                            >
                              {t.name}
                            </span>
                          ))}
                          {(member.teams ?? []).length > 2 ? (
                            <span className="text-[11px] font-medium text-slate-500">
                              +{(member.teams ?? []).length - 2} teams
                            </span>
                          ) : null}
                        </div>
                      ) : null}

                      <div
                        className="flex flex-col gap-2 border-t border-slate-100/90 pt-2.5 sm:flex-row sm:flex-wrap sm:items-center sm:gap-x-3 sm:gap-y-1"
                        aria-label="Tracked attendance, participation score, and volunteer hours"
                      >
                        <div className="flex min-w-0 flex-wrap items-center gap-2 text-xs text-slate-600">
                          <span className="font-medium text-slate-500">Summary</span>
                          <span className="hidden h-3 w-px bg-slate-200 sm:block" aria-hidden />
                          {member.totalTrackedEvents > 0 ? (
                            <span className="text-slate-800" title="Marked present at tracked past events (not RSVPs)">
                              {formatTrackedAttendanceSummary({
                                attendanceCount: member.attendanceCount,
                                totalTrackedEvents: member.totalTrackedEvents,
                                attendanceRate: member.attendanceRate,
                              })}
                            </span>
                          ) : (
                            <span className="text-slate-500" title={trackedAttendanceEmptyCopy()}>
                              No tracked events yet
                            </span>
                          )}
                        </div>
                        <span className="hidden h-3 w-px bg-slate-200 sm:block" aria-hidden />
                        <div className="flex flex-wrap items-center gap-2">
                          {rosterParticipationPill(member)}
                          <span className="text-xs text-slate-400">·</span>
                          <span className="text-xs font-medium text-slate-700">
                            {member.volunteerHoursTotal > 0
                              ? `${formatVolunteerHoursAmount(member.volunteerHoursTotal)} h volunteer`
                              : "No hours logged"}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>

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
        canManageVolunteerHours={canManageVolunteerHours && !isArchived}
        canManageMemberSkillsForOthers={canManageMemberSkillsForOthers}
        canManageMemberAvailabilityForOthers={canManageMemberAvailabilityForOthers}
        canManageOfficerNotes={canManageOfficerNotes}
        officerNotesByUserId={officerNotesByUserId}
        canManageMemberDues={canManageMemberDues}
        duesByUserId={duesByUserId}
        attendanceHistoryByUserId={attendanceHistoryByUserId}
        canViewMemberContact={canViewMemberContact}
        canSeeInactiveEngagement={canSeeInactiveEngagement}
        canViewOthersMemberAttendanceHistory={canViewOthersMemberAttendanceHistory}
      />

    </section>
  );
}
