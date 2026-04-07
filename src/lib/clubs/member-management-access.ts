import "server-only";

import { createClient } from "@/lib/supabase/server";
import type { PermissionKey } from "@/lib/rbac/permissions";
import { hasPermission } from "@/lib/rbac/permissions";

/**
 * Member-management visibility & mutation matrix (UI gates + server actions should stay aligned).
 *
 * | Area | View (typical) | Edit / manage |
 * |------|----------------|---------------|
 * | Roster list, names, legacy role, RBAC chips | Any club member | — |
 * | Promote/demote legacy officer, remove, mark alumni | — | `members.assign_roles` / `members.remove` (strict RBAC, no legacy fallback) |
 * | Invite | — | `members.invite` (strict) |
 * | Tags / committees / teams | Any member | `members.manage_*` **or** active legacy officer |
 * | Volunteer hours | Any member (per RLS) | `members.manage_volunteer_hours` **or** active legacy officer |
 * | Skills / interests (self) | Self | Self when active |
 * | Skills / interests (others) | Any member | `members.manage_member_skills` **or** active legacy officer |
 * | Availability (self) | Self | Self when active |
 * | Availability (others) | Any member | `members.manage_member_availability` **or** active legacy officer |
 * | Officer notes | Leadership w/ gate | Same |
 * | Dues | Leadership w/ gate | Same |
 * | Optional club contact (phone) | Self; others if `members.view_member_contact` **or** active legacy officer | Self only |
 * | Attendance summary on roster / profile | Any member | — |
 * | Per-event attendance **history** (profile list) | Self **or** `canViewOthersMemberAttendanceHistory` | — |
 * | Participation score (derived) | Any member viewing that profile | — |
 * | Likely inactive hint | `insights.view` **or** active legacy officer | — |
 * | Join requests | Review gate | `members.review_join_requests` **or** active legacy officer |
 * | Export / import roster | `members.export_roster` / import auth | Same (+ server route checks) |
 * | Bulk tag/committee/team | Same as single manage | Server must re-check |
 *
 * RLS remains authoritative; app gates avoid shipping leadership-only rows to the browser and mirror mutation rules.
 */

/**
 * Viewer’s `club_members` row for the current club (when on the members page or running a member action).
 * Used to mirror `is_club_officer`-style checks: legacy officer **and** `membership_status === 'active'`.
 */
export type ClubMembersViewerMembership = {
  role: string;
  membership_status: string;
} | null;

/**
 * True when the viewer matches an **active** legacy officer row — same idea as `public.is_club_officer`
 * (alumni or inactive officer rows do not grant officer fallback).
 */
export function isViewerActiveLegacyOfficer(membership: ClubMembersViewerMembership): boolean {
  return membership?.role === "officer" && membership?.membership_status === "active";
}

/**
 * RBAC permission **or** active legacy officer fallback (standard ClubHub pattern for officer UX on the members surface).
 */
export function hasPermissionOrActiveLegacyOfficer(
  userPermissions: ReadonlySet<PermissionKey>,
  permission: PermissionKey,
  viewerMembership: ClubMembersViewerMembership,
): boolean {
  return userPermissions.has(permission) || isViewerActiveLegacyOfficer(viewerMembership);
}

/** Shared server-action result for member-management mutations. */
export type MemberManagementActionResult = { ok: true } | { ok: false; error: string };

/**
 * `hasPermission` **or** active legacy officer row — same pattern as `po()` on the members page.
 * Use in server actions for features that grant legacy officers parity with historical behavior.
 */
export async function assertPermissionOrActiveLegacyOfficer(
  actorId: string,
  clubId: string,
  permission: PermissionKey,
  forbiddenMessage: string,
): Promise<MemberManagementActionResult> {
  if (await hasPermission(actorId, clubId, permission)) {
    return { ok: true };
  }

  const supabase = await createClient();
  const { data: row } = await supabase
    .from("club_members")
    .select("role, membership_status")
    .eq("club_id", clubId)
    .eq("user_id", actorId)
    .maybeSingle();

  if (isViewerActiveLegacyOfficer(row ?? null)) {
    return { ok: true };
  }

  return { ok: false, error: forbiddenMessage };
}

/**
 * Permission gates for the club members page UI (must stay aligned with server actions that use the same pattern).
 *
 * - **Strict RBAC** (no officer fallback): invite, remove, assign_roles — matches `actions.ts` member mutations.
 * - **Permission or active legacy officer**: tags, committees, teams, volunteer hours, skills/availability for others,
 *   officer notes, dues, export, insights-style roster hints, member contact visibility — matches feature actions + RLS intent.
 */
export type ClubMembersPagePermissionGates = {
  canInviteMembers: boolean;
  canRemoveMembers: boolean;
  canAssignRoles: boolean;
  canViewInsights: boolean;
  canManageMemberTags: boolean;
  canManageCommittees: boolean;
  canManageTeams: boolean;
  canSeeInactiveEngagement: boolean;
  canManageVolunteerHours: boolean;
  canManageMemberSkillsForOthers: boolean;
  canManageMemberAvailabilityForOthers: boolean;
  canManageOfficerNotes: boolean;
  canManageMemberDues: boolean;
  canExportMemberRoster: boolean;
  canViewMemberContact: boolean;
  /**
   * Per-event “marked present” history for **other** members (profile). Self always sees own history.
   * Stricter than DB SELECT (any member can read `event_attendance` in SQL) — app layer limits payload & UI.
   */
  canViewOthersMemberAttendanceHistory: boolean;
};

export function buildClubMembersPagePermissionGates(
  userPermissions: ReadonlySet<PermissionKey>,
  viewerMembership: ClubMembersViewerMembership,
): ClubMembersPagePermissionGates {
  const activeOfficer = isViewerActiveLegacyOfficer(viewerMembership);
  const po = (k: PermissionKey) => hasPermissionOrActiveLegacyOfficer(userPermissions, k, viewerMembership);

  return {
    canInviteMembers: userPermissions.has("members.invite"),
    canRemoveMembers: userPermissions.has("members.remove"),
    canAssignRoles: userPermissions.has("members.assign_roles"),
    canViewInsights: userPermissions.has("insights.view"),
    canManageMemberTags: po("members.manage_tags"),
    canManageCommittees: po("members.manage_committees"),
    canManageTeams: po("members.manage_teams"),
    canSeeInactiveEngagement: userPermissions.has("insights.view") || activeOfficer,
    canManageVolunteerHours: po("members.manage_volunteer_hours"),
    canManageMemberSkillsForOthers: po("members.manage_member_skills"),
    canManageMemberAvailabilityForOthers: po("members.manage_member_availability"),
    canManageOfficerNotes: po("members.manage_officer_notes"),
    canManageMemberDues: po("members.manage_member_dues"),
    canExportMemberRoster: po("members.export_roster"),
    canViewMemberContact: po("members.view_member_contact"),
    canViewOthersMemberAttendanceHistory:
      userPermissions.has("insights.view") || po("attendance.mark") || po("attendance.edit"),
  };
}

/** Join-request panel: archived clubs never review; otherwise RBAC or active legacy officer. */
export function canReviewClubJoinRequests(
  userPermissions: ReadonlySet<PermissionKey>,
  viewerMembership: ClubMembersViewerMembership,
  clubArchived: boolean,
): boolean {
  if (clubArchived) return false;
  return (
    userPermissions.has("members.review_join_requests") || isViewerActiveLegacyOfficer(viewerMembership)
  );
}

/** CSV export route — matches UI `canExportMemberRoster`. */
export async function actorCanExportMemberRoster(actorId: string, clubId: string): Promise<boolean> {
  if (await hasPermission(actorId, clubId, "members.export_roster")) {
    return true;
  }

  const supabase = await createClient();
  const { data } = await supabase
    .from("club_members")
    .select("role, membership_status")
    .eq("club_id", clubId)
    .eq("user_id", actorId)
    .maybeSingle();

  return isViewerActiveLegacyOfficer(data ?? null);
}
