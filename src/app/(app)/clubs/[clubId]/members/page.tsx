import { notFound, redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import {
  buildClubMembersPagePermissionGates,
  canReviewClubJoinRequests,
} from "@/lib/clubs/member-management-access";
import { canImportMemberList as userCanImportMemberList } from "@/lib/clubs/member-import-auth";
import { getUserPermissions, isClubPresident } from "@/lib/rbac/permissions";
import { getMembersWithRoles } from "@/lib/rbac/role-actions";
import { ClubMembersSection } from "@/components/ui/club-members-section";
import { mergeClubRosterIdentities } from "@/lib/clubs/merge-club-roster-identities";
import {
  fetchClubAttendanceHistoryByUserMap,
  fetchClubDuesSettings,
  fetchClubMemberDuesMap,
  fetchClubMemberOfficerNotesMap,
  getClubDetailForMembersRosterForCurrentUser,
  getPendingJoinRequestsForClub,
} from "@/lib/clubs/queries";
import type { MemberWithRoles } from "@/lib/rbac/role-actions";

type ClubMembersPageProps = {
  params: Promise<{ clubId: string }>;
  searchParams: Promise<{
    memberError?: string;
    memberSuccess?: string;
  }>;
};

export default async function ClubMembersPage({ params, searchParams }: ClubMembersPageProps) {
  const { clubId } = await params;
  const query = await searchParams;

  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const [club, membersResult, userPermissions, presidencyCheck] = await Promise.all([
    getClubDetailForMembersRosterForCurrentUser(clubId),
    getMembersWithRoles(clubId),
    getUserPermissions(user.id, clubId),
    isClubPresident(user.id, clubId),
  ]);

  if (!club) notFound();

  const { data: viewerMembership } = await supabase
    .from("club_members")
    .select("role, membership_status")
    .eq("club_id", clubId)
    .eq("user_id", user.id)
    .maybeSingle();

  const viewerRow =
    viewerMembership?.role && viewerMembership?.membership_status
      ? { role: viewerMembership.role, membership_status: viewerMembership.membership_status }
      : null;

  const permissionGates = buildClubMembersPagePermissionGates(userPermissions, viewerRow);

  const canReviewJoinRequests = canReviewClubJoinRequests(
    userPermissions,
    viewerRow,
    club.status === "archived",
  );

  const pendingJoinRequests = canReviewJoinRequests ? await getPendingJoinRequestsForClub(clubId) : [];

  // Build a quick-lookup map: userId → RBAC roles
  const rbacByUser: Record<string, MemberWithRoles["rbacRoles"]> = {};
  if (membersResult.ok) {
    for (const m of membersResult.data) {
      rbacByUser[m.userId] = m.rbacRoles;
    }
  }

  const clubForUi =
    membersResult.ok ? mergeClubRosterIdentities(club, membersResult.data) : club;

  const [officerNotesByUserId, duesByUserId, duesSettings, attendanceHistoryByUserId] = await Promise.all([
    permissionGates.canManageOfficerNotes ? fetchClubMemberOfficerNotesMap(clubId) : Promise.resolve(undefined),
    permissionGates.canManageMemberDues ? fetchClubMemberDuesMap(clubId) : Promise.resolve(undefined),
    permissionGates.canManageMemberDues ? fetchClubDuesSettings(clubId) : Promise.resolve(null),
    fetchClubAttendanceHistoryByUserMap(
      clubId,
      permissionGates.canViewOthersMemberAttendanceHistory
        ? undefined
        : { onlyUserIds: [user.id] },
    ),
  ]);

  const permissions = {
    ...permissionGates,
    canImportMemberList: await userCanImportMemberList(user.id, clubId),
  };

  return (
    <ClubMembersSection
      club={clubForUi}
      query={query}
      rbacByUser={rbacByUser}
      isPresident={presidencyCheck}
      permissions={permissions}
      pendingJoinRequests={pendingJoinRequests}
      officerNotesByUserId={officerNotesByUserId}
      duesByUserId={duesByUserId}
      duesSettings={duesSettings}
      attendanceHistoryByUserId={attendanceHistoryByUserId}
    />
  );
}
