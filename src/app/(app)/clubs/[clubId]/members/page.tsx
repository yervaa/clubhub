import { notFound, redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import { getUserPermissions, isClubPresident } from "@/lib/rbac/permissions";
import { getMembersWithRoles } from "@/lib/rbac/role-actions";
import { ClubMembersSection } from "@/components/ui/club-members-section";
import { getClubDetailForCurrentUser } from "@/lib/clubs/queries";
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
    getClubDetailForCurrentUser(clubId),
    getMembersWithRoles(clubId),
    getUserPermissions(user.id, clubId),
    isClubPresident(user.id, clubId),
  ]);

  if (!club) notFound();

  // Build a quick-lookup map: userId → RBAC roles
  const rbacByUser: Record<string, MemberWithRoles["rbacRoles"]> = {};
  if (membersResult.ok) {
    for (const m of membersResult.data) {
      rbacByUser[m.userId] = m.rbacRoles;
    }
  }

  const permissions = {
    canInviteMembers: userPermissions.has("members.invite"),
    canRemoveMembers: userPermissions.has("members.remove"),
    canAssignRoles: userPermissions.has("members.assign_roles"),
    canViewInsights: userPermissions.has("insights.view"),
  };

  return (
    <ClubMembersSection
      club={club}
      query={query}
      rbacByUser={rbacByUser}
      isPresident={presidencyCheck}
      permissions={permissions}
    />
  );
}
