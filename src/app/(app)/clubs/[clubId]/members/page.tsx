import { notFound, redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import { getUserPermissions, isClubPresident } from "@/lib/rbac/permissions";
import { getMembersWithRoles } from "@/lib/rbac/role-actions";
import { ClubMembersSection } from "@/components/ui/club-members-section";
import { getClubDetailForCurrentUser, type ClubDetail, type ClubMember } from "@/lib/clubs/queries";
import type { MemberWithRoles } from "@/lib/rbac/role-actions";

/** Prefer names/emails from getMembersWithRoles when RPC row is missing them (RLS / stale RPC). */
function mergeClubRosterIdentities(club: ClubDetail, withRoles: MemberWithRoles[]): ClubDetail {
  if (withRoles.length === 0) return club;
  const map = new Map(withRoles.map((m) => [m.userId, m]));
  const enrich = (member: ClubMember): ClubMember => {
    const r = map.get(member.userId);
    const name = member.fullName?.trim() || r?.fullName?.trim() || null;
    const email = member.email ?? r?.email ?? null;
    return { ...member, fullName: name, email };
  };
  return {
    ...club,
    members: club.members.map(enrich),
    topMembers: club.topMembers.map(enrich),
  };
}

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

  const clubForUi =
    membersResult.ok ? mergeClubRosterIdentities(club, membersResult.data) : club;

  const permissions = {
    canInviteMembers: userPermissions.has("members.invite"),
    canRemoveMembers: userPermissions.has("members.remove"),
    canAssignRoles: userPermissions.has("members.assign_roles"),
    canViewInsights: userPermissions.has("insights.view"),
  };

  return (
    <ClubMembersSection
      club={clubForUi}
      query={query}
      rbacByUser={rbacByUser}
      isPresident={presidencyCheck}
      permissions={permissions}
    />
  );
}
