import type { ClubDetail, ClubMember } from "@/lib/clubs/queries";
import type { MemberWithRoles } from "@/lib/rbac/role-actions";

/** Prefer names/emails from getMembersWithRoles when RPC row is missing them (RLS / stale RPC). */
export function mergeClubRosterIdentities(club: ClubDetail, withRoles: MemberWithRoles[]): ClubDetail {
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
