import { notFound, redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import { isClubPresident } from "@/lib/rbac/permissions";
import { getClubRoles, getMembersWithRoles, getAllPermissions } from "@/lib/rbac/role-actions";
import { ClubSettingsSection } from "@/components/ui/club-settings-section";

type SettingsPageProps = {
  params: Promise<{ clubId: string }>;
  searchParams: Promise<{
    roleId?: string;
    mode?: string;
    success?: string;
    error?: string;
  }>;
};

export default async function ClubSettingsPage({ params, searchParams }: SettingsPageProps) {
  const { clubId } = await params;
  const query = await searchParams;

  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  // Verify the club exists and the user is a member.
  const { data: membership } = await supabase
    .from("club_members")
    .select("user_id")
    .eq("club_id", clubId)
    .eq("user_id", user.id)
    .maybeSingle();

  if (!membership) notFound();

  const [presidencyCheck, rolesResult, membersResult, permissionsResult] = await Promise.all([
    isClubPresident(user.id, clubId),
    getClubRoles(clubId),
    getMembersWithRoles(clubId),
    getAllPermissions(),
  ]);

  if (rolesResult.error || !rolesResult.ok) {
    return (
      <section className="space-y-6">
        <div className="empty-state">
          <p className="empty-state-title">Could not load roles</p>
          <p className="empty-state-copy">
            {rolesResult.ok === false ? rolesResult.error : "Unexpected error. Please refresh."}
          </p>
        </div>
      </section>
    );
  }

  const roles = rolesResult.data;

  // Build memberCount per roleId for the role list.
  const memberCountByRole = new Map<string, number>();
  if (membersResult.ok) {
    for (const member of membersResult.data) {
      for (const rbacRole of member.rbacRoles) {
        memberCountByRole.set(rbacRole.roleId, (memberCountByRole.get(rbacRole.roleId) ?? 0) + 1);
      }
    }
  }

  // Default to the first system role if no roleId is in the URL.
  const selectedRoleId =
    query.roleId && roles.some((r) => r.id === query.roleId)
      ? query.roleId
      : (roles.find((r) => r.isSystem && r.name === "President")?.id ?? roles[0]?.id ?? null);

  const selectedRole = roles.find((r) => r.id === selectedRoleId) ?? null;
  const allPermissionKeys = (permissionsResult.ok ? permissionsResult.data : []).map((p) => p.key);
  const allMembersWithRoles = membersResult.ok ? membersResult.data : [];

  // Partition members into assigned / unassigned for the selected role.
  const assignedMembers = selectedRole
    ? allMembersWithRoles.filter((m) => m.rbacRoles.some((r) => r.roleId === selectedRole.id))
    : [];
  const unassignedMembers = selectedRole
    ? allMembersWithRoles.filter((m) => !m.rbacRoles.some((r) => r.roleId === selectedRole.id))
    : [];

  return (
    <ClubSettingsSection
      clubId={clubId}
      roles={roles}
      memberCountByRole={Object.fromEntries(memberCountByRole)}
      selectedRole={selectedRole}
      allPermissionKeys={allPermissionKeys}
      isPresident={presidencyCheck}
      assignedMembers={assignedMembers}
      unassignedMembers={unassignedMembers}
      mode={query.mode}
      success={query.success}
      error={query.error}
    />
  );
}
