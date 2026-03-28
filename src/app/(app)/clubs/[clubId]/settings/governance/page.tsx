import { notFound, redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import { isClubPresident, hasPermission } from "@/lib/rbac/permissions";
import type { AuditLogEntry } from "@/lib/rbac/audit";
import { GovernanceSection } from "@/components/ui/governance-section";

type GovernancePageProps = {
  params: Promise<{ clubId: string }>;
  searchParams: Promise<{
    success?: string;
    error?: string;
  }>;
};

type RawMemberRow = {
  user_id: string;
  role: string;
  profiles: { full_name: string | null; email: string | null } | null;
};

export default async function GovernancePage({ params, searchParams }: GovernancePageProps) {
  const { clubId } = await params;
  const query = await searchParams;

  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  // Verify club membership.
  const { data: membership } = await supabase
    .from("club_members")
    .select("user_id")
    .eq("club_id", clubId)
    .eq("user_id", user.id)
    .maybeSingle();

  if (!membership) notFound();

  // Fetch club name + President role ID + membership roster in parallel.
  const [clubResult, presidentRoleResult, allMembersResult, presidencyCheck, canViewAudit] =
    await Promise.all([
      supabase.from("clubs").select("id, name").eq("id", clubId).maybeSingle(),
      supabase
        .from("club_roles")
        .select("id")
        .eq("club_id", clubId)
        .eq("name", "President")
        .eq("is_system", true)
        .maybeSingle(),
      supabase
        .from("club_members")
        .select("user_id, role, profiles(full_name, email)")
        .eq("club_id", clubId),
      isClubPresident(user.id, clubId),
      hasPermission(user.id, clubId, "audit_logs.view"),
    ]);

  if (!clubResult.data) notFound();

  const presidentRoleId = presidentRoleResult.data?.id ?? null;

  // Fetch current President role assignments (if RBAC is set up).
  const presidentUserIds = new Set<string>();
  if (presidentRoleId) {
    const { data: presidentAssignments } = await supabase
      .from("member_roles")
      .select("user_id")
      .eq("club_id", clubId)
      .eq("role_id", presidentRoleId);

    for (const row of presidentAssignments ?? []) {
      presidentUserIds.add(row.user_id);
    }
  }

  const allMembers = ((allMembersResult.data ?? []) as unknown as RawMemberRow[]).map((m) => ({
    userId: m.user_id,
    name: m.profiles?.full_name ?? null,
    email: m.profiles?.email ?? null,
  }));

  const presidents = allMembers.filter((m) => presidentUserIds.has(m.userId));
  const nonPresidents = allMembers.filter((m) => !presidentUserIds.has(m.userId));

  // ─── Audit log (only for users with audit_logs.view) ───────────────────────
  let auditLogs: AuditLogEntry[] = [];

  if (canViewAudit) {
    type RawAuditRow = {
      id: string;
      actor_id: string;
      action: string;
      target_user_id: string | null;
      target_role_id: string | null;
      metadata: Record<string, unknown>;
      created_at: string;
    };

    const { data: rawLogs } = await supabase
      .from("club_audit_logs")
      .select("id, actor_id, action, target_user_id, target_role_id, metadata, created_at")
      .eq("club_id", clubId)
      .order("created_at", { ascending: false })
      .limit(20);

    const logs = (rawLogs ?? []) as RawAuditRow[];

    if (logs.length > 0) {
      const userIds = [
        ...new Set([
          ...logs.map((l) => l.actor_id),
          ...(logs.map((l) => l.target_user_id).filter(Boolean) as string[]),
        ]),
      ];

      const roleIds = [
        ...new Set(logs.map((l) => l.target_role_id).filter(Boolean) as string[]),
      ];

      const [profilesResult, rolesResult] = await Promise.all([
        supabase.from("profiles").select("id, full_name, email").in("id", userIds),
        roleIds.length > 0
          ? supabase.from("club_roles").select("id, name").in("id", roleIds)
          : Promise.resolve({ data: [] as { id: string; name: string }[] }),
      ]);

      const profilesById = new Map(
        (
          (profilesResult.data ?? []) as {
            id: string;
            full_name: string | null;
            email: string | null;
          }[]
        ).map((p) => [p.id, { name: p.full_name, email: p.email }]),
      );

      const rolesById = new Map(
        ((rolesResult.data ?? []) as { id: string; name: string }[]).map((r) => [r.id, r.name]),
      );

      auditLogs = logs.map((log) => {
        const actor = profilesById.get(log.actor_id);
        const targetUser = log.target_user_id ? profilesById.get(log.target_user_id) : null;
        const resolvedRoleName = log.target_role_id
          ? (rolesById.get(log.target_role_id) ?? (log.metadata?.role_name as string | undefined) ?? null)
          : (log.metadata?.role_name as string | undefined) ?? null;

        return {
          id: log.id,
          action: log.action as AuditLogEntry["action"],
          actorName: actor?.name ?? actor?.email ?? "Unknown",
          targetUserName: targetUser ? (targetUser.name ?? targetUser.email ?? "Unknown") : null,
          targetRoleName: resolvedRoleName,
          metadata: log.metadata,
          createdAt: log.created_at,
        };
      });
    }
  }

  return (
    <GovernanceSection
      clubId={clubId}
      clubName={clubResult.data.name}
      currentUserId={user.id}
      isPresident={presidencyCheck}
      presidentRoleId={presidentRoleId}
      presidents={presidents}
      nonPresidents={nonPresidents}
      query={query}
      auditLogs={auditLogs}
      canViewAudit={canViewAudit}
    />
  );
}
