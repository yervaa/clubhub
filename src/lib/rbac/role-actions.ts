import "server-only";
import { createClient } from "@/lib/supabase/server";
import { hasPermission, PermissionKey, PermissionDeniedError } from "@/lib/rbac/permissions";
import { createNotification } from "@/lib/notifications/create-notification";

// ─── Shared result wrapper ────────────────────────────────────────────────────

export type ActionResult<T = undefined> =
  | { ok: true; data: T }
  | { ok: false; error: string };

// ─── Public types ─────────────────────────────────────────────────────────────

export type ClubRole = {
  id: string;
  clubId: string;
  name: string;
  description: string;
  isSystem: boolean;
  createdAt: string;
  permissions: PermissionKey[];
};

export type MemberWithRoles = {
  userId: string;
  fullName: string | null;
  email: string | null;
  legacyRole: "officer" | "member";
  rbacRoles: Array<{
    roleId: string;
    roleName: string;
    isSystem: boolean;
  }>;
};

export type Permission = {
  id: string;
  key: PermissionKey;
  description: string;
};

// ─── Raw Supabase row types ───────────────────────────────────────────────────

type RawClubRole = {
  id: string;
  club_id: string;
  name: string;
  description: string;
  is_system: boolean;
  created_at: string;
  role_permissions: Array<{
    permissions: { key: string } | null;
  }>;
};

type RawMemberRole = {
  user_id: string;
  club_id: string;
  role_id: string;
  club_roles: {
    name: string;
    is_system: boolean;
  } | null;
};

type RawClubMember = {
  user_id: string;
  role: string;
  profiles: {
    full_name: string | null;
    email: string | null;
  } | null;
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function normalizeRole(raw: RawClubRole): ClubRole {
  return {
    id: raw.id,
    clubId: raw.club_id,
    name: raw.name,
    description: raw.description,
    isSystem: raw.is_system,
    createdAt: raw.created_at,
    permissions: raw.role_permissions
      .map((rp) => rp.permissions?.key)
      .filter((k): k is PermissionKey => Boolean(k)),
  };
}

function permissionError(err: unknown): string {
  if (err instanceof PermissionDeniedError) return `Permission denied: ${err.permission}`;
  if (err instanceof Error) return err.message;
  return "Unknown error";
}

// ─── QUERIES ─────────────────────────────────────────────────────────────────

/**
 * Returns all roles for a club, each with their full permission list.
 * Readable by any club member.
 */
export async function getClubRoles(clubId: string): Promise<ActionResult<ClubRole[]>> {
  const supabase = await createClient();

  const { data, error } = await supabase
    .from("club_roles")
    .select(`
      id, club_id, name, description, is_system, created_at,
      role_permissions ( permissions ( key ) )
    `)
    .eq("club_id", clubId)
    .order("name");

  if (error) return { ok: false, error: error.message };

  return {
    ok: true,
    data: ((data ?? []) as unknown as RawClubRole[]).map(normalizeRole),
  };
}

/**
 * Returns a single role by id, validated as belonging to the given club.
 */
export async function getClubRole(
  roleId: string,
  clubId: string,
): Promise<ActionResult<ClubRole>> {
  const supabase = await createClient();

  const { data, error } = await supabase
    .from("club_roles")
    .select(`
      id, club_id, name, description, is_system, created_at,
      role_permissions ( permissions ( key ) )
    `)
    .eq("id", roleId)
    .eq("club_id", clubId)
    .maybeSingle();

  if (error) return { ok: false, error: error.message };
  if (!data) return { ok: false, error: "Role not found in this club." };

  return { ok: true, data: normalizeRole(data as unknown as RawClubRole) };
}

/**
 * Returns all available permissions from the global catalog.
 */
export async function getAllPermissions(): Promise<ActionResult<Permission[]>> {
  const supabase = await createClient();

  const { data, error } = await supabase
    .from("permissions")
    .select("id, key, description")
    .order("key");

  if (error) return { ok: false, error: error.message };

  return {
    ok: true,
    data: (data ?? []) as Permission[],
  };
}

/**
 * Returns all club members with their legacy role and RBAC role assignments.
 * Readable by any club member (club_members + member_roles RLS).
 */
export async function getMembersWithRoles(clubId: string): Promise<ActionResult<MemberWithRoles[]>> {
  const supabase = await createClient();

  const [membersRes, memberRolesRes] = await Promise.all([
    supabase
      .from("club_members")
      .select("user_id, role, profiles ( full_name, email )")
      .eq("club_id", clubId)
      .eq("membership_status", "active"),
    supabase
      .from("member_roles")
      .select("user_id, club_id, role_id, club_roles ( name, is_system )")
      .eq("club_id", clubId),
  ]);

  if (membersRes.error) return { ok: false, error: membersRes.error.message };
  if (memberRolesRes.error) return { ok: false, error: memberRolesRes.error.message };

  // Index RBAC role assignments by userId for O(1) merge.
  const rbacByUser = new Map<string, MemberWithRoles["rbacRoles"]>();
  for (const mr of (memberRolesRes.data ?? []) as unknown as RawMemberRole[]) {
    if (!mr.club_roles) continue;
    const existing = rbacByUser.get(mr.user_id) ?? [];
    existing.push({
      roleId: mr.role_id,
      roleName: mr.club_roles.name,
      isSystem: mr.club_roles.is_system,
    });
    rbacByUser.set(mr.user_id, existing);
  }

  const members: MemberWithRoles[] = ((membersRes.data ?? []) as unknown as RawClubMember[]).map((cm) => ({
    userId: cm.user_id,
    fullName: cm.profiles?.full_name ?? null,
    email: cm.profiles?.email ?? null,
    legacyRole: (cm.role as "officer" | "member"),
    rbacRoles: rbacByUser.get(cm.user_id) ?? [],
  }));

  return { ok: true, data: members };
}

// ─── MUTATIONS ────────────────────────────────────────────────────────────────

/**
 * Creates a new custom role in the club.
 * Requires: roles.create
 */
export async function createClubRole(
  actorId: string,
  clubId: string,
  name: string,
  description: string,
  permissionKeys: PermissionKey[],
): Promise<ActionResult<ClubRole>> {
  try {
    const allowed = await hasPermission(actorId, clubId, "roles.create");
    if (!allowed) {
      return { ok: false, error: "Permission denied: roles.create" };
    }

    const supabase = await createClient();

    const { data: roleRow, error: roleErr } = await supabase
      .from("club_roles")
      .insert({ club_id: clubId, name: name.trim(), description: description.trim(), is_system: false })
      .select("id")
      .single();

    if (roleErr || !roleRow) {
      return { ok: false, error: roleErr?.message ?? "Failed to create role." };
    }

    if (permissionKeys.length > 0) {
      const { data: permRows, error: permLookupErr } = await supabase
        .from("permissions")
        .select("id, key")
        .in("key", permissionKeys);

      if (permLookupErr) return { ok: false, error: permLookupErr.message };

      const inserts = (permRows ?? []).map((p) => ({
        role_id: roleRow.id,
        permission_id: p.id,
      }));

      if (inserts.length > 0) {
        const { error: permInsertErr } = await supabase
          .from("role_permissions")
          .insert(inserts);

        if (permInsertErr) return { ok: false, error: permInsertErr.message };
      }
    }

    return getClubRole(roleRow.id, clubId);
  } catch (err) {
    return { ok: false, error: permissionError(err) };
  }
}

/**
 * Updates the name and description of a custom role.
 * System roles (President / Officer / Member) cannot be renamed.
 * Requires: roles.edit
 */
export async function updateClubRoleMetadata(
  actorId: string,
  roleId: string,
  clubId: string,
  name: string,
  description: string,
): Promise<ActionResult<ClubRole>> {
  try {
    const allowed = await hasPermission(actorId, clubId, "roles.edit");
    if (!allowed) {
      return { ok: false, error: "Permission denied: roles.edit" };
    }

    const supabase = await createClient();

    const { data: existing, error: existingErr } = await supabase
      .from("club_roles")
      .select("is_system")
      .eq("id", roleId)
      .eq("club_id", clubId)
      .maybeSingle();

    if (existingErr || !existing) {
      return { ok: false, error: "Role not found in this club." };
    }

    if (existing.is_system) {
      return { ok: false, error: "System roles (President, Officer, Member) cannot be renamed." };
    }

    const { error: updateErr } = await supabase
      .from("club_roles")
      .update({ name: name.trim(), description: description.trim() })
      .eq("id", roleId)
      .eq("club_id", clubId);

    if (updateErr) return { ok: false, error: updateErr.message };

    return getClubRole(roleId, clubId);
  } catch (err) {
    return { ok: false, error: permissionError(err) };
  }
}

/**
 * Replaces the full permission set for a role.
 * Replaces are atomic: old permissions are removed, new ones are inserted.
 * Requires: roles.assign_permissions
 *
 * Guardrail: the President role's permissions cannot be modified — it always
 * holds every permission, which is enforced here in addition to the DB trigger.
 */
export async function setRolePermissions(
  actorId: string,
  roleId: string,
  clubId: string,
  permissionKeys: PermissionKey[],
): Promise<ActionResult<ClubRole>> {
  try {
    const allowed = await hasPermission(actorId, clubId, "roles.assign_permissions");
    if (!allowed) {
      return { ok: false, error: "Permission denied: roles.assign_permissions" };
    }

    const supabase = await createClient();

    const { data: roleRow, error: roleErr } = await supabase
      .from("club_roles")
      .select("name, is_system")
      .eq("id", roleId)
      .eq("club_id", clubId)
      .maybeSingle();

    if (roleErr || !roleRow) {
      return { ok: false, error: "Role not found in this club." };
    }

    if (roleRow.name === "President" && roleRow.is_system) {
      return { ok: false, error: "The President role always holds every permission and cannot be edited." };
    }

    // Remove all existing permissions for this role.
    const { error: deleteErr } = await supabase
      .from("role_permissions")
      .delete()
      .eq("role_id", roleId);

    if (deleteErr) return { ok: false, error: deleteErr.message };

    // Insert the new permission set.
    if (permissionKeys.length > 0) {
      const { data: permRows, error: permLookupErr } = await supabase
        .from("permissions")
        .select("id, key")
        .in("key", permissionKeys);

      if (permLookupErr) return { ok: false, error: permLookupErr.message };

      const inserts = (permRows ?? []).map((p) => ({
        role_id: roleId,
        permission_id: p.id,
      }));

      if (inserts.length > 0) {
        const { error: permInsertErr } = await supabase
          .from("role_permissions")
          .insert(inserts);

        if (permInsertErr) return { ok: false, error: permInsertErr.message };
      }
    }

    return getClubRole(roleId, clubId);
  } catch (err) {
    return { ok: false, error: permissionError(err) };
  }
}

/**
 * Assigns a club role to a member.
 * The actor cannot assign the President role unless they are a President
 * themselves (guarding against privilege escalation).
 * Requires: members.assign_roles
 */
export async function assignMemberRole(
  actorId: string,
  targetUserId: string,
  clubId: string,
  roleId: string,
): Promise<ActionResult> {
  try {
    const allowed = await hasPermission(actorId, clubId, "members.assign_roles");
    if (!allowed) {
      return { ok: false, error: "Permission denied: members.assign_roles" };
    }

    const supabase = await createClient();

    // Verify the role belongs to this club and retrieve its metadata.
    const { data: roleRow, error: roleErr } = await supabase
      .from("club_roles")
      .select("name, is_system")
      .eq("id", roleId)
      .eq("club_id", clubId)
      .maybeSingle();

    if (roleErr || !roleRow) {
      return { ok: false, error: "Role not found in this club." };
    }

    // Only existing Presidents can grant the President role (privilege escalation guard).
    if (roleRow.name === "President" && roleRow.is_system) {
      const actorIsPresident = await hasPermission(actorId, clubId, "club.transfer_presidency");
      if (!actorIsPresident) {
        return { ok: false, error: "Only a President can assign the President role." };
      }
    }

    // Verify the target is an active member of the club.
    const { data: membership } = await supabase
      .from("club_members")
      .select("user_id")
      .eq("club_id", clubId)
      .eq("user_id", targetUserId)
      .eq("membership_status", "active")
      .maybeSingle();

    if (!membership) {
      return { ok: false, error: "Target user is not an active member of this club." };
    }

    const { error: insertErr } = await supabase
      .from("member_roles")
      .insert({ user_id: targetUserId, club_id: clubId, role_id: roleId });

    if (insertErr) {
      if (insertErr.code === "23505") {
        return { ok: true, data: undefined }; // already assigned — idempotent
      }
      return { ok: false, error: insertErr.message };
    }

    // Notify the target member about their new role (non-fatal).
    await createNotification({
      userId: targetUserId,
      clubId,
      type: "role.assigned",
      title: `You were assigned the ${roleRow.name} role`,
      body: "Your role in the club has been updated.",
      href: `/clubs/${clubId}`,
    });

    return { ok: true, data: undefined };
  } catch (err) {
    return { ok: false, error: permissionError(err) };
  }
}

/**
 * Removes a role assignment from a member.
 * The last-President protection is enforced at the DB layer (trigger) and
 * re-surfaced here with a clean error message.
 * Requires: members.assign_roles
 */
export async function removeMemberRole(
  actorId: string,
  targetUserId: string,
  clubId: string,
  roleId: string,
): Promise<ActionResult> {
  try {
    const allowed = await hasPermission(actorId, clubId, "members.assign_roles");
    if (!allowed) {
      return { ok: false, error: "Permission denied: members.assign_roles" };
    }

    const supabase = await createClient();

    // Fetch role name before deleting so we can include it in the notification.
    const { data: roleRow } = await supabase
      .from("club_roles")
      .select("name")
      .eq("id", roleId)
      .eq("club_id", clubId)
      .maybeSingle();

    const { error: deleteErr } = await supabase
      .from("member_roles")
      .delete()
      .eq("user_id", targetUserId)
      .eq("club_id", clubId)
      .eq("role_id", roleId);

    if (deleteErr) {
      // Translate the last-President DB trigger exception into a friendly message.
      if (deleteErr.message.includes("Cannot remove the last President")) {
        return { ok: false, error: "Cannot remove the last President from this club." };
      }
      return { ok: false, error: deleteErr.message };
    }

    // Notify the target member that the role was removed (non-fatal).
    if (roleRow) {
      await createNotification({
        userId: targetUserId,
        clubId,
        type: "role.removed",
        title: `Your ${roleRow.name} role was removed`,
        body: "Your role assignment in the club has changed.",
        href: `/clubs/${clubId}`,
      });
    }

    return { ok: true, data: undefined };
  } catch (err) {
    return { ok: false, error: permissionError(err) };
  }
}
