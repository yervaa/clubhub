"use server";

import { redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import { hasPermission } from "@/lib/rbac/permissions";
import type { PermissionKey } from "@/lib/rbac/permissions";
import { PERMISSION_CATALOG } from "@/lib/rbac/permission-catalog";
import {
  createClubRole,
  updateClubRoleMetadata,
  setRolePermissions,
  assignMemberRole,
  removeMemberRole,
} from "@/lib/rbac/role-actions";
import { logAuditEvent } from "@/lib/rbac/audit";
import { isValidTemplateKey, ROLE_TEMPLATES } from "@/lib/rbac/role-templates";
import {
  roleCreateSchema,
  roleUpdateSchema,
  roleDeleteSchema,
  assignRoleSchema,
  removeRoleSchema,
} from "@/lib/validation/clubs";

function settingsUrl(clubId: string, params?: Record<string, string>) {
  const base = `/clubs/${clubId}/settings`;
  if (!params) return base;
  const qs = new URLSearchParams(params).toString();
  return `${base}?${qs}`;
}

function safeValidationError(result: { error: { issues: Array<{ message: string }> } }) {
  return result.error.issues[0]?.message ?? "Please check your input and try again.";
}

// ─── Create custom role ───────────────────────────────────────────────────────

export async function createCustomRoleAction(formData: FormData) {
  const parsed = roleCreateSchema.safeParse({
    clubId: formData.get("club_id"),
    name: formData.get("name"),
    description: formData.get("description") ?? "",
    templateKey: formData.get("template_key") ?? undefined,
  });

  if (!parsed.success) {
    const clubIdRaw = formData.get("club_id");
    const clubId = typeof clubIdRaw === "string" ? clubIdRaw : "";
    redirect(settingsUrl(clubId, { mode: "create", error: safeValidationError(parsed) }));
  }

  const { clubId, name, description, templateKey } = parsed.data;

  // Resolve initial permissions from the template, if a valid key was supplied.
  const initialPermissions =
    templateKey && isValidTemplateKey(templateKey)
      ? ROLE_TEMPLATES[templateKey].permissions
      : [];

  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const result = await createClubRole(user.id, clubId, name, description, initialPermissions);

  if (!result.ok) {
    redirect(settingsUrl(clubId, { mode: "create", error: result.error }));
  }

  await logAuditEvent({
    clubId,
    actorId: user.id,
    action: "role.created",
    targetRoleId: result.data.id,
    metadata: {
      role_name: result.data.name,
      ...(templateKey && isValidTemplateKey(templateKey) ? { template: templateKey } : {}),
    },
  });

  redirect(settingsUrl(clubId, { roleId: result.data.id, success: "Role+created+successfully." }));
}

// ─── Save role (metadata + permissions) ──────────────────────────────────────
// Handles both system roles (permissions only) and custom roles (everything).

export async function saveRoleAction(formData: FormData) {
  const parsed = roleUpdateSchema.safeParse({
    clubId: formData.get("club_id"),
    roleId: formData.get("role_id"),
    name: formData.get("name") ?? "",
    description: formData.get("description") ?? "",
  });

  if (!parsed.success) {
    const clubIdRaw = formData.get("club_id");
    const roleIdRaw = formData.get("role_id");
    const clubId = typeof clubIdRaw === "string" ? clubIdRaw : "";
    const roleId = typeof roleIdRaw === "string" ? roleIdRaw : "";
    redirect(settingsUrl(clubId, { roleId, error: safeValidationError(parsed) }));
  }

  const { clubId, roleId, name, description } = parsed.data;

  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  // Determine what can be changed for this role.
  const { data: roleRow, error: roleErr } = await supabase
    .from("club_roles")
    .select("name, is_system")
    .eq("id", roleId)
    .eq("club_id", clubId)
    .maybeSingle();

  if (roleErr || !roleRow) {
    redirect(settingsUrl(clubId, { roleId, error: "Role+not+found." }));
  }

  const isPresident = roleRow.name === "President" && roleRow.is_system;
  if (isPresident) {
    redirect(settingsUrl(clubId, { roleId, error: "President+permissions+cannot+be+changed." }));
  }

  // Parse submitted permissions, filtering to only valid known keys.
  const rawPermissions = formData.getAll("permissions");
  const validPermissions = rawPermissions.filter(
    (p): p is PermissionKey => typeof p === "string" && p in PERMISSION_CATALOG,
  );

  // Custom roles: update name + description.
  if (!roleRow.is_system) {
    const metaResult = await updateClubRoleMetadata(user.id, roleId, clubId, name, description);
    if (!metaResult.ok) {
      redirect(settingsUrl(clubId, { roleId, error: encodeURIComponent(metaResult.error) }));
    }
  }

  // All non-President roles: update permissions.
  const canAssign = await hasPermission(user.id, clubId, "roles.assign_permissions");
  if (!canAssign) {
    redirect(settingsUrl(clubId, { roleId, error: "You+do+not+have+permission+to+edit+role+permissions." }));
  }

  const permResult = await setRolePermissions(user.id, roleId, clubId, validPermissions);
  if (!permResult.ok) {
    redirect(settingsUrl(clubId, { roleId, error: encodeURIComponent(permResult.error) }));
  }

  await logAuditEvent({
    clubId,
    actorId: user.id,
    action: "role.updated",
    targetRoleId: roleId,
    metadata: {
      role_name: roleRow.name,
      permission_count: validPermissions.length,
    },
  });

  redirect(settingsUrl(clubId, { roleId, success: "Role+saved+successfully." }));
}

// ─── Delete custom role ───────────────────────────────────────────────────────

export async function deleteRoleAction(formData: FormData) {
  const parsed = roleDeleteSchema.safeParse({
    clubId: formData.get("club_id"),
    roleId: formData.get("role_id"),
  });

  if (!parsed.success) {
    const clubIdRaw = formData.get("club_id");
    const clubId = typeof clubIdRaw === "string" ? clubIdRaw : "";
    redirect(settingsUrl(clubId, { error: safeValidationError(parsed) }));
  }

  const { clubId, roleId } = parsed.data;

  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const canDelete = await hasPermission(user.id, clubId, "roles.delete");
  if (!canDelete) {
    redirect(settingsUrl(clubId, { error: "You+do+not+have+permission+to+delete+roles." }));
  }

  // Verify the role is not a system role (DB trigger also blocks this, but fail fast).
  const { data: roleRow } = await supabase
    .from("club_roles")
    .select("name, is_system")
    .eq("id", roleId)
    .eq("club_id", clubId)
    .maybeSingle();

  if (roleRow?.is_system) {
    redirect(settingsUrl(clubId, { error: "System+roles+cannot+be+deleted." }));
  }

  // Capture the role name before deletion — after deletion the FK becomes null.
  const deletedRoleName = roleRow?.name ?? "Unknown";

  const { error: deleteErr } = await supabase
    .from("club_roles")
    .delete()
    .eq("id", roleId)
    .eq("club_id", clubId);

  if (deleteErr) {
    redirect(settingsUrl(clubId, { error: encodeURIComponent(deleteErr.message) }));
  }

  await logAuditEvent({
    clubId,
    actorId: user.id,
    action: "role.deleted",
    // target_role_id will be set to NULL by the DB FK after deletion, so store
    // the name in metadata as the durable reference.
    metadata: { role_name: deletedRoleName },
  });

  redirect(settingsUrl(clubId, { success: "Role+deleted." }));
}

// ─── Assign role to member ────────────────────────────────────────────────────

export async function assignRoleToMemberAction(formData: FormData) {
  const parsed = assignRoleSchema.safeParse({
    clubId: formData.get("club_id"),
    roleId: formData.get("role_id"),
    targetUserId: formData.get("target_user_id"),
  });

  if (!parsed.success) {
    const clubIdRaw = formData.get("club_id");
    const roleIdRaw = formData.get("role_id");
    const clubId = typeof clubIdRaw === "string" ? clubIdRaw : "";
    const roleId = typeof roleIdRaw === "string" ? roleIdRaw : "";
    redirect(settingsUrl(clubId, { roleId, error: safeValidationError(parsed) }));
  }

  const { clubId, roleId, targetUserId } = parsed.data;

  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  // Fetch role name for audit metadata before the operation.
  const { data: roleNameRow } = await supabase
    .from("club_roles")
    .select("name")
    .eq("id", roleId)
    .eq("club_id", clubId)
    .maybeSingle();
  const roleName = roleNameRow?.name ?? "Unknown";

  // assignMemberRole enforces members.assign_roles, club membership,
  // role-club ownership, and the President escalation guard.
  const result = await assignMemberRole(user.id, targetUserId, clubId, roleId);

  if (!result.ok) {
    redirect(settingsUrl(clubId, { roleId, error: encodeURIComponent(result.error) }));
  }

  await logAuditEvent({
    clubId,
    actorId: user.id,
    action: "role.assigned",
    targetUserId,
    targetRoleId: roleId,
    metadata: { role_name: roleName },
  });

  redirect(settingsUrl(clubId, { roleId, success: "Member+assigned+to+role." }));
}

// ─── Remove role from member ──────────────────────────────────────────────────

export async function removeRoleFromMemberAction(formData: FormData) {
  const parsed = removeRoleSchema.safeParse({
    clubId: formData.get("club_id"),
    roleId: formData.get("role_id"),
    targetUserId: formData.get("target_user_id"),
  });

  if (!parsed.success) {
    const clubIdRaw = formData.get("club_id");
    const roleIdRaw = formData.get("role_id");
    const clubId = typeof clubIdRaw === "string" ? clubIdRaw : "";
    const roleId = typeof roleIdRaw === "string" ? roleIdRaw : "";
    redirect(settingsUrl(clubId, { roleId, error: safeValidationError(parsed) }));
  }

  const { clubId, roleId, targetUserId } = parsed.data;

  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  // Fetch role name for audit metadata before the operation.
  const { data: roleNameRow } = await supabase
    .from("club_roles")
    .select("name")
    .eq("id", roleId)
    .eq("club_id", clubId)
    .maybeSingle();
  const roleName = roleNameRow?.name ?? "Unknown";

  // removeMemberRole enforces members.assign_roles and the last-President trigger.
  const result = await removeMemberRole(user.id, targetUserId, clubId, roleId);

  if (!result.ok) {
    redirect(settingsUrl(clubId, { roleId, error: encodeURIComponent(result.error) }));
  }

  await logAuditEvent({
    clubId,
    actorId: user.id,
    action: "role.removed",
    targetUserId,
    targetRoleId: roleId,
    metadata: { role_name: roleName },
  });

  redirect(settingsUrl(clubId, { roleId, success: "Role+removed+from+member." }));
}
