import "server-only";
import { createClient } from "@/lib/supabase/server";

// ─── Permission key catalog ───────────────────────────────────────────────────
// Must stay in sync with the `permissions` table (see supabase migrations).

export type PermissionKey =
  // Club administration
  | "club.manage_settings"
  | "club.archive"
  | "club.delete"
  | "club.transfer_presidency"
  // Member management
  | "members.view"
  | "members.invite"
  | "members.remove"
  | "members.assign_roles"
  | "members.manage_tags"
  | "members.manage_committees"
  | "members.manage_teams"
  | "members.review_join_requests"
  // Role management
  | "roles.create"
  | "roles.edit"
  | "roles.delete"
  | "roles.assign_permissions"
  // Announcements
  | "announcements.create"
  | "announcements.edit"
  | "announcements.delete"
  // Events
  | "events.create"
  | "events.edit"
  | "events.delete"
  // Attendance
  | "attendance.mark"
  | "attendance.edit"
  // Reflections
  | "reflections.create"
  | "reflections.edit"
  | "reflections.delete"
  // Insights & analytics
  | "insights.view"
  | "insights.export"
  // Audit
  | "audit_logs.view"
  // Tasks
  | "tasks.view"
  | "tasks.create"
  | "tasks.edit"
  | "tasks.delete"
  | "tasks.assign"
  | "tasks.complete";

// ─── Supabase RPC row types ───────────────────────────────────────────────────

type GetUserPermissionsRow = { permission_key: string };

// ─── Core helpers ─────────────────────────────────────────────────────────────

/**
 * Returns the full set of permission keys a user holds in a club.
 * Prefer `hasPermission` for individual checks to avoid unnecessary work.
 */
export async function getUserPermissions(
  userId: string,
  clubId: string,
): Promise<Set<PermissionKey>> {
  const supabase = await createClient();

  const { data, error } = await supabase.rpc("get_user_permissions", {
    target_user_id: userId,
    target_club_id: clubId,
  });

  if (error || !data) {
    return new Set();
  }

  return new Set(
    (data as GetUserPermissionsRow[]).map((row) => row.permission_key as PermissionKey),
  );
}

/**
 * Returns true if the user holds the given permission in the club.
 *
 * Delegates to the `has_club_permission` Postgres function (security definer)
 * so the check always runs with consistent, RLS-bypassing logic.
 */
export async function hasPermission(
  userId: string,
  clubId: string,
  permission: PermissionKey,
): Promise<boolean> {
  const supabase = await createClient();

  const { data, error } = await supabase.rpc("has_club_permission", {
    target_club_id: clubId,
    target_user_id: userId,
    permission_key: permission,
  });

  if (error) {
    return false;
  }

  return Boolean(data);
}

/**
 * Returns true if the user holds the President system role in the club.
 * Convenience wrapper around `has_club_permission` for high-privilege guards.
 */
export async function isClubPresident(userId: string, clubId: string): Promise<boolean> {
  const supabase = await createClient();

  const { data, error } = await supabase.rpc("is_club_president", {
    target_club_id: clubId,
    target_user_id: userId,
  });

  if (error) {
    return false;
  }

  return Boolean(data);
}

/**
 * Asserts that the user has a permission and throws a typed error if not.
 * Use in server actions where you want to fail fast with a consistent message.
 *
 * @throws {PermissionDeniedError}
 */
export async function requirePermission(
  userId: string,
  clubId: string,
  permission: PermissionKey,
): Promise<void> {
  const allowed = await hasPermission(userId, clubId, permission);
  if (!allowed) {
    throw new PermissionDeniedError(permission);
  }
}

// ─── Error type ───────────────────────────────────────────────────────────────

export class PermissionDeniedError extends Error {
  readonly permission: PermissionKey;

  constructor(permission: PermissionKey) {
    super(`Permission denied: ${permission}`);
    this.name = "PermissionDeniedError";
    this.permission = permission;
  }
}
