import "server-only";

import { createAdminClient } from "@/lib/supabase/admin";
import { createClient } from "@/lib/supabase/server";
import { hasPermission, type PermissionKey } from "@/lib/rbac/permissions";

/**
 * Mirrors RLS on `public.dues` insert/update: `dues.manage` **or** legacy `club_members.role = officer`.
 */
export async function canManageClubStripeDues(userId: string, clubId: string): Promise<boolean> {
  if (await hasPermission(userId, clubId, "dues.manage")) {
    return true;
  }
  const supabase = await createClient();
  const { data } = await supabase
    .from("club_members")
    .select("role")
    .eq("club_id", clubId)
    .eq("user_id", userId)
    .maybeSingle();
  return data?.role === "officer";
}

/** RPC `returns table (user_id uuid)` — normalize to string[]. */
function mapRpcUserIdRows(data: unknown): string[] {
  if (!Array.isArray(data)) return [];
  return data
    .map((row) => {
      if (row && typeof row === "object" && "user_id" in row && typeof (row as { user_id: unknown }).user_id === "string") {
        return (row as { user_id: string }).user_id;
      }
      return null;
    })
    .filter((id): id is string => Boolean(id));
}

export async function listPermissionHolderIds(
  clubId: string,
  permission: PermissionKey,
): Promise<string[]> {
  const admin = createAdminClient();
  const { data, error } = await admin.rpc("list_club_members_with_permission", {
    p_club_id: clubId,
    p_permission_key: permission,
  });
  if (error) {
    console.error("[dues-permissions] list_club_members_with_permission", error.message);
    return [];
  }
  return mapRpcUserIdRows(data);
}
