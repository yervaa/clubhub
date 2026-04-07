import "server-only";

import { createClient } from "@/lib/supabase/server";
import { hasPermission } from "@/lib/rbac/permissions";

/**
 * Mirrors export-route and members page: RBAC permission or active legacy officer.
 */
export async function canImportMemberList(actorId: string, clubId: string): Promise<boolean> {
  if (await hasPermission(actorId, clubId, "members.import_roster")) {
    return true;
  }

  const supabase = await createClient();
  const { data } = await supabase
    .from("club_members")
    .select("role, membership_status")
    .eq("club_id", clubId)
    .eq("user_id", actorId)
    .maybeSingle();

  return data?.role === "officer" && data.membership_status === "active";
}
