import "server-only";

import type { SupabaseClient } from "@supabase/supabase-js";

/** Service-role client: confirm task belongs to club before mutating assignees or relying on updates. */
export async function getClubTaskIdIfInClub(
  admin: SupabaseClient,
  taskId: string,
  clubId: string,
): Promise<string | null> {
  const { data } = await admin.from("club_tasks").select("id").eq("id", taskId).eq("club_id", clubId).maybeSingle();
  return data?.id ?? null;
}
