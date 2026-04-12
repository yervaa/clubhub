import "server-only";

import type { SupabaseClient } from "@supabase/supabase-js";

/**
 * Returns user IDs from `candidateIds` that are **not** active members of `clubId`.
 * Fail-closed: on query error, every candidate is treated as invalid.
 */
export async function findUserIdsNotActiveInClub(
  supabase: SupabaseClient,
  clubId: string,
  candidateIds: string[],
): Promise<string[]> {
  if (candidateIds.length === 0) return [];
  const unique = [...new Set(candidateIds)];
  const { data, error } = await supabase
    .from("club_members")
    .select("user_id")
    .eq("club_id", clubId)
    .eq("membership_status", "active")
    .in("user_id", unique);

  if (error) return unique;

  const found = new Set((data ?? []).map((r) => r.user_id as string));
  return unique.filter((id) => !found.has(id));
}
