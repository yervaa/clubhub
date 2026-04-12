import "server-only";
import type { SupabaseClient } from "@supabase/supabase-js";

/**
 * True if at least one announcement_created / poll_created notification exists
 * with this announcement_id in metadata (idempotent guard against duplicate broadcasts).
 */
export async function announcementBroadcastNotificationExists(
  admin: SupabaseClient,
  announcementId: string,
): Promise<boolean> {
  const { count, error } = await admin
    .from("notifications")
    .select("id", { count: "exact", head: true })
    .filter("metadata->>announcement_id", "eq", announcementId)
    .in("type", ["announcement_created", "poll_created"]);

  if (error) {
    console.error("[notifications] announcement broadcast lookup failed:", error.message);
    return false;
  }

  return (count ?? 0) > 0;
}

/**
 * True if an event_reminder notification exists for this user + event in metadata.
 */
export async function eventReminderNotificationExists(
  admin: SupabaseClient,
  userId: string,
  eventId: string,
): Promise<boolean> {
  const { count, error } = await admin
    .from("notifications")
    .select("id", { count: "exact", head: true })
    .eq("user_id", userId)
    .eq("type", "event_reminder")
    .filter("metadata->>event_id", "eq", eventId);

  if (error) {
    console.error("[notifications] event reminder lookup failed:", error.message);
    return false;
  }

  return (count ?? 0) > 0;
}
