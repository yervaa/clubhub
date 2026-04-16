import "server-only";

import type { SupabaseClient } from "@supabase/supabase-js";
import {
  DEFAULT_NOTIFICATION_PREFERENCES,
  type NotificationPreferencesRow,
  type ResolvedNotificationPreferences,
  rowToResolvedPreferences,
} from "@/lib/notifications/preference-model";

/** Batch-load preferences for notification delivery (service-role client). */
export async function loadResolvedPreferencesForUsers(
  admin: SupabaseClient,
  userIds: string[],
): Promise<Map<string, ResolvedNotificationPreferences>> {
  const unique = [...new Set(userIds)].filter(Boolean);
  const out = new Map<string, ResolvedNotificationPreferences>();

  for (const id of unique) {
    out.set(id, DEFAULT_NOTIFICATION_PREFERENCES);
  }

  if (unique.length === 0) {
    return out;
  }

  const { data, error } = await admin.from("notification_preferences").select("*").in("user_id", unique);

  if (error) {
    console.error("[notifications] Failed to load notification_preferences:", error.message);
    return out;
  }

  for (const row of (data ?? []) as NotificationPreferencesRow[]) {
    out.set(row.user_id, rowToResolvedPreferences(row));
  }

  return out;
}
