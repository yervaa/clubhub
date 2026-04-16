"use server";

import { revalidatePath } from "next/cache";
import { createClient } from "@/lib/supabase/server";
import { notificationPreferencesFormSchema } from "@/lib/validation/notification-preferences";

export type NotificationPreferencesActionState =
  | { ok: true; message?: string }
  | { ok: false; message: string }
  | null;

function parseCheckbox(formData: FormData, name: string): boolean {
  return formData.get(name) === "on";
}

export async function updateNotificationPreferencesAction(
  _prev: NotificationPreferencesActionState,
  formData: FormData,
): Promise<NotificationPreferencesActionState> {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    return { ok: false, message: "You must be signed in to update notification settings." };
  }

  const raw = {
    in_app_announcements: parseCheckbox(formData, "in_app_announcements"),
    email_announcements: parseCheckbox(formData, "email_announcements"),
    in_app_events: parseCheckbox(formData, "in_app_events"),
    email_events: parseCheckbox(formData, "email_events"),
    in_app_reminders: parseCheckbox(formData, "in_app_reminders"),
    email_reminders: parseCheckbox(formData, "email_reminders"),
    in_app_role_membership: parseCheckbox(formData, "in_app_role_membership"),
    email_role_membership: parseCheckbox(formData, "email_role_membership"),
    in_app_activity: parseCheckbox(formData, "in_app_activity"),
    email_activity: parseCheckbox(formData, "email_activity"),
    quiet_hours_enabled: parseCheckbox(formData, "quiet_hours_enabled"),
    quiet_hours_start: String(formData.get("quiet_hours_start") ?? "").trim(),
    quiet_hours_end: String(formData.get("quiet_hours_end") ?? "").trim(),
    timezone: String(formData.get("timezone") ?? "").trim() || "UTC",
    weekly_digest_enabled: parseCheckbox(formData, "weekly_digest_enabled"),
  };

  const parsed = notificationPreferencesFormSchema.safeParse(raw);
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    return { ok: false, message: first?.message ?? "Invalid notification settings." };
  }

  const v = parsed.data;
  const quietOn = v.quiet_hours_enabled;

  const { error } = await supabase.from("notification_preferences").upsert(
    {
      user_id: user.id,
      in_app_announcements: v.in_app_announcements,
      email_announcements: v.email_announcements,
      in_app_events: v.in_app_events,
      email_events: v.email_events,
      in_app_reminders: v.in_app_reminders,
      email_reminders: v.email_reminders,
      in_app_role_membership: v.in_app_role_membership,
      email_role_membership: v.email_role_membership,
      in_app_activity: v.in_app_activity,
      email_activity: v.email_activity,
      quiet_hours_enabled: quietOn,
      quiet_hours_start: quietOn ? v.quiet_hours_start!.trim() : null,
      quiet_hours_end: quietOn ? v.quiet_hours_end!.trim() : null,
      timezone: v.timezone,
      weekly_digest_enabled: v.weekly_digest_enabled,
      updated_at: new Date().toISOString(),
    },
    { onConflict: "user_id" },
  );

  if (error) {
    return { ok: false, message: error.message };
  }

  revalidatePath("/settings");
  return { ok: true, message: "Notification settings saved." };
}
