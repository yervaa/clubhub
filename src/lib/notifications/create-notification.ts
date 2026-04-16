import "server-only";

import { sendTransactionalEmail } from "@/lib/email/send-transactional-email";
import { createAdminClient } from "@/lib/supabase/admin";
import { loadResolvedPreferencesForUsers } from "@/lib/notifications/load-preferences";
import type { ResolvedNotificationPreferences } from "@/lib/notifications/preference-model";
import type { NotificationInput } from "@/lib/notifications/notification-types";
import {
  shouldReceiveInAppNotification,
  shouldSendImmediateEmailNotification,
} from "@/lib/notifications/preference-helpers";

// Re-export for callers that import types from this module.
export type { NotificationInput, NotificationType } from "@/lib/notifications/notification-types";

// ─── Notification type catalog ────────────────────────────────────────────────
// Keep these in sync with the type strings stored in the notifications table.
// UI rendering (icons, copy) is derived from these keys in notification-bell.tsx.

async function loadEmailsForUsers(
  admin: ReturnType<typeof createAdminClient>,
  userIds: string[],
): Promise<Map<string, string>> {
  const map = new Map<string, string>();
  if (userIds.length === 0) return map;
  const { data, error } = await admin.from("profiles").select("id, email").in("id", userIds);
  if (error) {
    console.error("[notifications] Failed to load profile emails:", error.message);
    return map;
  }
  for (const row of data ?? []) {
    const email = typeof row.email === "string" ? row.email.trim() : "";
    if (email) map.set(row.id, email);
  }
  return map;
}

function buildEmailText(input: NotificationInput): string {
  const lines = [input.title, "", input.body];
  if (input.href) {
    lines.push("", input.href);
  }
  return lines.join("\n");
}

async function sendEmailsForNotifications(
  admin: ReturnType<typeof createAdminClient>,
  inputs: NotificationInput[],
  prefsMap: Map<string, ResolvedNotificationPreferences>,
): Promise<void> {
  const now = new Date();
  const needEmail = inputs.filter((input) => {
    const prefs = prefsMap.get(input.userId);
    if (!prefs) return false;
    return shouldSendImmediateEmailNotification(prefs, input.type, now);
  });
  if (needEmail.length === 0) return;

  const emailMap = await loadEmailsForUsers(
    admin,
    [...new Set(needEmail.map((i) => i.userId))],
  );

  for (const input of needEmail) {
    const to = emailMap.get(input.userId);
    if (!to) continue;
    await sendTransactionalEmail({
      to,
      subject: input.title,
      text: buildEmailText(input),
    });
  }
}

// ─── Write helpers ────────────────────────────────────────────────────────────
// Both helpers use the admin client so writes bypass RLS.
// Failures are non-fatal — we log but never block the triggering action.
// In-app rows are only inserted when the user’s in-app preference for that category is on.
// Email is sent when the email preference is on and the user is not in quiet hours
// (otherwise suppressed; weekly digest can summarize if enabled).

export async function createNotification(input: NotificationInput): Promise<void> {
  const admin = createAdminClient();
  const prefsMap = await loadResolvedPreferencesForUsers(admin, [input.userId]);
  const prefs = prefsMap.get(input.userId)!;

  if (shouldReceiveInAppNotification(prefs, input.type)) {
    const { error } = await admin.from("notifications").insert({
      user_id: input.userId,
      club_id: input.clubId ?? null,
      type: input.type,
      title: input.title,
      body: input.body,
      href: input.href ?? null,
      activity_event_id: input.activityEventId ?? null,
      metadata: input.metadata ?? {},
    });

    if (error) {
      console.error("[notifications] Failed to create notification:", input.type, error.message);
    }
  }

  await sendEmailsForNotifications(admin, [input], prefsMap);
}

export type BulkNotificationResult = { ok: true } | { ok: false; message: string };

/**
 * Inserts multiple notifications in a single round-trip.
 * Use when broadcasting to all club members (e.g. announcement / event created).
 * Returns ok:false when the insert fails so callers can retry (e.g. cron) without duplicating
 * if combined with existence checks or delivery marker columns.
 */
export async function createBulkNotifications(inputs: NotificationInput[]): Promise<BulkNotificationResult> {
  if (inputs.length === 0) {
    return { ok: true };
  }

  const admin = createAdminClient();
  const userIds = [...new Set(inputs.map((i) => i.userId))];
  const prefsMap = await loadResolvedPreferencesForUsers(admin, userIds);

  const inAppRows = inputs.filter((input) => {
    const prefs = prefsMap.get(input.userId)!;
    return shouldReceiveInAppNotification(prefs, input.type);
  });

  if (inAppRows.length > 0) {
    const rows = inAppRows.map((input) => ({
      user_id: input.userId,
      club_id: input.clubId ?? null,
      type: input.type,
      title: input.title,
      body: input.body,
      href: input.href ?? null,
      activity_event_id: input.activityEventId ?? null,
      metadata: input.metadata ?? {},
    }));

    const { error } = await admin.from("notifications").insert(rows);

    if (error) {
      console.error("[notifications] Failed to create bulk notifications:", inputs[0]?.type, error.message);
      return { ok: false, message: error.message };
    }
  }

  await sendEmailsForNotifications(admin, inputs, prefsMap);

  return { ok: true };
}
