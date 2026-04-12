import "server-only";
import { createAdminClient } from "@/lib/supabase/admin";

// ─── Notification type catalog ────────────────────────────────────────────────
// Keep these in sync with the type strings stored in the notifications table.
// UI rendering (icons, copy) is derived from these keys in notification-bell.tsx.

export type NotificationType =
  | "announcement.posted"
  | "announcement_created"
  | "poll_created"
  | "event.created"
  | "event_reminder"
  | "role.assigned"
  | "role.removed"
  | "task.assigned"
  | "task_assigned";

// ─── Input shape ──────────────────────────────────────────────────────────────

export type NotificationInput = {
  userId: string;
  clubId?: string | null;
  type: NotificationType;
  title: string;
  body: string;
  href?: string | null;
  metadata?: Record<string, unknown>;
};

// ─── Write helpers ────────────────────────────────────────────────────────────
// Both helpers use the admin client so writes bypass RLS.
// Failures are non-fatal — we log but never block the triggering action.

export async function createNotification(input: NotificationInput): Promise<void> {
  const admin = createAdminClient();

  const { error } = await admin.from("notifications").insert({
    user_id: input.userId,
    club_id: input.clubId ?? null,
    type: input.type,
    title: input.title,
    body: input.body,
    href: input.href ?? null,
    metadata: input.metadata ?? {},
  });

  if (error) {
    console.error("[notifications] Failed to create notification:", input.type, error.message);
  }
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

  const rows = inputs.map((input) => ({
    user_id: input.userId,
    club_id: input.clubId ?? null,
    type: input.type,
    title: input.title,
    body: input.body,
    href: input.href ?? null,
    metadata: input.metadata ?? {},
  }));

  const { error } = await admin.from("notifications").insert(rows);

  if (error) {
    console.error("[notifications] Failed to create bulk notifications:", inputs[0]?.type, error.message);
    return { ok: false, message: error.message };
  }

  return { ok: true };
}
