import "server-only";
import type { SupabaseClient } from "@supabase/supabase-js";
import { createAdminClient } from "@/lib/supabase/admin";
import { createBulkNotifications } from "@/lib/notifications/create-notification";
import { announcementBroadcastNotificationExists } from "@/lib/notifications/delivery-queries";

type AnnouncementPublishRow = {
  id: string;
  club_id: string;
  title: string;
  created_by: string;
  poll_question: string | null;
  is_urgent: boolean | null;
};

const nowIso = () => new Date().toISOString();

async function markMemberBroadcastSent(admin: SupabaseClient, announcementId: string) {
  await admin
    .from("announcements")
    .update({ member_broadcast_sent_at: nowIso() })
    .eq("id", announcementId)
    .is("member_broadcast_sent_at", null);
}

/**
 * Sends announcement_created / poll_created (if not already in notifications), then sets
 * member_broadcast_sent_at. Safe to call repeatedly (cron retry).
 */
async function deliverScheduledAnnouncementBroadcast(admin: SupabaseClient, row: AnnouncementPublishRow) {
  if (await announcementBroadcastNotificationExists(admin, row.id)) {
    await markMemberBroadcastSent(admin, row.id);
    return;
  }

  const { data: members } = await admin
    .from("club_members")
    .select("user_id")
    .eq("club_id", row.club_id)
    .eq("membership_status", "active")
    .neq("user_id", row.created_by);

  if (!members?.length) {
    await markMemberBroadcastSent(admin, row.id);
    return;
  }

  const hasPoll = Boolean(row.poll_question?.trim());
  const href = `/clubs/${row.club_id}/announcements#announcement-${row.id}`;
  const isUrgent = Boolean(row.is_urgent);
  const body = hasPoll
    ? isUrgent
      ? "Urgent poll: please review and vote."
      : "A new poll was posted in your club."
    : isUrgent
      ? "Urgent club update posted."
      : "A new announcement was posted in your club.";

  const result = await createBulkNotifications(
    members.map((m) => ({
      userId: m.user_id,
      clubId: row.club_id,
      type: hasPoll ? ("poll_created" as const) : ("announcement_created" as const),
      title: row.title,
      body,
      href,
      metadata: { announcement_id: row.id },
    })),
  );

  if (result.ok) {
    await markMemberBroadcastSent(admin, row.id);
  }
}

/**
 * Publishes due scheduled announcements, delivers member broadcasts, and retries any
 * published scheduled rows that still lack member_broadcast_sent_at (failed notify).
 */
export async function publishDueScheduledAnnouncements(): Promise<{ published: number }> {
  const admin = createAdminClient();
  const t = nowIso();

  const { data: due, error } = await admin
    .from("announcements")
    .select("id, club_id, title, created_by, poll_question, is_urgent")
    .eq("is_published", false)
    .eq("approval_status", "approved")
    .not("scheduled_for", "is", null)
    .lte("scheduled_for", t);

  if (error || !due?.length) {
    // Still run retry pass below
  }

  let published = 0;

  for (const row of due ?? []) {
    const { data: flipped, error: upErr } = await admin
      .from("announcements")
      .update({ is_published: true })
      .eq("id", row.id)
      .eq("is_published", false)
      .select("id")
      .maybeSingle();

    if (upErr) {
      console.error("[announcements:publish-scheduled] update failed", row.id, upErr.message);
      continue;
    }

    if (!flipped) {
      continue;
    }

    published += 1;
    await deliverScheduledAnnouncementBroadcast(admin, row as AnnouncementPublishRow);
  }

  // Retry member broadcast: scheduled posts past their time, or immediate publishes
  // (scheduled_for null) where notify failed after is_published was set.
  const pendingSelect =
    "id, club_id, title, created_by, poll_question, is_urgent" as const;
  const basePending = () =>
    admin
      .from("announcements")
      .select(pendingSelect)
      .eq("is_published", true)
      .eq("approval_status", "approved")
      .is("member_broadcast_sent_at", null);

  const [{ data: pendingScheduled }, { data: pendingImmediate }] = await Promise.all([
    basePending().not("scheduled_for", "is", null).lte("scheduled_for", t),
    basePending().is("scheduled_for", null),
  ]);

  const pendingById = new Map<string, AnnouncementPublishRow>();
  for (const row of [...(pendingScheduled ?? []), ...(pendingImmediate ?? [])]) {
    pendingById.set(row.id, row as AnnouncementPublishRow);
  }

  for (const row of pendingById.values()) {
    await deliverScheduledAnnouncementBroadcast(admin, row);
  }

  return { published };
}
