import "server-only";
import { createAdminClient } from "@/lib/supabase/admin";
import { createBulkNotifications } from "@/lib/notifications/create-notification";

/**
 * Publishes announcements whose scheduled_for is in the past and is_published is false,
 * then notifies active club members (except the original author).
 */
export async function publishDueScheduledAnnouncements(): Promise<{ published: number }> {
  const admin = createAdminClient();
  const nowIso = new Date().toISOString();

  const { data: due, error } = await admin
    .from("announcements")
    .select("id, club_id, title, created_by, poll_question")
    .eq("is_published", false)
    .not("scheduled_for", "is", null)
    .lte("scheduled_for", nowIso);

  if (error || !due?.length) {
    return { published: 0 };
  }

  let published = 0;

  for (const row of due) {
    // Only treat as newly published if we flip is_published false → true (idempotent under
    // overlapping cron runs and safe to retry without duplicate notifications).
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

    const { data: members } = await admin
      .from("club_members")
      .select("user_id")
      .eq("club_id", row.club_id)
      .eq("membership_status", "active")
      .neq("user_id", row.created_by);

    if (!members?.length) continue;

    const hasPoll = Boolean(row.poll_question?.trim());
    const href = `/clubs/${row.club_id}/announcements#announcement-${row.id}`;

    await createBulkNotifications(
      members.map((m) => ({
        userId: m.user_id,
        clubId: row.club_id,
        type: hasPoll ? ("poll_created" as const) : ("announcement_created" as const),
        title: row.title,
        body: hasPoll ? "A new poll was posted in your club." : "A new announcement was posted in your club.",
        href,
        metadata: { announcement_id: row.id },
      })),
    );
  }

  return { published };
}
