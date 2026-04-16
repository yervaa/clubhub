import "server-only";

import { createBulkNotifications } from "@/lib/notifications/create-notification";
import { createAdminClient } from "@/lib/supabase/admin";
import type { createClient } from "@/lib/supabase/server";

type SupabaseServer = Awaited<ReturnType<typeof createClient>>;

/**
 * Sends member-facing announcement/poll notifications and sets `member_broadcast_sent_at` when successful.
 * Used on publish from organizers and on advisor approval.
 */
export async function sendAnnouncementMemberBroadcast(params: {
  supabase: SupabaseServer;
  clubId: string;
  actorId: string;
  announcementId: string;
  title: string;
  hasPoll: boolean;
  activityEventId: string | null;
  isUrgent: boolean;
}): Promise<void> {
  const { supabase, clubId, actorId, announcementId, title, hasPoll, activityEventId, isUrgent } = params;
  const { data: otherMembers } = await supabase
    .from("club_members")
    .select("user_id")
    .eq("club_id", clubId)
    .eq("membership_status", "active")
    .neq("user_id", actorId);

  const admin = createAdminClient();
  const href = `/clubs/${clubId}/announcements#announcement-${announcementId}`;
  const body = hasPoll
    ? isUrgent
      ? "Urgent poll: please review and vote."
      : "A new poll was posted in your club."
    : isUrgent
      ? "Urgent club update posted."
      : "A new announcement was posted in your club.";

  const sent =
    otherMembers && otherMembers.length > 0
      ? await createBulkNotifications(
          otherMembers.map((m) => ({
            userId: m.user_id,
            clubId,
            type: hasPoll ? ("poll_created" as const) : ("announcement_created" as const),
            title,
            body,
            href,
            activityEventId: activityEventId ?? undefined,
            metadata: { announcement_id: announcementId, activity_event_id: activityEventId },
          })),
        )
      : ({ ok: true } as const);

  if (sent.ok) {
    await admin
      .from("announcements")
      .update({ member_broadcast_sent_at: new Date().toISOString() })
      .eq("id", announcementId)
      .is("member_broadcast_sent_at", null);
  }
}
