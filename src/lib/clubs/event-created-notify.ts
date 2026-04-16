import "server-only";

import { createActivityEvent } from "@/lib/activity/create-activity-event";
import { createBulkNotifications } from "@/lib/notifications/create-notification";
import type { createClient } from "@/lib/supabase/server";

type SupabaseServer = Awaited<ReturnType<typeof createClient>>;

/**
 * Activity + member notifications when an event becomes visible to the club
 * (immediate create with approvals off, or after advisor approval).
 */
export async function notifyClubMembersOfPublishedEvent(params: {
  supabase: SupabaseServer;
  clubId: string;
  /** Exclude from member blast (typically the organizer). */
  excludeNotifyUserId: string;
  eventId: string;
  title: string;
  eventDate: Date;
  location: string;
  occurrenceCount: number;
  /** Activity + audit: who caused the publish (organizer or advisor). */
  actorId: string;
}): Promise<void> {
  const {
    supabase,
    clubId,
    excludeNotifyUserId,
    eventId,
    title,
    eventDate,
    location,
    occurrenceCount,
    actorId,
  } = params;

  const eventActivityId = await createActivityEvent({
    type: "event.created",
    actorId,
    clubId,
    entityId: eventId,
    targetLabel: title,
    href: `/clubs/${clubId}/events#event-${eventId}`,
  });

  const { data: otherMembers } = await supabase
    .from("club_members")
    .select("user_id")
    .eq("club_id", clubId)
    .eq("membership_status", "active")
    .neq("user_id", excludeNotifyUserId);

  if (!otherMembers?.length) return;

  await createBulkNotifications(
    otherMembers.map((m) => ({
      userId: m.user_id,
      clubId,
      type: "event.created" as const,
      title,
      body:
        occurrenceCount > 1
          ? `New recurring series (${occurrenceCount} events) starts ${eventDate.toLocaleDateString(undefined, { month: "short", day: "numeric" })} · ${location}`
          : `New event on ${eventDate.toLocaleDateString(undefined, { month: "short", day: "numeric" })} · ${location}`,
      href: `/clubs/${clubId}/events`,
      activityEventId: eventActivityId,
    })),
  );
}
