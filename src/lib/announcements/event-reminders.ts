import "server-only";
import { createAdminClient } from "@/lib/supabase/admin";
import { createBulkNotifications } from "@/lib/notifications/create-notification";

/**
 * Sends one in-app reminder per (event, user) for RSVPs yes/maybe when the event
 * starts in roughly 24 hours. Uses event_reminder_dispatches for idempotency.
 */
export async function dispatchEventReminders(): Promise<{ notified: number }> {
  const admin = createAdminClient();
  const now = Date.now();
  const windowStart = new Date(now + 22 * 60 * 60 * 1000).toISOString();
  const windowEnd = new Date(now + 26 * 60 * 60 * 1000).toISOString();

  const { data: events, error: evErr } = await admin
    .from("events")
    .select("id, club_id, title, event_date")
    .gte("event_date", windowStart)
    .lte("event_date", windowEnd);

  if (evErr || !events?.length) {
    return { notified: 0 };
  }

  let notified = 0;

  for (const ev of events) {
    const { data: rsvps } = await admin
      .from("rsvps")
      .select("user_id, status")
      .eq("event_id", ev.id)
      .in("status", ["yes", "maybe"]);

    if (!rsvps?.length) continue;

    const userIds = [...new Set(rsvps.map((r) => r.user_id))];

    const { data: already } = await admin
      .from("event_reminder_dispatches")
      .select("user_id")
      .eq("event_id", ev.id)
      .in("user_id", userIds);

    const done = new Set((already ?? []).map((r) => r.user_id));
    const targets = userIds.filter((uid) => !done.has(uid));
    if (targets.length === 0) continue;

    const when = new Date(ev.event_date).toLocaleString(undefined, {
      weekday: "short",
      month: "short",
      day: "numeric",
      hour: "numeric",
      minute: "2-digit",
    });

    const newlyDispatched: string[] = [];
    for (const user_id of targets) {
      const { error: rowErr } = await admin.from("event_reminder_dispatches").insert({ event_id: ev.id, user_id });
      if (rowErr) {
        if (rowErr.code !== "23505") {
          console.error("[event-reminders] dispatch insert failed", ev.id, user_id, rowErr.message);
        }
        continue;
      }
      newlyDispatched.push(user_id);
    }

    if (newlyDispatched.length === 0) continue;

    await createBulkNotifications(
      newlyDispatched.map((userId) => ({
        userId,
        clubId: ev.club_id,
        type: "event_reminder" as const,
        title: `Reminder: ${ev.title}`,
        body: `This event starts soon (${when}).`,
        href: `/clubs/${ev.club_id}/events`,
        metadata: { event_id: ev.id },
      })),
    );

    notified += newlyDispatched.length;
  }

  return { notified };
}
