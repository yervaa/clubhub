import "server-only";
import type { SupabaseClient } from "@supabase/supabase-js";
import { createAdminClient } from "@/lib/supabase/admin";
import { createBulkNotifications } from "@/lib/notifications/create-notification";
import { eventReminderNotificationExists } from "@/lib/notifications/delivery-queries";

type EventRow = { id: string; club_id: string; title: string; event_date: string };

const nowIso = () => new Date().toISOString();

function formatEventWhen(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    weekday: "short",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

async function markRemindersNotified(admin: SupabaseClient, eventId: string, userIds: string[]) {
  if (userIds.length === 0) return;
  const t = nowIso();
  await admin
    .from("event_reminder_dispatches")
    .update({ notified_at: t })
    .eq("event_id", eventId)
    .in("user_id", userIds)
    .is("notified_at", null);
}

/**
 * Ensures dispatch rows exist for idempotency, then sets notified_at only after
 * notifications insert succeeds (or heals if a notification already exists).
 */
async function deliverEventRemindersForUsers(
  admin: SupabaseClient,
  ev: EventRow,
  userIds: string[],
): Promise<number> {
  if (userIds.length === 0) return 0;

  const { data: existing } = await admin
    .from("event_reminder_dispatches")
    .select("user_id, notified_at")
    .eq("event_id", ev.id)
    .in("user_id", userIds);

  const haveRow = new Set((existing ?? []).map((r) => r.user_id));

  for (const user_id of userIds) {
    if (haveRow.has(user_id)) continue;
    const { error } = await admin.from("event_reminder_dispatches").insert({ event_id: ev.id, user_id });
    if (error && error.code !== "23505") {
      console.error("[event-reminders] dispatch insert failed", ev.id, user_id, error.message);
    }
  }

  const { data: rows } = await admin
    .from("event_reminder_dispatches")
    .select("user_id, notified_at")
    .eq("event_id", ev.id)
    .in("user_id", userIds);

  const pending = userIds.filter((uid) => {
    const r = rows?.find((x) => x.user_id === uid);
    return r != null && r.notified_at == null;
  });

  if (pending.length === 0) return 0;

  const eventPast = new Date(ev.event_date).getTime() <= Date.now();

  const { data: rsvpRows } = await admin
    .from("rsvps")
    .select("user_id, status")
    .eq("event_id", ev.id)
    .in("user_id", pending)
    .in("status", ["yes", "maybe"]);

  const stillRsvpd = new Set((rsvpRows ?? []).map((r) => r.user_id));
  const abandon: string[] = [];
  const active = pending.filter((uid) => {
    if (!stillRsvpd.has(uid)) {
      abandon.push(uid);
      return false;
    }
    return true;
  });

  if (abandon.length > 0) {
    await markRemindersNotified(admin, ev.id, abandon);
  }

  if (active.length === 0) return 0;

  if (eventPast) {
    const heal: string[] = [];
    for (const uid of active) {
      if (await eventReminderNotificationExists(admin, uid, ev.id)) {
        heal.push(uid);
      }
    }
    if (heal.length > 0) {
      await markRemindersNotified(admin, ev.id, heal);
    }
    const rest = active.filter((uid) => !heal.includes(uid));
    if (rest.length > 0) {
      await markRemindersNotified(admin, ev.id, rest);
    }
    return 0;
  }

  const toHeal: string[] = [];
  const toSend: string[] = [];
  for (const uid of active) {
    if (await eventReminderNotificationExists(admin, uid, ev.id)) {
      toHeal.push(uid);
    } else {
      toSend.push(uid);
    }
  }

  if (toHeal.length > 0) {
    await markRemindersNotified(admin, ev.id, toHeal);
  }

  if (toSend.length === 0) {
    return toHeal.length;
  }

  const when = formatEventWhen(ev.event_date);
  const result = await createBulkNotifications(
    toSend.map((userId) => ({
      userId,
      clubId: ev.club_id,
      type: "event_reminder" as const,
      title: `Reminder: ${ev.title}`,
      body: `This event starts soon (${when}).`,
      href: `/clubs/${ev.club_id}/events`,
      metadata: { event_id: ev.id },
    })),
  );

  if (result.ok) {
    await markRemindersNotified(admin, ev.id, toSend);
    return toSend.length + toHeal.length;
  }

  return toHeal.length;
}

/**
 * Sends one in-app reminder per (event, user) for RSVPs yes/maybe when the event
 * starts in roughly 24 hours. Retries until notified_at is set or the event has passed.
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

  let notified = 0;

  if (!evErr && events?.length) {
    for (const ev of events) {
      const { data: rsvps } = await admin
        .from("rsvps")
        .select("user_id, status")
        .eq("event_id", ev.id)
        .in("status", ["yes", "maybe"]);

      if (!rsvps?.length) continue;

      const userIds = [...new Set(rsvps.map((r) => r.user_id))];
      notified += await deliverEventRemindersForUsers(admin, ev, userIds);
    }
  }

  const { data: stuckRows } = await admin.from("event_reminder_dispatches").select("event_id, user_id").is("notified_at", null);

  if (stuckRows?.length) {
    const eventIds = [...new Set(stuckRows.map((r) => r.event_id))];
    const { data: eventRows } = await admin
      .from("events")
      .select("id, club_id, title, event_date")
      .in("id", eventIds);

    const evMap = new Map((eventRows ?? []).map((e) => [e.id, e]));

    const byEvent = new Map<string, string[]>();
    for (const row of stuckRows) {
      const ev = evMap.get(row.event_id);
      if (!ev) continue;
      const list = byEvent.get(row.event_id) ?? [];
      list.push(row.user_id);
      byEvent.set(row.event_id, list);
    }

    for (const [eventId, users] of byEvent) {
      const ev = evMap.get(eventId);
      if (!ev) continue;
      notified += await deliverEventRemindersForUsers(admin, ev, users);
    }
  }

  return { notified };
}
