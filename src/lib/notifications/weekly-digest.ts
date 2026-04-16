import "server-only";

import { getPublicSiteOrigin } from "@/lib/app/site-origin";
import { sendTransactionalEmail } from "@/lib/email/send-transactional-email";
import { createAdminClient } from "@/lib/supabase/admin";

/**
 * Sends one plain-text digest email per opted-in user when there is recent content.
 * Quiet hours are not applied here (scheduled send should run at a civil time via cron).
 */
export async function runWeeklyDigestEmails(): Promise<{ sent: number; skipped: number }> {
  const admin = createAdminClient();
  const now = new Date();
  const since = new Date(now);
  since.setDate(since.getDate() - 7);
  const until = new Date(now);
  until.setDate(until.getDate() + 7);

  const { data: optInRows, error: optErr } = await admin
    .from("notification_preferences")
    .select("user_id")
    .eq("weekly_digest_enabled", true);

  if (optErr) {
    console.error("[digest] Failed to list preferences:", optErr.message);
    return { sent: 0, skipped: 0 };
  }

  const userIds = [...new Set((optInRows ?? []).map((r) => r.user_id))];
  let sent = 0;
  let skipped = 0;

  for (const userId of userIds) {
    const { data: membershipRows } = await admin
      .from("club_members")
      .select("club_id")
      .eq("user_id", userId)
      .eq("membership_status", "active");

    const clubIds = [...new Set((membershipRows ?? []).map((m) => m.club_id))];
    if (clubIds.length === 0) {
      skipped += 1;
      continue;
    }

    const { data: clubRows } = await admin.from("clubs").select("id, name").in("id", clubIds);
    const clubNameById = new Map((clubRows ?? []).map((c) => [c.id, c.name]));

    const [{ data: recentAnnouncements }, { data: upcomingEvents }] = await Promise.all([
      admin
        .from("announcements")
        .select("club_id, title, created_at")
        .in("club_id", clubIds)
        .eq("is_published", true)
        .eq("approval_status", "approved")
        .gte("created_at", since.toISOString())
        .order("created_at", { ascending: false })
        .limit(25),
      admin
        .from("events")
        .select("club_id, title, event_date")
        .in("club_id", clubIds)
        .eq("approval_status", "approved")
        .gte("event_date", now.toISOString())
        .lte("event_date", until.toISOString())
        .order("event_date", { ascending: true })
        .limit(25),
    ]);

    const ann = recentAnnouncements ?? [];
    const ev = upcomingEvents ?? [];
    if (ann.length === 0 && ev.length === 0) {
      skipped += 1;
      continue;
    }

    const { data: profile } = await admin.from("profiles").select("email").eq("id", userId).maybeSingle();
    const to = profile?.email?.trim();
    if (!to) {
      skipped += 1;
      continue;
    }

    const lines: string[] = [
      "Your ClubHub weekly digest",
      "",
      `Summary for the week ending ${now.toLocaleDateString(undefined, { dateStyle: "medium" })}.`,
      "",
    ];

    if (ann.length > 0) {
      lines.push("Recent announcements");
      for (const a of ann) {
        const club = clubNameById.get(a.club_id) ?? "Club";
        lines.push(`- [${club}] ${a.title}`);
      }
      lines.push("");
    }

    if (ev.length > 0) {
      lines.push("Upcoming events (next 7 days)");
      for (const e of ev) {
        const club = clubNameById.get(e.club_id) ?? "Club";
        const when = new Date(e.event_date).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
        lines.push(`- [${club}] ${e.title} — ${when}`);
      }
      lines.push("");
    }

    const origin = getPublicSiteOrigin();
    if (origin) {
      lines.push(`Open ClubHub to see full details: ${origin}/notifications`);
    } else {
      lines.push("Open ClubHub to see full details in the app.");
    }

    const result = await sendTransactionalEmail({
      to,
      subject: "Your ClubHub weekly digest",
      text: lines.join("\n"),
    });

    if (result.ok) {
      sent += 1;
    } else {
      skipped += 1;
    }
  }

  return { sent, skipped };
}
