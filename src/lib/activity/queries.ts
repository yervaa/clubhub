import "server-only";
import { createClient } from "@/lib/supabase/server";
import type { ActivityFeedItem, ActivityEventType } from "@/lib/activity/types";

type ActivityEventRow = {
  id: string;
  type: string;
  actor_id: string;
  club_id: string;
  target_label: string;
  href: string | null;
  metadata: Record<string, unknown> | null;
  created_at: string;
};

function actionLabel(type: ActivityEventType): string {
  switch (type) {
    case "announcement.created":
      return "posted an announcement";
    case "event.created":
      return "created an event";
    case "rsvp.submitted":
      return "submitted an RSVP";
    case "attendance.marked":
      return "marked attendance";
    case "role.assigned":
      return "assigned a role";
    case "role.removed":
      return "removed a role";
    default:
      return "updated activity";
  }
}

function toFeedItems(
  rows: ActivityEventRow[],
  actorNameById: Map<string, string>,
  clubNameById: Map<string, string>,
): ActivityFeedItem[] {
  return rows.map((row) => ({
    id: row.id,
    type: row.type as ActivityEventType,
    actorName: actorNameById.get(row.actor_id) ?? "Someone",
    actionLabel: actionLabel(row.type as ActivityEventType),
    targetLabel: row.target_label,
    timestamp: row.created_at,
    href: row.href,
    clubId: row.club_id,
    clubName: clubNameById.get(row.club_id) ?? null,
    metadata: row.metadata ?? {},
  }));
}

async function resolveContext(rows: ActivityEventRow[]) {
  const supabase = await createClient();
  const actorIds = [...new Set(rows.map((r) => r.actor_id))];
  const clubIds = [...new Set(rows.map((r) => r.club_id))];
  const [profilesRes, clubsRes] = await Promise.all([
    actorIds.length > 0
      ? supabase.from("profiles").select("id, full_name, email").in("id", actorIds)
      : Promise.resolve({ data: [] as { id: string; full_name: string | null; email: string | null }[] }),
    clubIds.length > 0
      ? supabase.from("clubs").select("id, name").in("id", clubIds)
      : Promise.resolve({ data: [] as { id: string; name: string }[] }),
  ]);

  const actorNameById = new Map<string, string>();
  for (const p of profilesRes.data ?? []) {
    actorNameById.set(p.id, p.full_name?.trim() || p.email || "Someone");
  }

  const clubNameById = new Map<string, string>();
  for (const c of clubsRes.data ?? []) {
    clubNameById.set(c.id, c.name);
  }

  return { actorNameById, clubNameById };
}

export async function getClubActivityFeed(clubId: string, limit = 10): Promise<ActivityFeedItem[]> {
  const supabase = await createClient();
  const { data: rows } = await supabase
    .from("activity_events")
    .select("id, type, actor_id, club_id, target_label, href, metadata, created_at")
    .eq("club_id", clubId)
    .order("created_at", { ascending: false })
    .limit(limit);

  const activityRows = (rows ?? []) as ActivityEventRow[];
  const { actorNameById, clubNameById } = await resolveContext(activityRows);
  return toFeedItems(activityRows, actorNameById, clubNameById);
}

export async function getGlobalActivityFeed(limit = 18): Promise<ActivityFeedItem[]> {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return [];

  const { data: membershipRows } = await supabase
    .from("club_members")
    .select("club_id")
    .eq("user_id", user.id)
    .eq("membership_status", "active");
  const clubIds = [...new Set((membershipRows ?? []).map((r) => r.club_id))];
  if (clubIds.length === 0) return [];

  const { data: rows } = await supabase
    .from("activity_events")
    .select("id, type, actor_id, club_id, target_label, href, metadata, created_at")
    .in("club_id", clubIds)
    .order("created_at", { ascending: false })
    .limit(limit);

  const activityRows = (rows ?? []) as ActivityEventRow[];
  const { actorNameById, clubNameById } = await resolveContext(activityRows);
  return toFeedItems(activityRows, actorNameById, clubNameById);
}
