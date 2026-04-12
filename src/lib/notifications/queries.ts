import "server-only";
import { createClient } from "@/lib/supabase/server";

// ─── Resolved notification shape (used by UI) ─────────────────────────────────

export type NotificationItem = {
  id: string;
  type: string;
  title: string;
  body: string;
  href: string | null;
  isRead: boolean;
  createdAt: string;
  clubId: string | null;
  /** Resolved when club_id is set (extra query, batched). */
  clubName: string | null;
};

// ─── Queries ──────────────────────────────────────────────────────────────────

/**
 * Returns the most recent notifications for the authenticated user.
 * Used by the notification bell dropdown (limit 10) and the full page (limit 50).
 */
export async function getRecentNotifications(limit = 10): Promise<NotificationItem[]> {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) return [];

  const { data } = await supabase
    .from("notifications")
    .select("id, type, title, body, href, is_read, created_at, club_id")
    .eq("user_id", user.id)
    .order("created_at", { ascending: false })
    .limit(limit);

  const rows = data ?? [];
  const clubIds = [...new Set(rows.map((r) => r.club_id).filter((id): id is string => Boolean(id)))];
  const clubNameById = new Map<string, string>();

  if (clubIds.length > 0) {
    const { data: clubRows } = await supabase.from("clubs").select("id, name").in("id", clubIds);
    for (const c of clubRows ?? []) {
      clubNameById.set(c.id, c.name);
    }
  }

  return rows.map((n) => ({
    id: n.id,
    type: n.type as string,
    title: n.title,
    body: n.body,
    href: n.href,
    isRead: n.is_read,
    createdAt: n.created_at,
    clubId: n.club_id,
    clubName: n.club_id ? clubNameById.get(n.club_id) ?? null : null,
  }));
}

/**
 * Returns the count of unread notifications for the authenticated user.
 * Uses the partial index on (user_id, is_read) where is_read = false.
 */
export async function getUnreadNotificationCount(): Promise<number> {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) return 0;

  const { count } = await supabase
    .from("notifications")
    .select("id", { count: "exact", head: true })
    .eq("user_id", user.id)
    .eq("is_read", false);

  return count ?? 0;
}
