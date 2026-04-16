import "server-only";

import { cache } from "react";
import { createAdminClient } from "@/lib/supabase/admin";
import type { ClubStatus } from "@/lib/clubs/club-status";
import { normalizeEventType, type EventType } from "@/lib/events";

export type PublicClubUpcomingEvent = {
  id: string;
  title: string;
  location: string;
  eventDateIso: string;
  eventType: EventType;
};

export type PublicClubPagePayload = {
  clubId: string;
  name: string;
  description: string;
  joinCode: string;
  requireJoinApproval: boolean;
  status: ClubStatus;
  upcomingEvents: PublicClubUpcomingEvent[];
};

const JOIN_CODE_REGEX = /^[A-Z0-9]{8}$/;

/**
 * Public marketing snapshot for `/club/[joinCode]`.
 * Uses the service role only on the server — never exposed to the browser.
 * Returns null when the code is invalid or no club matches.
 */
export const getPublicClubPageByJoinCode = cache(async (rawJoinCode: string): Promise<PublicClubPagePayload | null> => {
  const joinCode = rawJoinCode.trim().toUpperCase();
  if (!JOIN_CODE_REGEX.test(joinCode)) {
    return null;
  }

  const admin = createAdminClient();
  const { data: club, error: clubError } = await admin
    .from("clubs")
    .select("id, name, description, join_code, status, require_join_approval")
    .eq("join_code", joinCode)
    .maybeSingle();

  if (clubError || !club?.id) {
    return null;
  }

  const status = (club.status as string) === "archived" ? "archived" : "active";
  const nowIso = new Date().toISOString();

  let upcomingEvents: PublicClubUpcomingEvent[] = [];
  if (status === "active") {
    const { data: rows, error: eventsError } = await admin
      .from("events")
      .select("id, title, location, event_date, event_type")
      .eq("club_id", club.id)
      .eq("approval_status", "approved")
      .gte("event_date", nowIso)
      .order("event_date", { ascending: true })
      .limit(8);

    if (!eventsError && rows) {
      upcomingEvents = (rows as { id: string; title: string; location: string; event_date: string; event_type: string }[]).map(
        (r) => ({
          id: r.id,
          title: r.title,
          location: r.location,
          eventDateIso: r.event_date,
          eventType: normalizeEventType(r.event_type),
        }),
      );
    }
  }

  return {
    clubId: club.id as string,
    name: String(club.name ?? "").trim() || "Club",
    description: typeof club.description === "string" ? club.description : "",
    joinCode: String(club.join_code ?? joinCode).toUpperCase(),
    requireJoinApproval: Boolean(club.require_join_approval),
    status,
    upcomingEvents,
  };
});
