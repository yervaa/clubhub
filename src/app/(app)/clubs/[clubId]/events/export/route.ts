import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

function escapeIcs(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/;/g, "\\;").replace(/,/g, "\\,").replace(/\n/g, "\\n");
}

function toIcsDate(date: Date): string {
  return date.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
}

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ clubId: string }> },
) {
  const { clubId } = await params;

  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // Verify membership.
  const { data: membership } = await supabase
    .from("club_members")
    .select("user_id")
    .eq("club_id", clubId)
    .eq("user_id", user.id)
    .maybeSingle();

  if (!membership) {
    return NextResponse.json({ error: "Not a member" }, { status: 403 });
  }

  // Fetch club name + events.
  const [clubRes, eventsRes] = await Promise.all([
    supabase.from("clubs").select("name").eq("id", clubId).maybeSingle(),
    supabase
      .from("events")
      .select("id, title, description, location, event_date")
      .eq("club_id", clubId)
      .order("event_date", { ascending: true }),
  ]);

  const clubName = clubRes.data?.name ?? "Club";
  const events = eventsRes.data ?? [];

  const lines: string[] = [
    "BEGIN:VCALENDAR",
    "VERSION:2.0",
    `PRODID:-//ClubHub//${escapeIcs(clubName)}//EN`,
    `X-WR-CALNAME:${escapeIcs(clubName)} Events`,
    "CALSCALE:GREGORIAN",
  ];

  for (const ev of events) {
    const start = new Date(ev.event_date);
    const end = new Date(start.getTime() + 60 * 60 * 1000); // 1-hour default
    lines.push(
      "BEGIN:VEVENT",
      `UID:${ev.id}@clubhub`,
      `DTSTART:${toIcsDate(start)}`,
      `DTEND:${toIcsDate(end)}`,
      `SUMMARY:${escapeIcs(ev.title)}`,
      `DESCRIPTION:${escapeIcs(ev.description ?? "")}`,
      `LOCATION:${escapeIcs(ev.location ?? "")}`,
      "END:VEVENT",
    );
  }

  lines.push("END:VCALENDAR");

  const icsContent = lines.join("\r\n");
  const filename = `${clubName.replace(/[^a-zA-Z0-9]/g, "_")}_events.ics`;

  return new NextResponse(icsContent, {
    headers: {
      "Content-Type": "text/calendar; charset=utf-8",
      "Content-Disposition": `attachment; filename="${filename}"`,
    },
  });
}
