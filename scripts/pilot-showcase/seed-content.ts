import type { SupabaseClient } from "@supabase/supabase-js";
import type { RosterSlug } from "./roster";

type EventType = "Meeting" | "Workshop" | "Social" | "Competition" | "Fundraiser" | "Service" | "Other";

function daysFromNow(days: number): string {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() + days);
  d.setUTCHours(14 + (Math.abs(days) % 4), 0, 0, 0);
  return d.toISOString();
}

function daysAgoCreated(days: number): string {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() - days);
  d.setUTCHours(11, 15, 0, 0);
  return d.toISOString();
}

function uid(m: Map<RosterSlug, string>, slug: RosterSlug): string {
  const id = m.get(slug);
  if (!id) throw new Error(`Missing user ${slug}`);
  return id;
}

export async function seedClubContent(args: {
  admin: SupabaseClient;
  clubId: string;
  presidentId: string;
  memberUserIds: string[];
  officerUserIds: string[];
  userMap: Map<RosterSlug, string>;
  announcements: Array<{ title: string; content: string; daysAgo: number; by: RosterSlug }>;
  events: Array<{
    title: string;
    description: string;
    location: string;
    event_type: EventType;
    days: number;
    skipAttendance?: boolean;
    addReflection?: boolean;
  }>;
  tasks: Array<{
    title: string;
    description: string;
    status: "todo" | "in_progress" | "blocked" | "completed";
    priority: "low" | "medium" | "high" | "urgent";
    dueDays: number | null;
    creator: RosterSlug;
    assignees: RosterSlug[];
  }>;
  auditSamples: Array<{
    action: string;
    target?: RosterSlug;
    daysAgo: number;
    metadata?: Record<string, unknown>;
  }>;
}): Promise<void> {
  const {
    admin,
    clubId,
    presidentId,
    memberUserIds,
    officerUserIds,
    userMap,
    announcements,
    events: eventSpecs,
    tasks: taskSpecs,
    auditSamples,
  } = args;

  const { error: annErr } = await admin.from("announcements").insert(
    announcements.map((a) => ({
      club_id: clubId,
      title: a.title,
      content: a.content,
      created_by: uid(userMap, a.by),
      created_at: daysAgoCreated(a.daysAgo),
    })),
  );
  if (annErr) throw annErr;

  const { data: insertedEvents, error: evErr } = await admin
    .from("events")
    .insert(
      eventSpecs.map((e) => ({
        club_id: clubId,
        title: e.title,
        description: e.description,
        location: e.location,
        event_date: daysFromNow(e.days),
        event_type: e.event_type,
        created_by: presidentId,
      })),
    )
    .select("id");
  if (evErr) throw evErr;
  if (!insertedEvents?.length || insertedEvents.length !== eventSpecs.length) {
    throw new Error("events insert returned unexpected row count");
  }

  const eventRows = eventSpecs.map((e, i) => ({
    id: insertedEvents[i].id as string,
    days: e.days,
    skipAttendance: e.skipAttendance,
    addReflection: e.addReflection !== false && e.days < -10,
  }));

  const statuses = ["yes", "maybe", "no"] as const;
  const rsvpRows: { event_id: string; user_id: string; status: string }[] = [];
  for (const ev of eventRows) {
    for (let i = 0; i < memberUserIds.length; i++) {
      const uidMember = memberUserIds[i];
      const status =
        statuses[i % 3] === "no" && i % 8 === 0 ? "no" : i % 5 === 0 ? "maybe" : "yes";
      rsvpRows.push({ event_id: ev.id, user_id: uidMember, status });
    }
  }
  if (rsvpRows.length) {
    const { error: rsvpErr } = await admin.from("rsvps").insert(rsvpRows);
    if (rsvpErr && rsvpErr.code !== "23505") throw rsvpErr;
  }

  const marker = officerUserIds[0] ?? presidentId;
  const attendanceRows: {
    event_id: string;
    user_id: string;
    marked_by: string;
    marked_at: string;
  }[] = [];
  for (const ev of eventRows) {
    if (ev.days >= 0 || ev.skipAttendance) continue;
    const presentPool = memberUserIds.filter((_, i) => i % 4 !== 0).slice(0, Math.min(10, memberUserIds.length));
    for (const uidMember of presentPool) {
      attendanceRows.push({
        event_id: ev.id,
        user_id: uidMember,
        marked_by: marker,
        marked_at: daysFromNow(ev.days + 1),
      });
    }
  }
  if (attendanceRows.length) {
    const { error: attErr } = await admin.from("event_attendance").insert(attendanceRows);
    if (attErr && attErr.code !== "23505") throw attErr;
  }

  const reflectionRows = eventRows
    .filter((ev) => ev.days < 0 && ev.addReflection)
    .map((ev) => ({
      event_id: ev.id,
      what_worked: "Clear communication the day before and a simple check-in table.",
      what_didnt: "Sign-in sheet ran out — bring two copies next time.",
      notes: "Upload receipts to the shared folder within a week.",
      created_by: presidentId,
      updated_by: presidentId,
    }));
  if (reflectionRows.length) {
    const { error: refErr } = await admin.from("event_reflections").insert(reflectionRows);
    if (refErr && refErr.code !== "23505") throw refErr;
  }

  for (const t of taskSpecs) {
    const creatorId = uid(userMap, t.creator);
    const body: Record<string, unknown> = {
      club_id: clubId,
      title: t.title,
      description: t.description,
      status: t.status,
      priority: t.priority,
      created_by: creatorId,
    };
    if (t.dueDays !== null) {
      body.due_at = daysFromNow(t.dueDays);
    }
    if (t.status === "completed") {
      body.completed_at = daysAgoCreated(3);
    }

    const { data: taskRow, error: te } = await admin.from("club_tasks").insert(body).select("id").single();
    if (te) throw te;

    const seen = new Set<RosterSlug>();
    for (const slug of t.assignees) {
      if (seen.has(slug)) continue;
      seen.add(slug);
      const { error: ae } = await admin.from("club_task_assignees").insert({
        task_id: taskRow.id as string,
        user_id: uid(userMap, slug),
      });
      if (ae && ae.code !== "23505") throw ae;
    }
  }

  const notifRows: Array<{
    user_id: string;
    club_id: string;
    type: string;
    title: string;
    body: string;
    href: string | null;
    is_read: boolean;
  }> = [];

  for (const uidMember of memberUserIds.slice(0, 6)) {
    notifRows.push({
      user_id: uidMember,
      club_id: clubId,
      type: "announcement_created",
      title: "New announcement",
      body: "Something new was posted in your club — open the app to read it.",
      href: `/clubs/${clubId}/announcements`,
      is_read: false,
    });
  }

  if (taskSpecs[0]) {
    const firstAssignee = taskSpecs[0].assignees[0];
    if (firstAssignee) {
      notifRows.push({
        user_id: uid(userMap, firstAssignee),
        club_id: clubId,
        type: "task_assigned",
        title: "Task assigned",
        body: `${taskSpecs[0].title} — check Tasks.`,
        href: `/clubs/${clubId}/tasks`,
        is_read: false,
      });
    }
  }

  if (notifRows.length) {
    const { error: ne } = await admin.from("notifications").insert(notifRows);
    if (ne) throw ne;
  }

  const { data: officerRoleRow } = await admin
    .from("club_roles")
    .select("id")
    .eq("club_id", clubId)
    .eq("name", "Officer")
    .maybeSingle();

  for (const sample of auditSamples) {
    const targetUser = sample.target ? uid(userMap, sample.target) : null;
    const roleId =
      sample.action === "role.assigned" ? ((officerRoleRow?.id as string | undefined) ?? null) : null;
    const { error: audErr } = await admin.from("club_audit_logs").insert({
      club_id: clubId,
      actor_id: presidentId,
      action: sample.action,
      target_user_id: targetUser,
      target_role_id: roleId,
      metadata: sample.metadata ?? {},
      created_at: daysAgoCreated(sample.daysAgo),
    });
    if (audErr) throw audErr;
  }
}

/** Muslim Student Association */
export const MSA_ANNOUNCEMENTS = [
  {
    title: "Room change for this week’s halaqa",
    content:
      "We’re in portable 12 instead of 204 — activities office double-booked us. Same time, bring a friend if you want.",
    daysAgo: 1,
    by: "pilot" as const,
  },
  {
    title: "Community iftar — volunteer sign-up",
    content:
      "We need setup, serving, and cleanup shifts. Sign the sheet in the chat; dress code is modest / school-appropriate.",
    daysAgo: 5,
    by: "marcus" as const,
  },
  {
    title: "Interfaith panel — question submissions",
    content:
      "Send anonymous questions for the chaplain + student panel by Wednesday. Nothing disrespectful — we’ll moderate.",
    daysAgo: 11,
    by: "pilot" as const,
  },
];

export const MSA_EVENTS = [
  {
    title: "Weekly halaqa & discussion",
    description: "Short reminder on adab, open Q&A, snacks after.",
    location: "Room 204 (check announcements if we move)",
    event_type: "Meeting" as const,
    days: 4,
  },
  {
    title: "Campus-wide service: meal packing",
    description: "Partnering with a local charity; hairnets and gloves provided.",
    location: "Cafeteria stage area",
    event_type: "Service" as const,
    days: 12,
  },
  {
    title: "Open house for new members",
    description: "Tour of prayer space options, club calendar, how to join GroupMe.",
    location: "Student union room B",
    event_type: "Social" as const,
    days: -5,
    addReflection: true,
  },
  {
    title: "Guest speaker: Muslim contributions in STEM",
    description: "Q&A after; slides will be posted for anyone who can’t attend.",
    location: "Auditorium",
    event_type: "Workshop" as const,
    days: -19,
    addReflection: true,
  },
  {
    title: "Ally training: respectful questions & support",
    description: "Faculty sponsor present; ground rules at the door.",
    location: "Library conference room",
    event_type: "Workshop" as const,
    days: -33,
    skipAttendance: true,
  },
];

export const MSA_TASKS = [
  {
    title: "Order paper goods and dates for iftar night",
    description: "Use the approved vendor list; treasurer needs receipts by Friday.",
    status: "in_progress" as const,
    priority: "high" as const,
    dueDays: 4,
    creator: "pilot" as const,
    assignees: ["marcus"] as RosterSlug[],
  },
  {
    title: "Design quarter-page ad for yearbook club spread",
    description: "Logo + meeting time + QR to interest form.",
    status: "todo" as const,
    priority: "medium" as const,
    dueDays: 2,
    creator: "marcus" as const,
    assignees: ["pilot", "james"] as RosterSlug[],
  },
  {
    title: "Reserve cafeteria tables for fundraiser",
    description: "Blocked on facilities email — follow up Monday morning.",
    status: "blocked" as const,
    priority: "urgent" as const,
    dueDays: -2,
    creator: "pilot" as const,
    assignees: ["elena"] as RosterSlug[],
  },
  {
    title: "Submit club roster to student activities",
    description: "Officer signatures + updated member list PDF.",
    status: "completed" as const,
    priority: "low" as const,
    dueDays: -14,
    creator: "pilot" as const,
    assignees: ["priya"] as RosterSlug[],
  },
];

/** DECA — business & competition club (president = pilot2) */
export const DECA_ANNOUNCEMENTS = [
  {
    title: "District competition registration closes Friday",
    content:
      "Advisor needs your event code + payment confirmation screenshot. No exceptions — state won’t let us add names late.",
    daysAgo: 2,
    by: "pilot2" as const,
  },
  {
    title: "Dress code for role-play rooms",
    content:
      "Business professional from the waist up minimum; full suit if you have it. No sneakers in judging rooms.",
    daysAgo: 6,
    by: "pilot" as const,
  },
  {
    title: "New practice case drops Thursday night",
    content:
      "PDF in the shared drive under /district-prep. Come with a one-page outline — we’ll pair you for mock judges.",
    daysAgo: 13,
    by: "pilot2" as const,
  },
];

export const DECA_EVENTS = [
  {
    title: "Chapter meeting: event picks + travel forms",
    description: "Bring your top two event choices; we’ll balance the roster.",
    location: "Business lab, room 118",
    event_type: "Meeting" as const,
    days: 5,
  },
  {
    title: "Mock role-play with alumni judges",
    description: "Two rounds + feedback sheets; arrive 15 min early in dress code.",
    location: "Main office conference suite",
    event_type: "Competition" as const,
    days: 10,
  },
  {
    title: "Fundraiser: bake sale at varsity game",
    description: "Shift signup in Tasks; money goes toward conference bus.",
    location: "Gym concession hallway",
    event_type: "Fundraiser" as const,
    days: -4,
    addReflection: true,
  },
  {
    title: "Written exam prep session — marketing cluster",
    description: "Practice test + answer review; bring laptop if you have one.",
    location: "Media center lab",
    event_type: "Workshop" as const,
    days: -16,
    addReflection: true,
  },
  {
    title: "Networking social with local small-business owners",
    description: "Elevator pitches optional; name tags at the door.",
    location: "Cafeteria A-wing",
    event_type: "Social" as const,
    days: -29,
  },
];

export const DECA_TASKS = [
  {
    title: "File chapter officer roster with DECA Inc.",
    description: "Use the template from the advisor folder; president + VP sign.",
    status: "todo" as const,
    priority: "high" as const,
    dueDays: 3,
    creator: "pilot2" as const,
    assignees: ["pilot"] as RosterSlug[],
  },
  {
    title: "Build slide deck for school assembly pitch",
    description: "90 seconds: who we are, how to join, competition photos.",
    status: "in_progress" as const,
    priority: "medium" as const,
    dueDays: 7,
    creator: "pilot" as const,
    assignees: ["priya"] as RosterSlug[],
  },
  {
    title: "Collect permission slips for Saturday bus",
    description: "Paper copies only — activities office checklist in drive.",
    status: "todo" as const,
    priority: "low" as const,
    dueDays: 6,
    creator: "marcus" as const,
    assignees: ["marcus"] as RosterSlug[],
  },
  {
    title: "Print name tents for mock judges",
    description: "Mail merge file is ready; use card stock in the copy room.",
    status: "completed" as const,
    priority: "medium" as const,
    dueDays: -9,
    creator: "pilot2" as const,
    assignees: ["pilot"] as RosterSlug[],
  },
];

/** Photography Club (president = marcus; pilot + pilot2 are officers) */
export const PHOTO_ANNOUNCEMENTS = [
  {
    title: "Darkroom hours this week",
    content:
      "Mon/Wed 3:15–5pm with a certified officer present. No film unless you’ve done the safety briefing.",
    daysAgo: 3,
    by: "marcus" as const,
  },
  {
    title: "SD cards from field trip — return by Friday",
    content:
      "Label your name on the case. We’re missing two 64GB cards from the downtown walk.",
    daysAgo: 8,
    by: "sophie" as const,
  },
  {
    title: "Spring gallery save-the-date",
    content:
      "Each member can submit up to three prints; matting supplies in the cabinet. Theme is “our town.”",
    daysAgo: 12,
    by: "marcus" as const,
  },
];

export const PHOTO_EVENTS = [
  {
    title: "Studio lighting crash course",
    description: "Softbox + reflector demos; bring a notebook, not your camera first round.",
    location: "Art wing studio 3",
    event_type: "Workshop" as const,
    days: 6,
  },
  {
    title: "Golden-hour photo walk — old town",
    description: "Buddy system after sunset; signed waiver on file required.",
    location: "Meet at main office steps",
    event_type: "Social" as const,
    days: 11,
  },
  {
    title: "Yearbook headshot make-up day",
    description: "Five-minute slots; plain backdrop; dress code per yearbook rules.",
    location: "Room 212",
    event_type: "Service" as const,
    days: -6,
    addReflection: true,
  },
  {
    title: "Critique circle: composition & editing",
    description: "Bring 3 images on a thumb drive; constructive feedback only.",
    location: "Media lab",
    event_type: "Meeting" as const,
    days: -18,
    addReflection: true,
  },
  {
    title: "Regional high-school photo contest drop-off",
    description: "Mounted prints only; rules PDF in drive; officers stamp receipt.",
    location: "Art office counter",
    event_type: "Competition" as const,
    days: -27,
  },
];

export const PHOTO_TASKS = [
  {
    title: "Inventory camera bodies after checkout weekend",
    description: "Serial numbers in spreadsheet; flag anything with a loose battery door.",
    status: "in_progress" as const,
    priority: "high" as const,
    dueDays: 5,
    creator: "marcus" as const,
    assignees: ["sophie"] as RosterSlug[],
  },
  {
    title: "Order replacement lens caps (52mm + 58mm)",
    description: "Use school PO; advisor approval already attached.",
    status: "todo" as const,
    priority: "urgent" as const,
    dueDays: 1,
    creator: "sophie" as const,
    assignees: ["tessa"] as RosterSlug[],
  },
  {
    title: "Wipe tripods and light stands with disinfectant",
    description: "After Saturday walk; checklist on the supply cart.",
    status: "todo" as const,
    priority: "medium" as const,
    dueDays: 12,
    creator: "marcus" as const,
    assignees: ["diego", "pilot", "pilot2"] as RosterSlug[],
  },
  {
    title: "Survey: best night for editing workshop",
    description: "Google Form link in chat; close Sunday night.",
    status: "completed" as const,
    priority: "low" as const,
    dueDays: -11,
    creator: "sophie" as const,
    assignees: ["marcus"] as RosterSlug[],
  },
];
