import type { SupabaseClient } from "@supabase/supabase-js";
import { CLUB_PLANS } from "./clubs-plan";
import { DEMO_USER_PASSWORD } from "./constants";
import { DEMO_USERS, demoEmail } from "./demo-users";
import { createCustomRole, loadPermissionMap, seedSystemRolesForClub } from "./rbac";

type UserIds = Map<string, string>;

type DemoSeedEventType =
  | "Meeting"
  | "Workshop"
  | "Social"
  | "Competition"
  | "Fundraiser"
  | "Service"
  | "Other";

function daysFromNow(days: number): string {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() + days);
  d.setUTCHours(15 + (Math.abs(days) % 5), 30, 0, 0);
  return d.toISOString();
}

function daysAgoCreated(days: number): string {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() - days);
  d.setUTCHours(10, 0, 0, 0);
  return d.toISOString();
}

export async function createDemoAuthUsers(admin: SupabaseClient): Promise<UserIds> {
  const map: UserIds = new Map();

  for (const u of DEMO_USERS) {
    const email = demoEmail(u.slug);
    const { data, error } = await admin.auth.admin.createUser({
      email,
      password: DEMO_USER_PASSWORD,
      email_confirm: true,
      user_metadata: { full_name: u.fullName },
    });
    if (error) {
      if (error.message.includes("already been registered")) {
        const { data: list } = await admin.auth.admin.listUsers({ page: 1, perPage: 200 });
        const found = list?.users.find((x) => x.email === email);
        if (found) {
          map.set(u.slug, found.id);
          await admin.from("profiles").upsert(
            { id: found.id, full_name: u.fullName, email },
            { onConflict: "id" },
          );
          continue;
        }
      }
      throw error;
    }
    if (!data.user) throw new Error(`No user returned for ${email}`);
    map.set(u.slug, data.user.id);
    await admin.from("profiles").upsert(
      { id: data.user.id, full_name: u.fullName, email },
      { onConflict: "id" },
    );
  }

  return map;
}

function uid(map: UserIds, slug: string): string {
  const id = map.get(slug);
  if (!id) throw new Error(`Missing user ${slug}`);
  return id;
}

function idx(map: UserIds, i: number): string {
  const slug = DEMO_USERS[i]?.slug;
  if (!slug) throw new Error(`Bad user index ${i}`);
  return uid(map, slug);
}

export async function seedDemoDataset(admin: SupabaseClient, userIds: UserIds): Promise<void> {
  const permByKey = await loadPermissionMap(admin);
  const permMapForCustom = new Map(permByKey);

  for (const plan of CLUB_PLANS) {
    const presidentId = idx(userIds, plan.presidentIndex);

    const { data: clubRow, error: cErr } = await admin
      .from("clubs")
      .insert({
        name: plan.name,
        description: plan.description,
        join_code: plan.joinCode,
        created_by: presidentId,
      })
      .select("id")
      .single();
    if (cErr) throw cErr;
    const clubId = clubRow.id as string;

    await seedSystemRolesForClub(admin, clubId, presidentId);

    const allMemberIndices = new Set([
      plan.presidentIndex,
      ...plan.officerIndices,
      ...plan.memberIndices,
    ]);

    for (const i of allMemberIndices) {
      if (i === plan.presidentIndex) continue;
      const legacyRole = plan.officerIndices.includes(i) ? "officer" : "member";
      const { error: mErr } = await admin.from("club_members").insert({
        club_id: clubId,
        user_id: idx(userIds, i),
        role: legacyRole,
      });
      if (mErr) throw mErr;
    }

    if (plan.customRoles?.length) {
      for (const cr of plan.customRoles) {
        const roleId = await createCustomRole(
          admin,
          clubId,
          cr.name,
          cr.description,
          cr.permissionKeys,
          permMapForCustom,
        );
        const { error: assignErr } = await admin.from("member_roles").insert({
          user_id: idx(userIds, cr.userIndex),
          club_id: clubId,
          role_id: roleId,
        });
        if (assignErr) throw assignErr;
      }
    }

    await seedClubContent(admin, clubId, plan, userIds, presidentId);
    console.log(`  ✓ ${plan.name}`);
  }
}

async function seedClubContent(
  admin: SupabaseClient,
  clubId: string,
  plan: (typeof CLUB_PLANS)[number],
  userIds: UserIds,
  presidentId: string,
): Promise<void> {
  const memberUserIds = [
    plan.presidentIndex,
    ...plan.officerIndices,
    ...plan.memberIndices,
  ].map((i) => idx(userIds, i));

  const officerUserIds = [plan.presidentIndex, ...plan.officerIndices].map((i) => idx(userIds, i));

  const shortName = plan.name.replace(/^Demo\s+/i, "");
  const announcements = [
    {
      title: `${shortName}: room change this week`,
      content:
        "We’re moving this week’s meeting — check the header on the Events page for the updated room. Bring whatever you usually bring.",
      daysAgo: 2,
    },
    {
      title: "Volunteer slots for open house",
      content:
        "We need four people Saturday 10–2 for demos and signup sheets. Grab a slot in Tasks or reply in the next meeting.",
      daysAgo: 6,
    },
    {
      title: "Officer applications — one week left",
      content:
        "Short Google Form is pinned; interviews next Monday. Questions? DM any current officer.",
      daysAgo: 14,
    },
    {
      title: "Permission slips & travel",
      content:
        "Turn forms in to the activities office by Friday. No slip = no bus seat for away events.",
      daysAgo: 28,
    },
  ];

  const { error: annErr } = await admin.from("announcements").insert(
    announcements.map((a) => ({
      club_id: clubId,
      title: a.title,
      content: a.content,
      created_by: presidentId,
      created_at: daysAgoCreated(a.daysAgo),
    })),
  );
  if (annErr) throw annErr;

  const eventSpecs: Array<{
    title: string;
    blurb: string;
    loc: string;
    type: DemoSeedEventType;
    days: number;
    skipAttendance?: boolean;
    addReflection?: boolean;
  }> = [
    {
      title: "Officer planning session",
      blurb: "Agenda: budget, calendar, and committee check-ins.",
      loc: "Student activities office",
      type: "Meeting",
      days: 4,
    },
    {
      title: "Guest speaker: college pathways",
      blurb: "Alumni panel + Q&A; snacks provided.",
      loc: "Auditorium B",
      type: "Workshop",
      days: 11,
    },
    {
      title: "Weekend service project",
      blurb: "Park cleanup — wear closed-toe shoes.",
      loc: "Riverside Park east lot",
      type: "Service",
      days: 18,
    },
    {
      title: "Regional qualifier setup",
      blurb: "Field build, pit layout, volunteer briefing.",
      loc: "Gymnasium main floor",
      type: "Competition",
      days: -3,
      addReflection: false,
    },
    {
      title: "Post-event debrief & pizza",
      blurb: "Quick retro on what worked; sign up for next shifts.",
      loc: "Room 104",
      type: "Social",
      days: -6,
      skipAttendance: plan.joinCode === "DMOSTU",
      addReflection: false,
    },
    {
      title: "Fundraiser tally night",
      blurb: "Count sales, deposit prep, thank-you posts.",
      loc: "Library conference room",
      type: "Fundraiser",
      days: -12,
      addReflection: true,
    },
    {
      title: "Mid-semester general meeting",
      blurb: "Constitution reminders + open floor.",
      loc: "Lecture hall 2",
      type: "Meeting",
      days: -22,
      addReflection: true,
    },
    {
      title: "Skills workshop night",
      blurb: "Rotations: public speaking / design / logistics.",
      loc: "CTE wing lab",
      type: "Workshop",
      days: -38,
      addReflection: true,
    },
    {
      title: "Welcome back social",
      blurb: "Icebreakers and committee signup boards.",
      loc: "Courtyard tent",
      type: "Social",
      days: -55,
      addReflection: true,
    },
    {
      title: "Joint club mixer",
      blurb: "Hosted with two other schools — name tags at door.",
      loc: "Union ballroom",
      type: "Other",
      days: -72,
      addReflection: true,
    },
  ];

  const { data: insertedEvents, error: evErr } = await admin
    .from("events")
    .insert(
      eventSpecs.map((e) => ({
        club_id: clubId,
        title: e.title,
        description: e.blurb,
        location: e.loc,
        event_date: daysFromNow(e.days),
        event_type: e.type,
        created_by: presidentId,
      })),
    )
    .select("id");
  if (evErr) throw evErr;
  if (!insertedEvents?.length || insertedEvents.length !== eventSpecs.length) {
    throw new Error("events insert returned unexpected row count");
  }

  const eventRows: { id: string; days: number; skipAttendance?: boolean; addReflection?: boolean }[] =
    eventSpecs.map((e, i) => ({
      id: insertedEvents[i].id as string,
      days: e.days,
      skipAttendance: e.skipAttendance,
      addReflection: e.addReflection !== false && e.days < -20,
    }));

  const statuses = ["yes", "maybe", "no"] as const;
  const rsvpRows: { event_id: string; user_id: string; status: string }[] = [];
  for (const ev of eventRows) {
    for (let i = 0; i < memberUserIds.length; i++) {
      const uidMember = memberUserIds[i];
      const status = statuses[i % 3] === "no" && i % 7 === 0 ? "no" : i % 4 === 0 ? "maybe" : "yes";
      rsvpRows.push({ event_id: ev.id, user_id: uidMember, status });
    }
  }
  const { error: rsvpErr } = await admin.from("rsvps").insert(rsvpRows);
  if (rsvpErr && rsvpErr.code !== "23505") throw rsvpErr;

  const marker = officerUserIds[0] ?? presidentId;
  const attendanceRows: {
    event_id: string;
    user_id: string;
    marked_by: string;
    marked_at: string;
  }[] = [];
  for (const ev of eventRows) {
    if (ev.days >= 0 || ev.skipAttendance) continue;
    const presentPool = memberUserIds.filter((_, i) => i % 5 !== 0).slice(0, Math.min(12, memberUserIds.length));
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
      what_worked: "Strong turnout and clear roles at check-in. Members stuck to the timeline.",
      what_didnt: "AV took longer than expected — book setup an extra 20 minutes next time.",
      notes: "Follow up: share photos in the drive within 48h.",
      created_by: presidentId,
      updated_by: presidentId,
    }));
  if (reflectionRows.length) {
    const { error: refErr } = await admin.from("event_reflections").insert(reflectionRows);
    if (refErr && refErr.code !== "23505") throw refErr;
  }

  const taskSpecs: Array<{
    title: string;
    description: string;
    status: "todo" | "in_progress" | "blocked" | "completed";
    priority: "low" | "medium" | "high" | "urgent";
    dueDays: number | null;
    assigneeIndices: number[];
    creatorIndex: number;
  }> = [
    {
      title: "Finalize flyer for Instagram",
      description: "Use brand colors; export PNG + PDF for printing.",
      status: "in_progress",
      priority: "high",
      dueDays: 3,
      assigneeIndices: [2],
      creatorIndex: plan.presidentIndex,
    },
    {
      title: "Reserve classroom for next officer meeting",
      description: "Need projector + whiteboard; avoid Wednesdays.",
      status: "todo",
      priority: "medium",
      dueDays: 7,
      assigneeIndices: [plan.officerIndices[0] ?? plan.presidentIndex],
      creatorIndex: plan.presidentIndex,
    },
    {
      title: "Buy snacks for recruitment table",
      description: "Allergen-free option + receipts for treasurer.",
      status: "blocked",
      priority: "urgent",
      dueDays: -1,
      assigneeIndices: [plan.memberIndices[0] ?? plan.presidentIndex],
      creatorIndex: plan.officerIndices[0] ?? plan.presidentIndex,
    },
    {
      title: "Post recap photos to shared album",
      description: "Tag officers; no faces of visitors without release.",
      status: "completed",
      priority: "low",
      dueDays: -10,
      assigneeIndices: [plan.memberIndices[1] ?? plan.presidentIndex],
      creatorIndex: plan.presidentIndex,
    },
    {
      title: "Create signup form for volunteer shifts",
      description: "Google Form + auto email to officers.",
      status: "todo",
      priority: "high",
      dueDays: 5,
      assigneeIndices: [2, plan.officerIndices[1] ?? plan.presidentIndex],
      creatorIndex: plan.officerIndices[0] ?? plan.presidentIndex,
    },
  ];

  for (const t of taskSpecs) {
    const creatorId = idx(userIds, t.creatorIndex);
    const insertBody: Record<string, unknown> = {
      club_id: clubId,
      title: t.title,
      description: t.description,
      status: t.status,
      priority: t.priority,
      created_by: creatorId,
    };
    if (t.dueDays !== null) {
      insertBody.due_at = daysFromNow(t.dueDays);
    }
    if (t.status === "completed") {
      insertBody.completed_at = daysAgoCreated(4);
    }

    const { data: taskRow, error: te } = await admin.from("club_tasks").insert(insertBody).select("id").single();
    if (te) throw te;

    const seenAssignees = new Set<number>();
    for (const ai of t.assigneeIndices) {
      if (seenAssignees.has(ai)) continue;
      seenAssignees.add(ai);
      const { error: ae } = await admin.from("club_task_assignees").insert({
        task_id: taskRow.id as string,
        user_id: idx(userIds, ai),
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

  for (const uidMember of memberUserIds.slice(0, 8)) {
    notifRows.push({
      user_id: uidMember,
      club_id: clubId,
      type: "announcement_created",
      title: "New announcement",
      body: "Meeting room change this week is live — check the feed.",
      href: `/clubs/${clubId}/announcements`,
      is_read: false,
    });
  }

  notifRows.push({
    user_id: idx(userIds, 2),
    club_id: clubId,
    type: "task_assigned",
    title: "Task assigned to you",
    body: "Finalize flyer for Instagram — due soon.",
    href: `/clubs/${clubId}/tasks`,
    is_read: false,
  });

  const { error: ne } = await admin.from("notifications").insert(notifRows);
  if (ne) throw ne;

  const treasurerDef = plan.customRoles?.find((c) => c.name === "Treasurer");
  if (treasurerDef) {
    const { data: treasurerRole } = await admin
      .from("club_roles")
      .select("id")
      .eq("club_id", clubId)
      .eq("name", "Treasurer")
      .maybeSingle();

    if (treasurerRole?.id) {
      const { error: ae } = await admin.from("club_audit_logs").insert({
        club_id: clubId,
        actor_id: presidentId,
        action: "role.assigned",
        target_user_id: idx(userIds, treasurerDef.userIndex),
        target_role_id: treasurerRole.id as string,
        metadata: { role_name: "Treasurer" },
        created_at: daysAgoCreated(40),
      });
      if (ae) throw ae;
    }
  }

  const { data: officerRoleRow } = await admin
    .from("club_roles")
    .select("id")
    .eq("club_id", clubId)
    .eq("name", "Officer")
    .maybeSingle();

  if (officerRoleRow?.id && officerUserIds[1]) {
    const { error: aud2 } = await admin.from("club_audit_logs").insert({
      club_id: clubId,
      actor_id: presidentId,
      action: "role.assigned",
      target_user_id: officerUserIds[1],
      target_role_id: officerRoleRow.id as string,
      metadata: { role_name: "Officer" },
      created_at: daysAgoCreated(18),
    });
    if (aud2) throw aud2;
  }

  if (plan.joinCode === "DMOSTU" && plan.memberIndices[0] !== undefined) {
    const incomingPresident = idx(userIds, plan.memberIndices[0]);
    const { error: aud3 } = await admin.from("club_audit_logs").insert({
      club_id: clubId,
      actor_id: presidentId,
      action: "presidency.transferred",
      target_user_id: incomingPresident,
      target_role_id: null,
      metadata: { note: "Documented handoff after fall elections (demo timeline)." },
      created_at: daysAgoCreated(52),
    });
    if (aud3) throw aud3;
  }
}
