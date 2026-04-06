import "server-only";
import { unstable_noStore as noStore } from "next/cache";
import { normalizeEventType, type EventType } from "@/lib/events";
import { createClient } from "@/lib/supabase/server";
import type { ClubStatus } from "@/lib/clubs/club-status";

export type UserClub = {
  id: string;
  name: string;
  description: string;
  joinCode: string;
  role: "member" | "officer";
};

export type ClubAnnouncement = {
  id: string;
  title: string;
  content: string;
  createdAt: string;
};

export type ClubEvent = {
  id: string;
  title: string;
  description: string;
  location: string;
  eventType: EventType;
  eventDate: string;
  eventDateRaw: Date;
  userRsvpStatus: "yes" | "no" | "maybe" | null;
  /** Whether the current user appears in attendance for this event (self only; safe for all members). */
  userMarkedPresent: boolean;
  attendanceCount: number;
  presentMemberIds: string[];
  rsvpCounts: {
    yes: number;
    no: number;
    maybe: number;
  };
  reflection: {
    whatWorked: string;
    whatDidnt: string;
    notes: string | null;
    updatedAt: string;
    /** Raw ISO-8601 string for sorting and relative-time formatting */
    updatedAtIso: string;
  } | null;
};

export type MembershipStatus = "active" | "alumni";

/** Club-defined member label (not an RBAC role). */
export type ClubMemberTag = {
  id: string;
  name: string;
};

/** Club committee (subgroup); distinct from tags. */
export type ClubCommitteeSummary = {
  id: string;
  name: string;
};

/** Club team; distinct from committees and tags. */
export type ClubTeamSummary = {
  id: string;
  name: string;
};

export type ClubMember = {
  userId: string;
  fullName: string | null;
  email: string | null;
  role: "member" | "officer";
  /** Club-specific lifecycle: alumni retain history but are not active operational members. */
  membershipStatus: MembershipStatus;
  /** ISO timestamp from `club_members.joined_at` when available. */
  joinedAt: string | null;
  /** Tags assigned to this member within the club. */
  tags: ClubMemberTag[];
  /** Committees this member belongs to (may be multiple). */
  committees: ClubCommitteeSummary[];
  /** Teams this member belongs to (may be multiple). */
  teams: ClubTeamSummary[];
  attendanceCount: number;
  totalTrackedEvents: number;
  attendanceRate: number;
};

export type ClubActivityItem = {
  id: string;
  kind: "member_joined" | "announcement_posted" | "event_created" | "rsvp_updated" | "attendance_marked";
  message: string;
  createdAt: string;
  /** Raw ISO-8601 string for sorting and relative-time formatting */
  createdAtIso: string;
};

export type ClubAttentionAlert = {
  id: string;
  type: "upcoming_event_low_rsvp" | "no_upcoming_events" | "no_recent_announcement" | "attendance_not_marked";
  title: string;
  description: string;
  ctaLabel: string;
  ctaTarget: string;
};

export type DashboardAttentionAlert = {
  id: string;
  clubId: string;
  clubName: string;
  type: ClubAttentionAlert["type"];
  title: string;
  description: string;
  ctaLabel: string;
  ctaHref: string;
  priority: number;
};

export type ClubDetail = {
  id: string;
  name: string;
  description: string;
  joinCode: string;
  /** When true, join code / invite link creates a pending request instead of immediate membership. */
  requireJoinApproval: boolean;
  /** active: normal; archived: read-only / historical */
  status: ClubStatus;
  currentUserId: string;
  currentUserRole: "member" | "officer";
  /** Count of active members (excludes alumni). Used for stats, RSVP denominators, and checklists. */
  memberCount: number;
  members: ClubMember[];
  totalTrackedEvents: number;
  clubAverageAttendance: number;
  topMembers: ClubMember[];
  attentionAlerts: ClubAttentionAlert[];
  recentActivity: ClubActivityItem[];
  announcements: ClubAnnouncement[];
  events: ClubEvent[];
  /** All tag definitions for this club (for pickers / management). */
  memberTagDefinitions: ClubMemberTag[];
  /** All committees defined for this club. */
  clubCommittees: ClubCommitteeSummary[];
  /** All teams defined for this club. */
  clubTeams: ClubTeamSummary[];
};

export type DashboardAnnouncement = {
  id: string;
  clubId: string;
  clubName: string;
  title: string;
  createdAt: string;
  createdAtRaw: string;
};

export type DashboardEvent = {
  id: string;
  clubId: string;
  clubName: string;
  title: string;
  location: string;
  eventType: EventType;
  eventDate: string;
  eventDateRaw: string;
};

export type DashboardTaskPreview = {
  id: string;
  clubId: string;
  clubName: string;
  title: string;
  dueAt: string | null;
  dueAtIso: string | null;
  priority: "low" | "medium" | "high" | "urgent";
  isOverdue: boolean;
};

export type DashboardData = {
  clubs: UserClub[];
  recentAnnouncements: DashboardAnnouncement[];
  upcomingEvents: DashboardEvent[];
  needsAttentionAlerts: DashboardAttentionAlert[];
  /** Open tasks assigned to the current user, across their clubs. */
  myOpenTasks: DashboardTaskPreview[];
  unreadNotificationCount: number;
};

type ClubMemberRow = {
  role: "member" | "officer";
  clubs:
    | {
        id: string;
        name: string;
        description: string;
        join_code: string;
        status?: string;
        require_join_approval?: boolean | null;
      }
    | {
        id: string;
        name: string;
        description: string;
        join_code: string;
        status?: string;
        require_join_approval?: boolean | null;
      }[]
    | null;
};

type ClubMemberViewRow = {
  user_id: string;
  full_name: string | null;
  email: string | null;
  role: "member" | "officer";
  membership_status: MembershipStatus;
};

type ClubMemberBaseRow = {
  user_id: string;
  role: "member" | "officer";
  membership_status: MembershipStatus;
  joined_at: string;
};

type ClubActivityRow = {
  id: string;
  kind: ClubActivityItem["kind"];
  message: string;
  created_at: string;
};

type AttentionAlertDraft = ClubAttentionAlert & {
  priority: number;
};

type AttentionAlertContext = {
  now: Date;
  sevenDaysAgo: Date;
  memberCount: number;
  nextUpcomingEvent:
    | {
        id: string;
        title: string;
        eventDate: string;
      }
    | null;
  nextEventResponseCount: number;
  latestAnnouncementCreatedAt: string | null;
  hasAnnouncement: boolean;
  mostRecentPastEvent:
    | {
        id: string;
        title: string;
      }
    | null;
  latestPastEventHasTrackedAttendance: boolean;
};

function normalizeClubRelation(
  relation:
    | {
        id: string;
        name: string;
        description: string;
        join_code: string;
        status?: string;
        require_join_approval?: boolean | null;
      }
    | {
        id: string;
        name: string;
        description: string;
        join_code: string;
        status?: string;
        require_join_approval?: boolean | null;
      }[]
    | null,
) {
  return Array.isArray(relation) ? relation[0] ?? null : relation;
}

function getSortableMemberName(member: { fullName: string | null; email: string | null }) {
  const fullName = member.fullName?.trim();

  if (fullName) {
    return fullName.toLowerCase();
  }

  if (member.email) {
    return member.email.toLowerCase();
  }

  return "member";
}

function buildAttentionAlertDrafts({
  now,
  sevenDaysAgo,
  memberCount,
  nextUpcomingEvent,
  nextEventResponseCount,
  latestAnnouncementCreatedAt,
  hasAnnouncement,
  mostRecentPastEvent,
  latestPastEventHasTrackedAttendance,
}: AttentionAlertContext): AttentionAlertDraft[] {
  const drafts: AttentionAlertDraft[] = [];

  if (nextUpcomingEvent && memberCount > 0) {
    const hoursUntilNextEvent = (new Date(nextUpcomingEvent.eventDate).getTime() - now.getTime()) / (1000 * 60 * 60);
    const nextEventResponseRate = Math.round((nextEventResponseCount / memberCount) * 100);

    if (hoursUntilNextEvent <= 48 && nextEventResponseRate < 50) {
      drafts.push({
        id: `upcoming-low-rsvp-${nextUpcomingEvent.id}`,
        type: "upcoming_event_low_rsvp",
        title: "Upcoming event needs more responses",
        description: `${nextUpcomingEvent.title} is within 48 hours, but only ${nextEventResponseRate}% of members have RSVP'd so far.`,
        ctaLabel: "Review events",
        ctaTarget: "/events",
        priority: 100,
      });
    }
  }

  if (!nextUpcomingEvent) {
    drafts.push({
      id: "no-upcoming-events",
      type: "no_upcoming_events",
      title: "No upcoming events scheduled",
      description: "Add the next meeting or event so members know what is coming up.",
      ctaLabel: "Create event",
      ctaTarget: "/events#create-event",
      priority: 80,
    });
  }

  if (!hasAnnouncement || !latestAnnouncementCreatedAt || new Date(latestAnnouncementCreatedAt).getTime() < sevenDaysAgo.getTime()) {
    drafts.push({
      id: "no-recent-announcement",
      type: "no_recent_announcement",
      title: "Members have not seen a recent update",
      description: hasAnnouncement
        ? "Your latest announcement is older than 7 days. Post a fresh update to keep the club informed."
        : "No announcement has been posted yet. Share a quick update so members know what is happening.",
      ctaLabel: "Post announcement",
      ctaTarget: "/announcements",
      priority: 60,
    });
  }

  if (mostRecentPastEvent && !latestPastEventHasTrackedAttendance) {
    drafts.push({
      id: `attendance-missing-${mostRecentPastEvent.id}`,
      type: "attendance_not_marked",
      title: "Attendance was not marked for the latest past event",
      description: `${mostRecentPastEvent.title} has no attendance tracked yet, so attendance insights are incomplete.`,
      ctaLabel: "Track attendance",
      ctaTarget: "/events",
      priority: 90,
    });
  }

  return drafts;
}

/** Pre-migration 027: `club_members.membership_status` does not exist yet. */
function isMissingMembershipStatusColumn(error: { code?: string; message?: string }): boolean {
  return (
    error.code === "42703" && Boolean(error.message?.toLowerCase().includes("membership_status"))
  );
}

/** Server logs only — helps diagnose empty dashboard when the DB is missing columns (e.g. migration 027) or RLS blocks reads. */
function logGetCurrentUserClubsFailure(
  userId: string,
  error: { code?: string; message?: string; details?: string; hint?: string } | null,
  data: unknown,
) {
  const msg = error?.message?.toLowerCase() ?? "";
  const likelyMissingMembershipStatus =
    msg.includes("membership_status") || msg.includes("schema cache") || msg.includes("column");

  console.error("[getCurrentUserClubs] club_members query did not succeed", {
    userId,
    errorCode: error?.code ?? null,
    errorMessage: error?.message ?? null,
    details: error?.details ?? null,
    hint: error?.hint ?? null,
    dataWasNullish: data == null,
    diagnose:
      likelyMissingMembershipStatus
        ? "Apply supabase/027_alumni_membership.sql to this Supabase project if membership_status is missing."
        : "Check RLS on club_members/clubs, or confirm this user has club_members rows.",
  });
}

export async function getCurrentUserClubs(): Promise<UserClub[]> {
  noStore();

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    return [];
  }

  const select = "role, clubs(id, name, description, join_code, status)" as const;

  let { data, error } = await supabase
    .from("club_members")
    .select(select)
    .eq("user_id", user.id)
    .eq("membership_status", "active")
    .order("joined_at", { ascending: false });

  if (error && isMissingMembershipStatusColumn(error)) {
    const retry = await supabase
      .from("club_members")
      .select(select)
      .eq("user_id", user.id)
      .order("joined_at", { ascending: false });
    data = retry.data;
    error = retry.error;
  }

  if (error) {
    logGetCurrentUserClubsFailure(user.id, error, data);
    return [];
  }

  if (data == null) {
    logGetCurrentUserClubsFailure(user.id, null, data);
    return [];
  }

  const rows = data as unknown as ClubMemberRow[];

  return rows
    .map((row) => ({
      role: row.role,
      club: normalizeClubRelation(row.clubs),
    }))
    .filter((row) => row.club)
    .filter((row) => (row.club!.status ?? "active") === "active")
    .map((row) => ({
      id: row.club!.id,
      name: row.club!.name,
      description: row.club!.description,
      joinCode: row.club!.join_code,
      role: row.role,
    }));
}

export async function getDashboardData(): Promise<DashboardData> {
  noStore();

  const clubs = await getCurrentUserClubs();
  const clubIds = clubs.map((club) => club.id);

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  async function fetchUnreadCount(): Promise<number> {
    if (!user) return 0;
    const { count } = await supabase
      .from("notifications")
      .select("id", { count: "exact", head: true })
      .eq("user_id", user.id)
      .eq("is_read", false);
    return count ?? 0;
  }

  if (clubIds.length === 0) {
    return {
      clubs: [],
      recentAnnouncements: [],
      upcomingEvents: [],
      needsAttentionAlerts: [],
      myOpenTasks: [],
      unreadNotificationCount: await fetchUnreadCount(),
    };
  }

  const now = new Date();
  const nowIso = now.toISOString();
  const sevenDaysAgo = new Date(now);
  sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

  const { data: clubMembersData } = await supabase
    .from("club_members")
    .select("club_id")
    .in("club_id", clubIds)
    .eq("membership_status", "active");

  const { data: announcementsData } = await supabase
    .from("announcements")
    .select("id, title, created_at, club_id")
    .in("club_id", clubIds)
    .order("created_at", { ascending: false });

  const { data: upcomingEventsData } = await supabase
    .from("events")
    .select("id, title, location, event_type, event_date, club_id")
    .in("club_id", clubIds)
    .gte("event_date", nowIso)
    .order("event_date", { ascending: true });

  const { data: pastEventsData } = await supabase
    .from("events")
    .select("id, title, event_date, club_id")
    .in("club_id", clubIds)
    .lt("event_date", nowIso)
    .order("event_date", { ascending: false });

  const clubNameById = new Map(clubs.map((club) => [club.id, club.name]));
  const memberCountByClubId = new Map<string, number>();

  for (const row of clubMembersData ?? []) {
    memberCountByClubId.set(row.club_id, (memberCountByClubId.get(row.club_id) ?? 0) + 1);
  }

  const nextUpcomingEventByClubId = new Map<string, { id: string; title: string; eventDate: string }>();
  for (const event of upcomingEventsData ?? []) {
    if (!nextUpcomingEventByClubId.has(event.club_id)) {
      nextUpcomingEventByClubId.set(event.club_id, {
        id: event.id,
        title: event.title,
        eventDate: event.event_date,
      });
    }
  }

  const nextUpcomingEventIds = Array.from(nextUpcomingEventByClubId.values()).map((event) => event.id);
  const { data: nextEventRsvpData } =
    nextUpcomingEventIds.length > 0
      ? await supabase
          .from("rsvps")
          .select("event_id")
          .in("event_id", nextUpcomingEventIds)
      : { data: [] as { event_id: string }[] };

  const nextEventResponseCountByEventId = new Map<string, number>();
  for (const rsvp of nextEventRsvpData ?? []) {
    nextEventResponseCountByEventId.set(rsvp.event_id, (nextEventResponseCountByEventId.get(rsvp.event_id) ?? 0) + 1);
  }

  const latestAnnouncementByClubId = new Map<string, { createdAt: string }>();
  for (const announcement of announcementsData ?? []) {
    if (!latestAnnouncementByClubId.has(announcement.club_id)) {
      latestAnnouncementByClubId.set(announcement.club_id, { createdAt: announcement.created_at });
    }
  }

  const mostRecentPastEventByClubId = new Map<string, { id: string; title: string }>();
  for (const event of pastEventsData ?? []) {
    if (!mostRecentPastEventByClubId.has(event.club_id)) {
      mostRecentPastEventByClubId.set(event.club_id, {
        id: event.id,
        title: event.title,
      });
    }
  }

  const pastEventIds = (pastEventsData ?? []).map((event) => event.id);
  const { data: pastAttendanceData } =
    pastEventIds.length > 0
      ? await supabase
          .from("event_attendance")
          .select("event_id")
          .in("event_id", pastEventIds)
      : { data: [] as { event_id: string }[] };

  const trackedPastEventIds = new Set((pastAttendanceData ?? []).map((attendance) => attendance.event_id));
  const needsAttentionAlerts = clubs
    .flatMap((club) => {
      const nextUpcomingEvent = nextUpcomingEventByClubId.get(club.id) ?? null;
      const latestAnnouncement = latestAnnouncementByClubId.get(club.id) ?? null;
      const mostRecentPastEvent = mostRecentPastEventByClubId.get(club.id) ?? null;
      const drafts = buildAttentionAlertDrafts({
        now,
        sevenDaysAgo,
        memberCount: memberCountByClubId.get(club.id) ?? 0,
        nextUpcomingEvent,
        nextEventResponseCount: nextUpcomingEvent ? (nextEventResponseCountByEventId.get(nextUpcomingEvent.id) ?? 0) : 0,
        latestAnnouncementCreatedAt: latestAnnouncement?.createdAt ?? null,
        hasAnnouncement: Boolean(latestAnnouncement),
        mostRecentPastEvent,
        latestPastEventHasTrackedAttendance: mostRecentPastEvent ? trackedPastEventIds.has(mostRecentPastEvent.id) : true,
      });

      return drafts.map((draft) => ({
        id: `${club.id}-${draft.id}`,
        clubId: club.id,
        clubName: club.name,
        type: draft.type,
        title: draft.title,
        description: draft.description,
        ctaLabel: draft.ctaLabel,
        ctaHref: `/clubs/${club.id}${draft.ctaTarget}`,
        priority: draft.priority + (club.role === "officer" ? 20 : 0),
      }));
    })
    .sort((a, b) => b.priority - a.priority)
    .slice(0, 4);

  let myOpenTasks: DashboardTaskPreview[] = [];
  if (user) {
    const { data: assigneeRows } = await supabase
      .from("club_task_assignees")
      .select("task_id")
      .eq("user_id", user.id);

    const taskIdSet = new Set((assigneeRows ?? []).map((r) => r.task_id));
    const taskIds = Array.from(taskIdSet);
    if (taskIds.length > 0) {
      const { data: tasksData } = await supabase
        .from("club_tasks")
        .select("id, club_id, title, priority, due_at, status")
        .in("id", taskIds)
        .in("club_id", clubIds)
        .neq("status", "completed")
        .order("due_at", { ascending: true, nullsFirst: false })
        .limit(8);

      myOpenTasks = (tasksData ?? []).map((t) => {
        const dueAtIso = t.due_at;
        const due = dueAtIso ? new Date(dueAtIso) : null;
        const isOverdue = due !== null && due < now;
        return {
          id: t.id,
          clubId: t.club_id,
          clubName: clubNameById.get(t.club_id) ?? "Club",
          title: t.title,
          dueAtIso,
          dueAt: dueAtIso
            ? new Date(dueAtIso).toLocaleDateString(undefined, { month: "short", day: "numeric" })
            : null,
          priority: t.priority as DashboardTaskPreview["priority"],
          isOverdue,
        };
      });
    }
  }

  const unreadNotificationCount = await fetchUnreadCount();

  return {
    clubs,
    recentAnnouncements: (announcementsData ?? []).slice(0, 8).map((announcement) => ({
      id: announcement.id,
      clubId: announcement.club_id,
      clubName: clubNameById.get(announcement.club_id) ?? "Club",
      title: announcement.title,
      createdAt: new Date(announcement.created_at).toLocaleString(),
      createdAtRaw: announcement.created_at,
    })),
    upcomingEvents: (upcomingEventsData ?? []).slice(0, 8).map((event) => ({
      id: event.id,
      clubId: event.club_id,
      clubName: clubNameById.get(event.club_id) ?? "Club",
      title: event.title,
      location: event.location,
      eventType: normalizeEventType(event.event_type),
      eventDate: new Date(event.event_date).toLocaleString(),
      eventDateRaw: event.event_date,
    })),
    needsAttentionAlerts,
    myOpenTasks,
    unreadNotificationCount,
  };
}

export async function getClubDetailForCurrentUser(clubId: string): Promise<ClubDetail | null> {
  noStore();

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    return null;
  }

  const { data: membership, error: membershipError } = await supabase
    .from("club_members")
    .select("role, clubs(id, name, description, join_code, status, require_join_approval)")
    .eq("club_id", clubId)
    .eq("user_id", user.id)
    .maybeSingle();

  if (membershipError || !membership?.clubs) {
    return null;
  }

  const clubRelation = normalizeClubRelation(membership.clubs);
  if (!clubRelation) {
    return null;
  }

  const { data: memberBaseData } = await supabase
    .from("club_members")
    .select("user_id, role, membership_status, joined_at")
    .eq("club_id", clubId)
    .order("role", { ascending: false });

  const { data: membersData } = await supabase
    .rpc("get_club_members_for_view", { target_club_id: clubId });

  const memberViewById = new Map(
    ((membersData ?? []) as ClubMemberViewRow[]).map((member) => [member.user_id, member]),
  );

  const { data: tagDefRows, error: tagDefError } = await supabase
    .from("club_member_tags")
    .select("id, name")
    .eq("club_id", clubId)
    .order("name");

  const safeTagDefs = tagDefError ? [] : (tagDefRows ?? []);
  const tagIdsForClub = safeTagDefs.map((t) => t.id);
  const tagIdToTag = new Map(safeTagDefs.map((t) => [t.id, { id: t.id, name: t.name }]));

  const { data: assignRows } =
    tagIdsForClub.length === 0 || tagDefError
      ? { data: [] as { user_id: string; tag_id: string }[] }
      : await supabase
          .from("club_member_tag_assignments")
          .select("user_id, tag_id")
          .in("tag_id", tagIdsForClub);

  const tagsByUserId = new Map<string, ClubMemberTag[]>();
  for (const row of assignRows ?? []) {
    const tag = tagIdToTag.get(row.tag_id);
    if (!tag) continue;
    const list = tagsByUserId.get(row.user_id) ?? [];
    list.push(tag);
    tagsByUserId.set(row.user_id, list);
  }
  for (const list of tagsByUserId.values()) {
    list.sort((a, b) => a.name.localeCompare(b.name));
  }

  const { data: committeeRows, error: committeeDefError } = await supabase
    .from("club_committees")
    .select("id, name")
    .eq("club_id", clubId)
    .order("name");

  const safeCommittees = committeeDefError ? [] : (committeeRows ?? []);
  const committeeIdsForClub = safeCommittees.map((c) => c.id);
  const committeeIdToSummary = new Map(safeCommittees.map((c) => [c.id, { id: c.id, name: c.name }]));

  const { data: committeeMemberRows } =
    committeeIdsForClub.length === 0 || committeeDefError
      ? { data: [] as { user_id: string; committee_id: string }[] }
      : await supabase
          .from("club_committee_members")
          .select("user_id, committee_id")
          .in("committee_id", committeeIdsForClub);

  const committeesByUserId = new Map<string, ClubCommitteeSummary[]>();
  for (const row of committeeMemberRows ?? []) {
    const c = committeeIdToSummary.get(row.committee_id);
    if (!c) continue;
    const list = committeesByUserId.get(row.user_id) ?? [];
    list.push(c);
    committeesByUserId.set(row.user_id, list);
  }
  for (const list of committeesByUserId.values()) {
    list.sort((a, b) => a.name.localeCompare(b.name));
  }

  const { data: teamRows, error: teamDefError } = await supabase
    .from("club_teams")
    .select("id, name")
    .eq("club_id", clubId)
    .order("name");

  const safeTeams = teamDefError ? [] : (teamRows ?? []);
  const teamIdsForClub = safeTeams.map((t) => t.id);
  const teamIdToSummary = new Map(safeTeams.map((t) => [t.id, { id: t.id, name: t.name }]));

  const { data: teamMemberRows } =
    teamIdsForClub.length === 0 || teamDefError
      ? { data: [] as { user_id: string; team_id: string }[] }
      : await supabase
          .from("club_team_members")
          .select("user_id, team_id")
          .in("team_id", teamIdsForClub);

  const teamsByUserId = new Map<string, ClubTeamSummary[]>();
  for (const row of teamMemberRows ?? []) {
    const t = teamIdToSummary.get(row.team_id);
    if (!t) continue;
    const list = teamsByUserId.get(row.user_id) ?? [];
    list.push(t);
    teamsByUserId.set(row.user_id, list);
  }
  for (const list of teamsByUserId.values()) {
    list.sort((a, b) => a.name.localeCompare(b.name));
  }

  const now = new Date();
  const nowIso = now.toISOString();
  const sevenDaysAgo = new Date(now);
  sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

  const { data: announcementsData } = await supabase
    .from("announcements")
    .select("id, title, content, created_at")
    .eq("club_id", clubId)
    .order("created_at", { ascending: false })
    .limit(10);

  const { data: activityData } = await supabase
    .rpc("get_club_recent_activity", { target_club_id: clubId });

  const [{ data: upcomingEventsRows }, { data: pastEventsRows }] = await Promise.all([
    supabase
      .from("events")
      .select("id, title, description, location, event_type, event_date")
      .eq("club_id", clubId)
      .gte("event_date", nowIso)
      .order("event_date", { ascending: true })
      .limit(100),
    supabase
      .from("events")
      .select("id, title, description, location, event_type, event_date")
      .eq("club_id", clubId)
      .lt("event_date", nowIso)
      .order("event_date", { ascending: false })
      .limit(150),
  ]);

  const eventRowById = new Map<
    string,
    {
      id: string;
      title: string;
      description: string;
      location: string;
      event_type: string;
      event_date: string;
    }
  >();
  for (const row of upcomingEventsRows ?? []) {
    eventRowById.set(row.id, row);
  }
  for (const row of pastEventsRows ?? []) {
    eventRowById.set(row.id, row);
  }
  const eventsData = [...eventRowById.values()];

  const firstUpcoming = (upcomingEventsRows ?? [])[0] ?? null;
  const nextUpcomingEventData = firstUpcoming
    ? { id: firstUpcoming.id, title: firstUpcoming.title, event_date: firstUpcoming.event_date }
    : null;

  const eventIds = eventsData.map((event) => event.id);

  const { data: rsvpData } =
    eventIds.length > 0
      ? await supabase
          .from("rsvps")
          .select("event_id, user_id, status")
          .in("event_id", eventIds)
      : { data: [] as { event_id: string; user_id: string; status: "yes" | "no" | "maybe" }[] };

  const { data: attendanceData } =
    eventIds.length > 0
      ? await supabase
          .from("event_attendance")
          .select("event_id, user_id")
          .in("event_id", eventIds)
      : { data: [] as { event_id: string; user_id: string }[] };

  // RLS on event_reflections handles per-user access (is_club_officer OR has reflections.create).
  // We always attempt the fetch; non-permitted users receive an empty result set from the DB.
  const { data: reflectionData } =
    eventIds.length > 0
      ? await supabase
          .from("event_reflections")
          .select("event_id, what_worked, what_didnt, notes, updated_at")
          .in("event_id", eventIds)
      : {
          data: [] as {
            event_id: string;
            what_worked: string;
            what_didnt: string;
            notes: string | null;
            updated_at: string;
          }[],
        };

  const { data: pastEventsData } = await supabase
    .from("events")
    .select("id")
    .eq("club_id", clubId)
    .lt("event_date", nowIso);

  const { data: mostRecentPastEventData } = await supabase
    .from("events")
    .select("id, title, event_date")
    .eq("club_id", clubId)
    .lt("event_date", nowIso)
    .order("event_date", { ascending: false })
    .limit(1)
    .maybeSingle();

  const pastEventIds = (pastEventsData ?? []).map((event) => event.id);

  const { data: pastAttendanceData } =
    pastEventIds.length > 0
      ? await supabase
          .from("event_attendance")
          .select("event_id, user_id")
          .in("event_id", pastEventIds)
      : { data: [] as { event_id: string; user_id: string }[] };

  const trackedEventIds = new Set((pastAttendanceData ?? []).map((attendance) => attendance.event_id));
  const totalTrackedEvents = trackedEventIds.size;
  const trackedAttendanceByUser = new Map<string, Set<string>>();

  for (const attendance of pastAttendanceData ?? []) {
    if (!trackedEventIds.has(attendance.event_id)) {
      continue;
    }

    const userAttendance = trackedAttendanceByUser.get(attendance.user_id) ?? new Set<string>();
    userAttendance.add(attendance.event_id);
    trackedAttendanceByUser.set(attendance.user_id, userAttendance);
  }

  const membersWithAttendance = ((memberBaseData ?? []) as ClubMemberBaseRow[]).map((member) => {
    const detail = memberViewById.get(member.user_id);
    const attendanceCount = trackedAttendanceByUser.get(member.user_id)?.size ?? 0;
    const attendanceRate = totalTrackedEvents > 0
      ? Math.round((attendanceCount / totalTrackedEvents) * 100)
      : 0;
    const membershipStatus = detail?.membership_status ?? member.membership_status;

    return {
      userId: member.user_id,
      fullName: detail?.full_name ?? null,
      email: detail?.email ?? null,
      role: member.role,
      membershipStatus,
      joinedAt: member.joined_at ?? null,
      tags: tagsByUserId.get(member.user_id) ?? [],
      committees: committeesByUserId.get(member.user_id) ?? [],
      teams: teamsByUserId.get(member.user_id) ?? [],
      attendanceCount,
      totalTrackedEvents,
      attendanceRate,
    };
  });

  const activeMembersForAvg = membersWithAttendance.filter((m) => m.membershipStatus === "active");
  const clubAverageAttendance =
    totalTrackedEvents > 0 && activeMembersForAvg.length > 0
      ? Math.round(
          (activeMembersForAvg.reduce((sum, member) => sum + member.attendanceCount, 0)
            / (totalTrackedEvents * activeMembersForAvg.length))
            * 100,
        )
      : 0;

  const topMembers = [...membersWithAttendance]
    .sort((a, b) => {
      if (b.attendanceRate !== a.attendanceRate) {
        return b.attendanceRate - a.attendanceRate;
      }

      if (b.attendanceCount !== a.attendanceCount) {
        return b.attendanceCount - a.attendanceCount;
      }

      return getSortableMemberName(a).localeCompare(getSortableMemberName(b));
    })
    .slice(0, 3);

  const memberCount = ((memberBaseData ?? []) as ClubMemberBaseRow[]).filter(
    (m) => m.membership_status === "active",
  ).length;
  const nextUpcomingEvent = nextUpcomingEventData
    ? {
        id: nextUpcomingEventData.id,
        title: nextUpcomingEventData.title,
        eventDate: nextUpcomingEventData.event_date,
      }
    : null;
  const latestAnnouncementData = (announcementsData ?? [])[0] ?? null;
  const attentionAlertDrafts = buildAttentionAlertDrafts({
    now,
    sevenDaysAgo,
    memberCount,
    nextUpcomingEvent,
    nextEventResponseCount: nextUpcomingEvent ? (rsvpData ?? []).filter((rsvp) => rsvp.event_id === nextUpcomingEvent.id).length : 0,
    latestAnnouncementCreatedAt: latestAnnouncementData?.created_at ?? null,
    hasAnnouncement: Boolean(latestAnnouncementData),
    mostRecentPastEvent: mostRecentPastEventData
      ? {
          id: mostRecentPastEventData.id,
          title: mostRecentPastEventData.title,
        }
      : null,
    latestPastEventHasTrackedAttendance: mostRecentPastEventData ? trackedEventIds.has(mostRecentPastEventData.id) : true,
  });

  const attentionAlerts = attentionAlertDrafts
    .sort((a, b) => b.priority - a.priority)
    .slice(0, 3)
    .map((alert) => ({
      id: alert.id,
      type: alert.type,
      title: alert.title,
      description: alert.description,
      ctaLabel: alert.ctaLabel,
      ctaTarget: alert.ctaTarget,
    }));

  const lifecycleStatus: ClubStatus =
    clubRelation.status === "archived" ? "archived" : "active";

  return {
    id: clubRelation.id,
    name: clubRelation.name,
    description: clubRelation.description,
    joinCode: clubRelation.join_code,
    requireJoinApproval: Boolean(clubRelation.require_join_approval),
    status: lifecycleStatus,
    currentUserId: user.id,
    currentUserRole: membership.role,
    memberCount,
    members: membersWithAttendance,
    totalTrackedEvents,
    clubAverageAttendance,
    topMembers,
    attentionAlerts,
    recentActivity: ((activityData ?? []) as ClubActivityRow[]).map((item) => ({
      id: item.id,
      kind: item.kind,
      message: item.message,
      createdAt: new Date(item.created_at).toLocaleString(),
      createdAtIso: item.created_at,
    })),
    announcements: (announcementsData ?? []).map((announcement) => ({
      id: announcement.id,
      title: announcement.title,
      content: announcement.content,
      createdAt: new Date(announcement.created_at).toLocaleString(),
    })),
    memberTagDefinitions: safeTagDefs.map((t) => ({ id: t.id, name: t.name })),
    clubCommittees: safeCommittees.map((c) => ({ id: c.id, name: c.name })),
    clubTeams: safeTeams.map((t) => ({ id: t.id, name: t.name })),
    events: eventsData.map((event) => ({
      id: event.id,
      title: event.title,
      description: event.description,
      location: event.location,
      eventType: normalizeEventType(event.event_type),
      eventDate: new Date(event.event_date).toLocaleString(),
      eventDateRaw: new Date(event.event_date),
      userRsvpStatus:
        (rsvpData ?? []).find((rsvp) => rsvp.event_id === event.id && rsvp.user_id === user.id)?.status ?? null,
      userMarkedPresent: (attendanceData ?? []).some(
        (attendance) => attendance.event_id === event.id && attendance.user_id === user.id,
      ),
      attendanceCount: (attendanceData ?? []).filter((attendance) => attendance.event_id === event.id).length,
      presentMemberIds: (attendanceData ?? [])
        .filter((attendance) => attendance.event_id === event.id)
        .map((attendance) => attendance.user_id),
      rsvpCounts: {
        yes: (rsvpData ?? []).filter((rsvp) => rsvp.event_id === event.id && rsvp.status === "yes").length,
        no: (rsvpData ?? []).filter((rsvp) => rsvp.event_id === event.id && rsvp.status === "no").length,
        maybe: (rsvpData ?? []).filter((rsvp) => rsvp.event_id === event.id && rsvp.status === "maybe").length,
      },
      reflection: (() => {
        const reflection = (reflectionData ?? []).find((item) => item.event_id === event.id);

        if (!reflection) {
          return null;
        }

        return {
          whatWorked: reflection.what_worked,
          whatDidnt: reflection.what_didnt,
          notes: reflection.notes,
          updatedAt: new Date(reflection.updated_at).toLocaleString(),
          updatedAtIso: reflection.updated_at,
        };
      })(),
    })),
  };
}

export type PendingJoinRequest = {
  id: string;
  userId: string;
  fullName: string | null;
  requestedAt: string;
};

/** Pending join requests for leadership review (names via SECURITY DEFINER RPC; see migration 033). */
export async function getPendingJoinRequestsForClub(clubId: string): Promise<PendingJoinRequest[]> {
  noStore();

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    return [];
  }

  const { data, error } = await supabase.rpc("list_pending_club_join_requests", {
    p_club_id: clubId,
  });

  if (error || !data) {
    return [];
  }

  return (data as { id: string; user_id: string; full_name: string | null; requested_at: string }[]).map((row) => ({
    id: row.id,
    userId: row.user_id,
    fullName: row.full_name?.trim() ? row.full_name : null,
    requestedAt: row.requested_at,
  }));
}
