import "server-only";
import { unstable_noStore as noStore } from "next/cache";
import { signAnnouncementAttachmentRows } from "@/lib/announcements/attachment-signing";
import { parsePollOptionsFromDb } from "@/lib/announcements/poll-options";
import { normalizeEventType, type EventType } from "@/lib/events";
import { createClient } from "@/lib/supabase/server";
import type { ClubStatus } from "@/lib/clubs/club-status";
import {
  buildLastEngagementByUserMs,
  computeLikelyInactiveMember,
} from "@/lib/clubs/member-inactivity";
import { compareAvailabilitySlots, normalizeAvailabilityTime } from "@/lib/clubs/member-availability-display";

export type UserClub = {
  id: string;
  name: string;
  description: string;
  joinCode: string;
  role: "member" | "officer";
};

export type ClubAnnouncementAttachment = {
  id: string;
  fileName: string;
  fileType: string;
  signedUrl: string;
};

export type ClubAnnouncement = {
  id: string;
  title: string;
  content: string;
  createdAt: string;
  createdAtRaw: string;
  pollQuestion: string | null;
  pollOptions: string[] | null;
  scheduledFor: string | null;
  isPublished: boolean;
  isPinned: boolean;
  pinnedAt: string | null;
  isUrgent: boolean;
  /** Populated on the announcements tab (aggregated RPCs). */
  readCount?: number;
  totalMembers?: number;
  pollTallies?: { optionIndex: number; count: number }[];
  totalPollVotes?: number;
  userPollVoteIndex?: number | null;
  attachments?: ClubAnnouncementAttachment[];
};

type AnnouncementSelectRow = {
  id: string;
  title: string;
  content: string;
  created_at: string;
  poll_question?: string | null;
  poll_options?: unknown;
  scheduled_for?: string | null;
  is_published?: boolean | null;
  is_pinned?: boolean | null;
  pinned_at?: string | null;
  is_urgent?: boolean | null;
};

function mapAnnouncementRow(row: AnnouncementSelectRow): ClubAnnouncement {
  return {
    id: row.id,
    title: row.title,
    content: row.content,
    createdAt: new Date(row.created_at).toLocaleString(),
    createdAtRaw: row.created_at,
    pollQuestion: row.poll_question ?? null,
    pollOptions: parsePollOptionsFromDb(row.poll_options),
    scheduledFor: row.scheduled_for ?? null,
    isPublished: row.is_published ?? true,
    isPinned: row.is_pinned ?? false,
    pinnedAt: row.pinned_at ?? null,
    isUrgent: row.is_urgent ?? false,
  };
}

export type ClubEvent = {
  id: string;
  title: string;
  description: string;
  location: string;
  eventType: EventType;
  /** Optional attendee limit; null means unlimited. */
  capacity: number | null;
  /** Confirmed going RSVPs (`status = yes`). */
  confirmedYesCount: number;
  /** Waitlisted RSVPs (`status = waitlist`). */
  waitlistCount: number;
  /** Remaining confirmed spots; null when capacity is unlimited. */
  capacityRemaining: number | null;
  /** True when confirmed attendees exceed configured capacity. */
  isOverCapacity: boolean;
  eventDate: string;
  eventDateRaw: Date;
  seriesId: string | null;
  seriesOccurrence: number | null;
  userRsvpStatus: EventRsvpStatus | null;
  /** One-based position in the waitlist for current user when applicable. */
  userWaitlistPosition: number | null;
  /** Whether the current user appears in attendance for this event (self only; safe for all members). */
  userMarkedPresent: boolean;
  attendanceCount: number;
  presentMemberIds: string[];
  rsvpCounts: {
    yes: number;
    no: number;
    maybe: number;
    waitlist: number;
  };
  goingMemberIds: string[];
  reflection: {
    whatWorked: string;
    whatDidnt: string;
    notes: string | null;
    updatedAt: string;
    /** Raw ISO-8601 string for sorting and relative-time formatting */
    updatedAtIso: string;
  } | null;
};

export type EventRsvpStatus = "yes" | "no" | "maybe" | "waitlist";

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

/** Single volunteer hours log row for a member within a club. */
export type ClubVolunteerHourEntry = {
  id: string;
  hours: number;
  note: string | null;
  /** ISO date string (YYYY-MM-DD). */
  serviceDate: string;
  createdAt: string;
};

/** Club-scoped skill or interest label for a member (not leadership tags). */
export type ClubMemberSkillInterestEntry = {
  id: string;
  kind: "skill" | "interest";
  label: string;
  createdAt: string;
};

/** Recurring weekly availability within a club (local wall times). */
export type ClubMemberAvailabilitySlot = {
  id: string;
  /** 1 = Monday … 7 = Sunday */
  dayOfWeek: number;
  /** `HH:MM` or null with null end = all day / flexible */
  timeStart: string | null;
  timeEnd: string | null;
  createdAt: string;
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
  /** Most recent engagement from RSVP or attended event; null if none in loaded history. */
  lastEngagementAt: string | null;
  /** Club has too few tracked events to fairly label inactivity. */
  engagementSignalWeak: boolean;
  /** Derived hint: low recent participation (not a membership status). */
  likelyInactive: boolean;
  /** Sum of logged volunteer hours in this club. */
  volunteerHoursTotal: number;
  /** Newest-first entries (same club). */
  volunteerHourEntries: ClubVolunteerHourEntry[];
  /** Skills and interests for this member in this club (oldest-first). */
  skillInterestEntries: ClubMemberSkillInterestEntry[];
  /** Weekly availability slots (Mon=1 … Sun=7), sorted for display. */
  availabilitySlots: ClubMemberAvailabilitySlot[];
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
  /**
   * Members-roster loader: total announcements in the club (cheap count) when `announcements` is left empty.
   */
  rosterAnnouncementsCount?: number;
  /**
   * Members-roster loader: total events in the club (cheap count) when `events` is left empty.
   */
  rosterEventsCount?: number;
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

type ClubEventRow = {
  id: string;
  title: string;
  description: string;
  location: string;
  event_type: string;
  event_date: string;
  capacity?: number | null;
  series_id?: string | null;
  series_occurrence?: number | null;
};

function mapEventRowsToClubEvents(
  eventsData: ClubEventRow[],
  userId: string,
  rsvpData:
    | { event_id: string; user_id: string; status: EventRsvpStatus; created_at: string; waitlisted_at?: string | null }[]
    | null
    | undefined,
  attendanceData: { event_id: string; user_id: string }[] | null | undefined,
  reflectionData:
    | { event_id: string; what_worked: string; what_didnt: string; notes: string | null; updated_at: string }[]
    | null
    | undefined,
): ClubEvent[] {
  const waitlistPositionByEventAndUser = new Map<string, number>();
  const waitlistRows = (rsvpData ?? []).filter((rsvp) => rsvp.status === "waitlist");
  const waitlistRowsByEvent = new Map<string, typeof waitlistRows>();
  for (const row of waitlistRows) {
    const existing = waitlistRowsByEvent.get(row.event_id) ?? [];
    existing.push(row);
    waitlistRowsByEvent.set(row.event_id, existing);
  }
  for (const [eventId, rows] of waitlistRowsByEvent) {
    rows
      .sort((a, b) => {
        const aRank = new Date(a.waitlisted_at ?? a.created_at).getTime();
        const bRank = new Date(b.waitlisted_at ?? b.created_at).getTime();
        if (aRank !== bRank) return aRank - bRank;
        if (a.created_at !== b.created_at) return a.created_at.localeCompare(b.created_at);
        return a.user_id.localeCompare(b.user_id);
      })
      .forEach((row, index) => {
        waitlistPositionByEventAndUser.set(`${eventId}:${row.user_id}`, index + 1);
      });
  }

  return eventsData.map((event) => {
    const eventRsvps = (rsvpData ?? []).filter((rsvp) => rsvp.event_id === event.id);
    const yesCount = eventRsvps.filter((rsvp) => rsvp.status === "yes").length;
    const noCount = eventRsvps.filter((rsvp) => rsvp.status === "no").length;
    const maybeCount = eventRsvps.filter((rsvp) => rsvp.status === "maybe").length;
    const waitlistCount = eventRsvps.filter((rsvp) => rsvp.status === "waitlist").length;
    const eventAttendanceRows = (attendanceData ?? []).filter((attendance) => attendance.event_id === event.id);
    const userRsvpStatus = eventRsvps.find((rsvp) => rsvp.user_id === userId)?.status ?? null;
    const capacity = event.capacity ?? null;
    return {
      id: event.id,
      title: event.title,
      description: event.description,
      location: event.location,
      eventType: normalizeEventType(event.event_type),
      capacity,
      confirmedYesCount: yesCount,
      waitlistCount,
      capacityRemaining: capacity == null ? null : Math.max(0, capacity - yesCount),
      isOverCapacity: capacity != null && yesCount > capacity,
      eventDate: new Date(event.event_date).toLocaleString(),
      eventDateRaw: new Date(event.event_date),
      seriesId: event.series_id ?? null,
      seriesOccurrence: event.series_occurrence ?? null,
      userRsvpStatus,
      userWaitlistPosition:
        userRsvpStatus === "waitlist" ? (waitlistPositionByEventAndUser.get(`${event.id}:${userId}`) ?? null) : null,
      userMarkedPresent: eventAttendanceRows.some((attendance) => attendance.user_id === userId),
      attendanceCount: eventAttendanceRows.length,
      presentMemberIds: eventAttendanceRows.map((attendance) => attendance.user_id),
      rsvpCounts: {
        yes: yesCount,
        no: noCount,
        maybe: maybeCount,
        waitlist: waitlistCount,
      },
      goingMemberIds: eventRsvps
        .filter((rsvp) => rsvp.status === "yes")
        .map((rsvp) => rsvp.user_id),
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
    };
  });
}

/** Roster fields required for event RSVP/attendance UI; other ClubMember fields are inert defaults. */
function buildLightMembersForEventUi(
  memberBaseData: ClubMemberBaseRow[] | null | undefined,
  memberViewById: Map<string, ClubMemberViewRow>,
): ClubMember[] {
  return ((memberBaseData ?? []) as ClubMemberBaseRow[]).map((member) => {
    const detail = memberViewById.get(member.user_id);
    const membershipStatus = detail?.membership_status ?? member.membership_status;
    return {
      userId: member.user_id,
      fullName: detail?.full_name ?? null,
      email: detail?.email ?? null,
      role: member.role,
      membershipStatus,
      joinedAt: member.joined_at ?? null,
      tags: [],
      committees: [],
      teams: [],
      attendanceCount: 0,
      totalTrackedEvents: 0,
      attendanceRate: 0,
      lastEngagementAt: null,
      engagementSignalWeak: true,
      likelyInactive: false,
      volunteerHoursTotal: 0,
      volunteerHourEntries: [],
      skillInterestEntries: [],
      availabilitySlots: [],
    };
  });
}

/** Members with attendance + engagement fields only (no tags, committees, volunteer, etc.). */
function buildMembersWithAttendanceInsightsOnly(
  memberBaseData: ClubMemberBaseRow[] | null | undefined,
  memberViewById: Map<string, ClubMemberViewRow>,
  trackedAttendanceByUser: Map<string, Set<string>>,
  totalTrackedEvents: number,
  lastEngagementByUserMs: Map<string, number>,
  now: Date,
): ClubMember[] {
  return ((memberBaseData ?? []) as ClubMemberBaseRow[]).map((member) => {
    const detail = memberViewById.get(member.user_id);
    const attendanceCount = trackedAttendanceByUser.get(member.user_id)?.size ?? 0;
    const attendanceRate =
      totalTrackedEvents > 0 ? Math.round((attendanceCount / totalTrackedEvents) * 100) : 0;
    const membershipStatus = detail?.membership_status ?? member.membership_status;

    const engagement = computeLikelyInactiveMember({
      membershipStatus,
      joinedAtIso: member.joined_at ?? null,
      totalTrackedEvents,
      lastEngagementMs: lastEngagementByUserMs.get(member.user_id),
      now,
    });

    return {
      userId: member.user_id,
      fullName: detail?.full_name ?? null,
      email: detail?.email ?? null,
      role: member.role,
      membershipStatus,
      joinedAt: member.joined_at ?? null,
      tags: [],
      committees: [],
      teams: [],
      attendanceCount,
      totalTrackedEvents,
      attendanceRate,
      lastEngagementAt: engagement.lastEngagementAt,
      engagementSignalWeak: engagement.engagementSignalWeak,
      likelyInactive: engagement.likelyInactive,
      volunteerHoursTotal: 0,
      volunteerHourEntries: [],
      skillInterestEntries: [],
      availabilitySlots: [],
    };
  });
}

function buildMembersVolunteerOnly(
  memberBaseData: ClubMemberBaseRow[] | null | undefined,
  memberViewById: Map<string, ClubMemberViewRow>,
  volunteerEntriesByUser: Map<string, ClubVolunteerHourEntry[]>,
  volunteerTotalByUser: Map<string, number>,
): ClubMember[] {
  return ((memberBaseData ?? []) as ClubMemberBaseRow[]).map((member) => {
    const detail = memberViewById.get(member.user_id);
    const membershipStatus = detail?.membership_status ?? member.membership_status;
    return {
      userId: member.user_id,
      fullName: detail?.full_name ?? null,
      email: detail?.email ?? null,
      role: member.role,
      membershipStatus,
      joinedAt: member.joined_at ?? null,
      tags: [],
      committees: [],
      teams: [],
      attendanceCount: 0,
      totalTrackedEvents: 0,
      attendanceRate: 0,
      lastEngagementAt: null,
      engagementSignalWeak: true,
      likelyInactive: false,
      volunteerHoursTotal: volunteerTotalByUser.get(member.user_id) ?? 0,
      volunteerHourEntries: volunteerEntriesByUser.get(member.user_id) ?? [],
      skillInterestEntries: [],
      availabilitySlots: [],
    };
  });
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

  const now = new Date();
  const nowIso = now.toISOString();
  const sevenDaysAgo = new Date(now);
  sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

  const [
    memberBaseRes,
    membersDataRes,
    tagDefRes,
    committeeRes,
    teamRes,
    announcementsRes,
    activityRes,
    upcomingPastRes,
    pastEventsIdsRes,
  ] = await Promise.all([
    supabase
      .from("club_members")
      .select("user_id, role, membership_status, joined_at")
      .eq("club_id", clubId)
      .order("role", { ascending: false }),
    supabase.rpc("get_club_members_for_view", { target_club_id: clubId }),
    supabase.from("club_member_tags").select("id, name").eq("club_id", clubId).order("name"),
    supabase.from("club_committees").select("id, name").eq("club_id", clubId).order("name"),
    supabase.from("club_teams").select("id, name").eq("club_id", clubId).order("name"),
    supabase
      .from("announcements")
      .select(
        "id, title, content, created_at, poll_question, poll_options, scheduled_for, is_published, is_pinned, pinned_at, is_urgent",
      )
      .eq("club_id", clubId)
      .order("is_pinned", { ascending: false })
      .order("pinned_at", { ascending: false, nullsFirst: false })
      .order("created_at", { ascending: false })
      .limit(10),
    supabase.rpc("get_club_recent_activity", { target_club_id: clubId }),
    Promise.all([
      supabase
        .from("events")
        .select("id, title, description, location, event_type, event_date, capacity, series_id, series_occurrence")
        .eq("club_id", clubId)
        .gte("event_date", nowIso)
        .order("event_date", { ascending: true })
        .limit(100),
      supabase
        .from("events")
        .select("id, title, description, location, event_type, event_date, capacity, series_id, series_occurrence")
        .eq("club_id", clubId)
        .lt("event_date", nowIso)
        .order("event_date", { ascending: false })
        .limit(150),
    ]),
    supabase.from("events").select("id").eq("club_id", clubId).lt("event_date", nowIso),
  ]);

  const memberBaseData = memberBaseRes.data;
  const { data: membersData } = membersDataRes;
  const memberViewById = new Map(
    ((membersData ?? []) as ClubMemberViewRow[]).map((member) => [member.user_id, member]),
  );

  const tagDefError = tagDefRes.error;
  const tagDefRows = tagDefRes.data;
  const safeTagDefs = tagDefError ? [] : (tagDefRows ?? []);
  const tagIdsForClub = safeTagDefs.map((t) => t.id);
  const tagIdToTag = new Map(safeTagDefs.map((t) => [t.id, { id: t.id, name: t.name }]));

  const committeeDefError = committeeRes.error;
  const committeeRows = committeeRes.data;
  const safeCommittees = committeeDefError ? [] : (committeeRows ?? []);
  const committeeIdsForClub = safeCommittees.map((c) => c.id);
  const committeeIdToSummary = new Map(safeCommittees.map((c) => [c.id, { id: c.id, name: c.name }]));

  const teamDefError = teamRes.error;
  const teamRows = teamRes.data;
  const safeTeams = teamDefError ? [] : (teamRows ?? []);
  const teamIdsForClub = safeTeams.map((t) => t.id);
  const teamIdToSummary = new Map(safeTeams.map((t) => [t.id, { id: t.id, name: t.name }]));

  const announcementsData = announcementsRes.data;
  const activityData = activityRes.data;
  const [{ data: upcomingEventsRows }, { data: pastEventsRows }] = upcomingPastRes;
  const pastEventsData = pastEventsIdsRes.data;

  const [{ data: assignRows }, { data: committeeMemberRows }, { data: teamMemberRows }] = await Promise.all([
    tagIdsForClub.length === 0 || tagDefError
      ? Promise.resolve({ data: [] as { user_id: string; tag_id: string }[] })
      : supabase.from("club_member_tag_assignments").select("user_id, tag_id").in("tag_id", tagIdsForClub),
    committeeIdsForClub.length === 0 || committeeDefError
      ? Promise.resolve({ data: [] as { user_id: string; committee_id: string }[] })
      : supabase.from("club_committee_members").select("user_id, committee_id").in("committee_id", committeeIdsForClub),
    teamIdsForClub.length === 0 || teamDefError
      ? Promise.resolve({ data: [] as { user_id: string; team_id: string }[] })
      : supabase.from("club_team_members").select("user_id, team_id").in("team_id", teamIdsForClub),
  ]);

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

  const emptyRsvp = {
    data: [] as {
      event_id: string;
      user_id: string;
      status: EventRsvpStatus;
      created_at: string;
    }[],
  };
  const emptyReflection = {
    data: [] as {
      event_id: string;
      what_worked: string;
      what_didnt: string;
      notes: string | null;
      updated_at: string;
    }[],
  };

  const [rsvpRes, attendanceRes, reflectionRes] = await Promise.all([
    eventIds.length > 0
      ? supabase.from("rsvps").select("event_id, user_id, status, created_at, waitlisted_at").in("event_id", eventIds)
      : Promise.resolve(emptyRsvp),
    eventIds.length > 0
      ? supabase.from("event_attendance").select("event_id, user_id").in("event_id", eventIds)
      : Promise.resolve({ data: [] as { event_id: string; user_id: string }[] }),
    eventIds.length > 0
      ? supabase
          .from("event_reflections")
          .select("event_id, what_worked, what_didnt, notes, updated_at")
          .in("event_id", eventIds)
      : Promise.resolve(emptyReflection),
  ]);

  const rsvpData = rsvpRes.data;
  const attendanceData = attendanceRes.data;
  const reflectionData = reflectionRes.data;

  const mostRecentPastRow = (pastEventsRows ?? [])[0] ?? null;
  const mostRecentPastEventData = mostRecentPastRow
    ? { id: mostRecentPastRow.id, title: mostRecentPastRow.title }
    : null;

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

  const lastEngagementByUserMs = buildLastEngagementByUserMs({
    now,
    events: eventsData.map((e) => ({ id: e.id, event_date: e.event_date })),
    pastAttendance: pastAttendanceData ?? [],
    rsvps: (rsvpData ?? []) as { event_id: string; user_id: string; created_at: string }[],
  });

  const [volunteerHoursFetch, skillInterestFetch, availabilityFetch] = await Promise.all([
    supabase
      .from("club_member_volunteer_hours")
      .select("id, user_id, hours, note, service_date, created_at")
      .eq("club_id", clubId),
    supabase
      .from("club_member_skills_interests")
      .select("id, user_id, kind, label, created_at")
      .eq("club_id", clubId)
      .order("created_at", { ascending: true }),
    supabase
      .from("club_member_availability_slots")
      .select("id, user_id, day_of_week, time_start, time_end, created_at")
      .eq("club_id", clubId),
  ]);

  const volunteerRowsRaw = volunteerHoursFetch.error ? [] : (volunteerHoursFetch.data ?? []);

  const volunteerEntriesByUser = new Map<string, ClubVolunteerHourEntry[]>();
  const volunteerTotalByUser = new Map<string, number>();

  for (const row of volunteerRowsRaw as {
    id: string;
    user_id: string;
    hours: string | number;
    note: string | null;
    service_date: string;
    created_at: string;
  }[]) {
    const h = typeof row.hours === "string" ? Number.parseFloat(row.hours) : Number(row.hours);
    if (!Number.isFinite(h)) continue;
    const entry: ClubVolunteerHourEntry = {
      id: row.id,
      hours: h,
      note: row.note,
      serviceDate: row.service_date,
      createdAt: row.created_at,
    };
    const list = volunteerEntriesByUser.get(row.user_id) ?? [];
    list.push(entry);
    volunteerEntriesByUser.set(row.user_id, list);
    volunteerTotalByUser.set(row.user_id, (volunteerTotalByUser.get(row.user_id) ?? 0) + h);
  }
  for (const list of volunteerEntriesByUser.values()) {
    list.sort((a, b) => {
      if (a.serviceDate !== b.serviceDate) return b.serviceDate.localeCompare(a.serviceDate);
      return b.createdAt.localeCompare(a.createdAt);
    });
  }

  const skillInterestRowsRaw = skillInterestFetch.error ? [] : (skillInterestFetch.data ?? []);

  const skillInterestByUser = new Map<string, ClubMemberSkillInterestEntry[]>();
  for (const row of skillInterestRowsRaw as {
    id: string;
    user_id: string;
    kind: string;
    label: string;
    created_at: string;
  }[]) {
    if (row.kind !== "skill" && row.kind !== "interest") continue;
    const entry: ClubMemberSkillInterestEntry = {
      id: row.id,
      kind: row.kind,
      label: row.label.trim(),
      createdAt: row.created_at,
    };
    const list = skillInterestByUser.get(row.user_id) ?? [];
    list.push(entry);
    skillInterestByUser.set(row.user_id, list);
  }

  const availabilityRowsRaw = availabilityFetch.error ? [] : (availabilityFetch.data ?? []);

  const availabilityByUser = new Map<string, ClubMemberAvailabilitySlot[]>();
  for (const row of availabilityRowsRaw as {
    id: string;
    user_id: string;
    day_of_week: number;
    time_start: string | null;
    time_end: string | null;
    created_at: string;
  }[]) {
    const dow = Number(row.day_of_week);
    if (!Number.isFinite(dow) || dow < 1 || dow > 7) continue;
    const slot: ClubMemberAvailabilitySlot = {
      id: row.id,
      dayOfWeek: dow,
      timeStart: normalizeAvailabilityTime(row.time_start),
      timeEnd: normalizeAvailabilityTime(row.time_end),
      createdAt: row.created_at,
    };
    const list = availabilityByUser.get(row.user_id) ?? [];
    list.push(slot);
    availabilityByUser.set(row.user_id, list);
  }
  for (const list of availabilityByUser.values()) {
    list.sort(compareAvailabilitySlots);
  }

  const membersWithAttendance = ((memberBaseData ?? []) as ClubMemberBaseRow[]).map((member) => {
    const detail = memberViewById.get(member.user_id);
    const attendanceCount = trackedAttendanceByUser.get(member.user_id)?.size ?? 0;
    const attendanceRate = totalTrackedEvents > 0
      ? Math.round((attendanceCount / totalTrackedEvents) * 100)
      : 0;
    const membershipStatus = detail?.membership_status ?? member.membership_status;

    const engagement = computeLikelyInactiveMember({
      membershipStatus,
      joinedAtIso: member.joined_at ?? null,
      totalTrackedEvents,
      lastEngagementMs: lastEngagementByUserMs.get(member.user_id),
      now,
    });

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
      lastEngagementAt: engagement.lastEngagementAt,
      engagementSignalWeak: engagement.engagementSignalWeak,
      likelyInactive: engagement.likelyInactive,
      volunteerHoursTotal: volunteerTotalByUser.get(member.user_id) ?? 0,
      volunteerHourEntries: volunteerEntriesByUser.get(member.user_id) ?? [],
      skillInterestEntries: skillInterestByUser.get(member.user_id) ?? [],
      availabilitySlots: availabilityByUser.get(member.user_id) ?? [],
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
    announcements: (announcementsData ?? []).map((announcement) =>
      mapAnnouncementRow(announcement as AnnouncementSelectRow),
    ),
    memberTagDefinitions: safeTagDefs.map((t) => ({ id: t.id, name: t.name })),
    clubCommittees: safeCommittees.map((c) => ({ id: c.id, name: c.name })),
    clubTeams: safeTeams.map((t) => ({ id: t.id, name: t.name })),
    events: mapEventRowsToClubEvents(
      eventsData as ClubEventRow[],
      user.id,
      (rsvpData ?? []) as { event_id: string; user_id: string; status: EventRsvpStatus; created_at: string; waitlisted_at?: string | null }[],
      attendanceData ?? [],
      reflectionData ?? [],
    ),
  };
}

/**
 * Minimal club payload for the announcements tab only (no roster, events, tags, or activity RPC).
 */
export async function getClubDetailForAnnouncementsForCurrentUser(clubId: string): Promise<ClubDetail | null> {
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

  const [{ data: announcementsData }, { count: activeMemberCount }, readSumRes, pollSumRes] = await Promise.all([
    supabase
      .from("announcements")
      .select(
        "id, title, content, created_at, poll_question, poll_options, scheduled_for, is_published, is_pinned, pinned_at, is_urgent",
      )
      .eq("club_id", clubId)
      .order("is_pinned", { ascending: false })
      .order("pinned_at", { ascending: false, nullsFirst: false })
      .order("created_at", { ascending: false })
      .limit(30),
    supabase
      .from("club_members")
      .select("id", { count: "exact", head: true })
      .eq("club_id", clubId)
      .eq("membership_status", "active"),
    supabase.rpc("get_club_announcement_read_summaries", { p_club_id: clubId }),
    supabase.rpc("get_club_announcement_poll_summaries", { p_club_id: clubId }),
  ]);

  const annRows = announcementsData ?? [];
  const annIds = annRows.map((a) => a.id);

  type AttachRow = {
    id: string;
    announcement_id: string;
    file_url: string;
    file_name: string;
    file_type: string;
  };

  const [myVotesRes, attachRes] =
    annIds.length === 0
      ? [
          { data: [] as { announcement_id: string; option_index: number }[] },
          { data: [] as AttachRow[] },
        ]
      : await Promise.all([
          supabase
            .from("poll_votes")
            .select("announcement_id, option_index")
            .eq("user_id", user.id)
            .in("announcement_id", annIds),
          supabase
            .from("announcement_attachments")
            .select("id, announcement_id, file_url, file_name, file_type")
            .in("announcement_id", annIds)
            .order("created_at", { ascending: true }),
        ]);

  const readByAnn = new Map<string, { readCount: number; memberCount: number }>();
  for (const r of (readSumRes.data ?? []) as {
    announcement_id: string;
    read_count: number;
    member_count: number;
  }[]) {
    readByAnn.set(r.announcement_id, {
      readCount: Number(r.read_count),
      memberCount: Number(r.member_count),
    });
  }

  const pollTalliesByAnn = new Map<string, { optionIndex: number; count: number }[]>();
  for (const pr of (pollSumRes.data ?? []) as {
    announcement_id: string;
    option_index: number;
    vote_count: number;
  }[]) {
    const list = pollTalliesByAnn.get(pr.announcement_id) ?? [];
    list.push({ optionIndex: pr.option_index, count: Number(pr.vote_count) });
    pollTalliesByAnn.set(pr.announcement_id, list);
  }

  const voteByAnn = new Map<string, number>();
  for (const v of myVotesRes.data ?? []) {
    voteByAnn.set(v.announcement_id, v.option_index);
  }

  const attachRows = (attachRes.data ?? []) as AttachRow[];
  const signed = await signAnnouncementAttachmentRows(attachRows);

  const attachmentsByAnn = new Map<string, ClubAnnouncementAttachment[]>();
  for (const ar of attachRows) {
    const url = signed.get(ar.id);
    if (!url) continue;
    const list = attachmentsByAnn.get(ar.announcement_id) ?? [];
    list.push({
      id: ar.id,
      fileName: ar.file_name,
      fileType: ar.file_type,
      signedUrl: url,
    });
    attachmentsByAnn.set(ar.announcement_id, list);
  }

  const lifecycleStatus: ClubStatus = clubRelation.status === "archived" ? "archived" : "active";

  const announcements: ClubAnnouncement[] = annRows.map((row) => {
    const base = mapAnnouncementRow(row as AnnouncementSelectRow);
    const read = readByAnn.get(row.id);
    const tallies = pollTalliesByAnn.get(row.id) ?? [];
    const sortedTallies = [...tallies].sort((a, b) => a.optionIndex - b.optionIndex);
    const totalPollVotes = sortedTallies.reduce((s, t) => s + t.count, 0);
    const hasPoll = Boolean(base.pollQuestion && base.pollOptions && base.pollOptions.length > 0);

    return {
      ...base,
      readCount: read?.readCount ?? 0,
      totalMembers: read?.memberCount ?? activeMemberCount ?? 0,
      pollTallies: hasPoll ? sortedTallies : undefined,
      totalPollVotes: hasPoll ? totalPollVotes : undefined,
      userPollVoteIndex: hasPoll ? (voteByAnn.has(row.id) ? voteByAnn.get(row.id)! : null) : null,
      attachments: attachmentsByAnn.get(row.id),
    };
  });

  return {
    id: clubRelation.id,
    name: clubRelation.name,
    description: clubRelation.description,
    joinCode: clubRelation.join_code,
    requireJoinApproval: Boolean(clubRelation.require_join_approval),
    status: lifecycleStatus,
    currentUserId: user.id,
    currentUserRole: membership.role,
    memberCount: activeMemberCount ?? 0,
    members: [],
    totalTrackedEvents: 0,
    clubAverageAttendance: 0,
    topMembers: [],
    attentionAlerts: [],
    recentActivity: [],
    announcements,
    memberTagDefinitions: [],
    clubCommittees: [],
    clubTeams: [],
    events: [],
  };
}

/**
 * Club payload for events list/history: event graph + light roster for attendance UI only.
 */
export async function getClubDetailForEventsForCurrentUser(clubId: string): Promise<ClubDetail | null> {
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

  const now = new Date();
  const nowIso = now.toISOString();

  const [memberBaseRes, membersDataRes, upcomingPastRes] = await Promise.all([
    supabase
      .from("club_members")
      .select("user_id, role, membership_status, joined_at")
      .eq("club_id", clubId)
      .order("role", { ascending: false }),
    supabase.rpc("get_club_members_for_view", { target_club_id: clubId }),
    Promise.all([
      supabase
        .from("events")
        .select("id, title, description, location, event_type, event_date, capacity, series_id, series_occurrence")
        .eq("club_id", clubId)
        .gte("event_date", nowIso)
        .order("event_date", { ascending: true })
        .limit(100),
      supabase
        .from("events")
        .select("id, title, description, location, event_type, event_date, capacity, series_id, series_occurrence")
        .eq("club_id", clubId)
        .lt("event_date", nowIso)
        .order("event_date", { ascending: false })
        .limit(150),
    ]),
  ]);

  const memberBaseData = memberBaseRes.data;
  const { data: membersData } = membersDataRes;
  const memberViewById = new Map(
    ((membersData ?? []) as ClubMemberViewRow[]).map((member) => [member.user_id, member]),
  );
  const [{ data: upcomingEventsRows }, { data: pastEventsRows }] = upcomingPastRes;

  const eventRowById = new Map<string, ClubEventRow>();
  for (const row of upcomingEventsRows ?? []) {
    eventRowById.set(row.id, row as ClubEventRow);
  }
  for (const row of pastEventsRows ?? []) {
    eventRowById.set(row.id, row as ClubEventRow);
  }
  const eventsData = [...eventRowById.values()];
  const eventIds = eventsData.map((event) => event.id);

  const emptyRsvp = {
    data: [] as {
      event_id: string;
      user_id: string;
      status: EventRsvpStatus;
      created_at: string;
    }[],
  };
  const emptyReflection = {
    data: [] as {
      event_id: string;
      what_worked: string;
      what_didnt: string;
      notes: string | null;
      updated_at: string;
    }[],
  };

  const [rsvpRes, attendanceRes, reflectionRes] = await Promise.all([
    eventIds.length > 0
      ? supabase.from("rsvps").select("event_id, user_id, status, created_at, waitlisted_at").in("event_id", eventIds)
      : Promise.resolve(emptyRsvp),
    eventIds.length > 0
      ? supabase.from("event_attendance").select("event_id, user_id").in("event_id", eventIds)
      : Promise.resolve({ data: [] as { event_id: string; user_id: string }[] }),
    eventIds.length > 0
      ? supabase
          .from("event_reflections")
          .select("event_id, what_worked, what_didnt, notes, updated_at")
          .in("event_id", eventIds)
      : Promise.resolve(emptyReflection),
  ]);

  const memberCount = ((memberBaseData ?? []) as ClubMemberBaseRow[]).filter(
    (m) => m.membership_status === "active",
  ).length;
  const members = buildLightMembersForEventUi(memberBaseData, memberViewById);
  const lifecycleStatus: ClubStatus = clubRelation.status === "archived" ? "archived" : "active";

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
    members,
    totalTrackedEvents: 0,
    clubAverageAttendance: 0,
    topMembers: [],
    attentionAlerts: [],
    recentActivity: [],
    announcements: [],
    memberTagDefinitions: [],
    clubCommittees: [],
    clubTeams: [],
    events: mapEventRowsToClubEvents(
      eventsData,
      user.id,
      (rsvpRes.data ?? []) as { event_id: string; user_id: string; status: EventRsvpStatus; created_at: string; waitlisted_at?: string | null }[],
      attendanceRes.data ?? [],
      reflectionRes.data ?? [],
    ),
  };
}

/**
 * Club overview: activity feed, attention alerts, next event, announcements, and aggregate stats.
 * Skips roster enrichment (tags, committees, volunteer, skills, availability) and `get_club_members_for_view`.
 */
export async function getClubDetailForOverviewForCurrentUser(clubId: string): Promise<ClubDetail | null> {
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

  const now = new Date();
  const nowIso = now.toISOString();
  const sevenDaysAgo = new Date(now);
  sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

  const [memberBaseRes, announcementsRes, activityRes, upcomingPastRes, pastEventsIdsRes] = await Promise.all([
    supabase
      .from("club_members")
      .select("user_id, role, membership_status, joined_at")
      .eq("club_id", clubId)
      .order("role", { ascending: false }),
    supabase
      .from("announcements")
      .select(
        "id, title, content, created_at, poll_question, poll_options, scheduled_for, is_published, is_pinned, pinned_at, is_urgent",
      )
      .eq("club_id", clubId)
      .order("is_pinned", { ascending: false })
      .order("pinned_at", { ascending: false, nullsFirst: false })
      .order("created_at", { ascending: false })
      .limit(10),
    supabase.rpc("get_club_recent_activity", { target_club_id: clubId }),
    Promise.all([
      supabase
        .from("events")
        .select("id, title, description, location, event_type, event_date, capacity, series_id, series_occurrence")
        .eq("club_id", clubId)
        .gte("event_date", nowIso)
        .order("event_date", { ascending: true })
        .limit(100),
      supabase
        .from("events")
        .select("id, title, description, location, event_type, event_date, capacity, series_id, series_occurrence")
        .eq("club_id", clubId)
        .lt("event_date", nowIso)
        .order("event_date", { ascending: false })
        .limit(150),
    ]),
    supabase.from("events").select("id").eq("club_id", clubId).lt("event_date", nowIso),
  ]);

  const memberBaseData = memberBaseRes.data;
  const announcementsData = announcementsRes.data;
  const activityData = activityRes.data;
  const [{ data: upcomingEventsRows }, { data: pastEventsRows }] = upcomingPastRes;
  const pastEventsData = pastEventsIdsRes.data;

  const eventRowById = new Map<string, ClubEventRow>();
  for (const row of upcomingEventsRows ?? []) {
    eventRowById.set(row.id, row as ClubEventRow);
  }
  for (const row of pastEventsRows ?? []) {
    eventRowById.set(row.id, row as ClubEventRow);
  }
  const eventsData = [...eventRowById.values()];
  const eventIds = eventsData.map((event) => event.id);

  const emptyRsvp = {
    data: [] as {
      event_id: string;
      user_id: string;
      status: EventRsvpStatus;
      created_at: string;
    }[],
  };
  const emptyReflection = {
    data: [] as {
      event_id: string;
      what_worked: string;
      what_didnt: string;
      notes: string | null;
      updated_at: string;
    }[],
  };

  const pastEventIds = (pastEventsData ?? []).map((event) => event.id);

  const [rsvpRes, attendanceRes, reflectionRes, pastAttendanceRes] = await Promise.all([
    eventIds.length > 0
      ? supabase.from("rsvps").select("event_id, user_id, status, created_at, waitlisted_at").in("event_id", eventIds)
      : Promise.resolve(emptyRsvp),
    eventIds.length > 0
      ? supabase.from("event_attendance").select("event_id, user_id").in("event_id", eventIds)
      : Promise.resolve({ data: [] as { event_id: string; user_id: string }[] }),
    eventIds.length > 0
      ? supabase
          .from("event_reflections")
          .select("event_id, what_worked, what_didnt, notes, updated_at")
          .in("event_id", eventIds)
      : Promise.resolve(emptyReflection),
    pastEventIds.length > 0
      ? supabase.from("event_attendance").select("event_id, user_id").in("event_id", pastEventIds)
      : Promise.resolve({ data: [] as { event_id: string; user_id: string }[] }),
  ]);

  const rsvpData = rsvpRes.data;
  const attendanceData = attendanceRes.data;
  const reflectionData = reflectionRes.data;
  const pastAttendanceData = pastAttendanceRes.data;

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

  const memberCount = ((memberBaseData ?? []) as ClubMemberBaseRow[]).filter(
    (m) => m.membership_status === "active",
  ).length;

  const activeMemberRows = ((memberBaseData ?? []) as ClubMemberBaseRow[]).filter(
    (m) => m.membership_status === "active",
  );
  const sumAttendanceCounts = activeMemberRows.reduce(
    (sum, m) => sum + (trackedAttendanceByUser.get(m.user_id)?.size ?? 0),
    0,
  );
  const clubAverageAttendance =
    totalTrackedEvents > 0 && activeMemberRows.length > 0
      ? Math.round((sumAttendanceCounts / (totalTrackedEvents * activeMemberRows.length)) * 100)
      : 0;

  const firstUpcoming = (upcomingEventsRows ?? [])[0] ?? null;
  const nextUpcomingEventData = firstUpcoming
    ? { id: firstUpcoming.id, title: firstUpcoming.title, event_date: firstUpcoming.event_date }
    : null;
  const mostRecentPastRow = (pastEventsRows ?? [])[0] ?? null;
  const mostRecentPastEventData = mostRecentPastRow
    ? { id: mostRecentPastRow.id, title: mostRecentPastRow.title }
    : null;

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
    nextEventResponseCount: nextUpcomingEvent
      ? (rsvpData ?? []).filter((rsvp) => rsvp.event_id === nextUpcomingEvent.id).length
      : 0,
    latestAnnouncementCreatedAt: latestAnnouncementData?.created_at ?? null,
    hasAnnouncement: Boolean(latestAnnouncementData),
    mostRecentPastEvent: mostRecentPastEventData,
    latestPastEventHasTrackedAttendance: mostRecentPastEventData
      ? trackedEventIds.has(mostRecentPastEventData.id)
      : true,
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

  const lifecycleStatus: ClubStatus = clubRelation.status === "archived" ? "archived" : "active";

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
    members: [],
    totalTrackedEvents,
    clubAverageAttendance,
    topMembers: [],
    attentionAlerts,
    recentActivity: ((activityData ?? []) as ClubActivityRow[]).map((item) => ({
      id: item.id,
      kind: item.kind,
      message: item.message,
      createdAt: new Date(item.created_at).toLocaleString(),
      createdAtIso: item.created_at,
    })),
    announcements: (announcementsData ?? []).map((announcement) =>
      mapAnnouncementRow(announcement as AnnouncementSelectRow),
    ),
    memberTagDefinitions: [],
    clubCommittees: [],
    clubTeams: [],
    events: mapEventRowsToClubEvents(
      eventsData as ClubEventRow[],
      user.id,
      (rsvpData ?? []) as { event_id: string; user_id: string; status: EventRsvpStatus; created_at: string; waitlisted_at?: string | null }[],
      attendanceData ?? [],
      reflectionData ?? [],
    ),
  };
}

/**
 * Insights tab: attendance trends and engagement segments without announcements, activity RPC, tags, or volunteer data.
 */
export async function getClubDetailForInsightsForCurrentUser(clubId: string): Promise<ClubDetail | null> {
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

  const now = new Date();
  const nowIso = now.toISOString();

  const [memberBaseRes, membersDataRes, upcomingPastRes, pastEventsIdsRes] = await Promise.all([
    supabase
      .from("club_members")
      .select("user_id, role, membership_status, joined_at")
      .eq("club_id", clubId)
      .order("role", { ascending: false }),
    supabase.rpc("get_club_members_for_view", { target_club_id: clubId }),
    Promise.all([
      supabase
        .from("events")
        .select("id, title, description, location, event_type, event_date, capacity, series_id, series_occurrence")
        .eq("club_id", clubId)
        .gte("event_date", nowIso)
        .order("event_date", { ascending: true })
        .limit(100),
      supabase
        .from("events")
        .select("id, title, description, location, event_type, event_date, capacity, series_id, series_occurrence")
        .eq("club_id", clubId)
        .lt("event_date", nowIso)
        .order("event_date", { ascending: false })
        .limit(150),
    ]),
    supabase.from("events").select("id").eq("club_id", clubId).lt("event_date", nowIso),
  ]);

  const memberBaseData = memberBaseRes.data;
  const { data: membersData } = membersDataRes;
  const memberViewById = new Map(
    ((membersData ?? []) as ClubMemberViewRow[]).map((member) => [member.user_id, member]),
  );
  const [{ data: upcomingEventsRows }, { data: pastEventsRows }] = upcomingPastRes;
  const pastEventsData = pastEventsIdsRes.data;

  const eventRowById = new Map<string, ClubEventRow>();
  for (const row of upcomingEventsRows ?? []) {
    eventRowById.set(row.id, row as ClubEventRow);
  }
  for (const row of pastEventsRows ?? []) {
    eventRowById.set(row.id, row as ClubEventRow);
  }
  const eventsData = [...eventRowById.values()];
  const eventIds = eventsData.map((event) => event.id);

  const emptyRsvp = {
    data: [] as {
      event_id: string;
      user_id: string;
      status: EventRsvpStatus;
      created_at: string;
    }[],
  };
  const emptyReflection = {
    data: [] as {
      event_id: string;
      what_worked: string;
      what_didnt: string;
      notes: string | null;
      updated_at: string;
    }[],
  };

  const pastEventIds = (pastEventsData ?? []).map((event) => event.id);

  const [rsvpRes, attendanceRes, pastAttendanceRes] = await Promise.all([
    eventIds.length > 0
      ? supabase.from("rsvps").select("event_id, user_id, status, created_at, waitlisted_at").in("event_id", eventIds)
      : Promise.resolve(emptyRsvp),
    eventIds.length > 0
      ? supabase.from("event_attendance").select("event_id, user_id").in("event_id", eventIds)
      : Promise.resolve({ data: [] as { event_id: string; user_id: string }[] }),
    pastEventIds.length > 0
      ? supabase.from("event_attendance").select("event_id, user_id").in("event_id", pastEventIds)
      : Promise.resolve({ data: [] as { event_id: string; user_id: string }[] }),
  ]);

  const rsvpData = rsvpRes.data;
  const attendanceData = attendanceRes.data;
  const pastAttendanceData = pastAttendanceRes.data;

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

  const lastEngagementByUserMs = buildLastEngagementByUserMs({
    now,
    events: eventsData.map((e) => ({ id: e.id, event_date: e.event_date })),
    pastAttendance: pastAttendanceData ?? [],
    rsvps: (rsvpData ?? []) as { event_id: string; user_id: string; created_at: string }[],
  });

  const membersWithAttendance = buildMembersWithAttendanceInsightsOnly(
    memberBaseData,
    memberViewById,
    trackedAttendanceByUser,
    totalTrackedEvents,
    lastEngagementByUserMs,
    now,
  );

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

  const lifecycleStatus: ClubStatus = clubRelation.status === "archived" ? "archived" : "active";

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
    attentionAlerts: [],
    recentActivity: [],
    announcements: [],
    memberTagDefinitions: [],
    clubCommittees: [],
    clubTeams: [],
    events: mapEventRowsToClubEvents(
      eventsData as ClubEventRow[],
      user.id,
      (rsvpData ?? []) as { event_id: string; user_id: string; status: EventRsvpStatus; created_at: string; waitlisted_at?: string | null }[],
      attendanceData ?? [],
      emptyReflection.data,
    ),
  };
}

/**
 * Volunteer hours tab: roster display names + volunteer entries only.
 */
export async function getClubDetailForVolunteerHoursForCurrentUser(clubId: string): Promise<ClubDetail | null> {
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

  const [memberBaseRes, membersDataRes, volunteerHoursFetch] = await Promise.all([
    supabase
      .from("club_members")
      .select("user_id, role, membership_status, joined_at")
      .eq("club_id", clubId)
      .order("role", { ascending: false }),
    supabase.rpc("get_club_members_for_view", { target_club_id: clubId }),
    supabase
      .from("club_member_volunteer_hours")
      .select("id, user_id, hours, note, service_date, created_at")
      .eq("club_id", clubId),
  ]);

  const memberBaseData = memberBaseRes.data;
  const { data: membersData } = membersDataRes;
  const memberViewById = new Map(
    ((membersData ?? []) as ClubMemberViewRow[]).map((member) => [member.user_id, member]),
  );

  const volunteerRowsRaw = volunteerHoursFetch.error ? [] : (volunteerHoursFetch.data ?? []);
  const volunteerEntriesByUser = new Map<string, ClubVolunteerHourEntry[]>();
  const volunteerTotalByUser = new Map<string, number>();

  for (const row of volunteerRowsRaw as {
    id: string;
    user_id: string;
    hours: string | number;
    note: string | null;
    service_date: string;
    created_at: string;
  }[]) {
    const h = typeof row.hours === "string" ? Number.parseFloat(row.hours) : Number(row.hours);
    if (!Number.isFinite(h)) continue;
    const entry: ClubVolunteerHourEntry = {
      id: row.id,
      hours: h,
      note: row.note,
      serviceDate: row.service_date,
      createdAt: row.created_at,
    };
    const list = volunteerEntriesByUser.get(row.user_id) ?? [];
    list.push(entry);
    volunteerEntriesByUser.set(row.user_id, list);
    volunteerTotalByUser.set(row.user_id, (volunteerTotalByUser.get(row.user_id) ?? 0) + h);
  }
  for (const list of volunteerEntriesByUser.values()) {
    list.sort((a, b) => {
      if (a.serviceDate !== b.serviceDate) return b.serviceDate.localeCompare(a.serviceDate);
      return b.createdAt.localeCompare(a.createdAt);
    });
  }

  const members = buildMembersVolunteerOnly(memberBaseData, memberViewById, volunteerEntriesByUser, volunteerTotalByUser);
  const memberCount = ((memberBaseData ?? []) as ClubMemberBaseRow[]).filter(
    (m) => m.membership_status === "active",
  ).length;
  const lifecycleStatus: ClubStatus = clubRelation.status === "archived" ? "archived" : "active";

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
    members,
    totalTrackedEvents: 0,
    clubAverageAttendance: 0,
    topMembers: [],
    attentionAlerts: [],
    recentActivity: [],
    announcements: [],
    memberTagDefinitions: [],
    clubCommittees: [],
    clubTeams: [],
    events: [],
  };
}

/** Set `CLUBHUB_PROFILE_MEMBERS_ROSTER=1` to log server timings for `getClubDetailForMembersRosterForCurrentUser`. */
function membersRosterProfilingEnabled(): boolean {
  const v = process.env.CLUBHUB_PROFILE_MEMBERS_ROSTER?.trim();
  return v === "1" || v?.toLowerCase() === "true";
}

function membersRosterProfileNow(): number {
  return typeof performance !== "undefined" && typeof performance.now === "function"
    ? performance.now()
    : Date.now();
}

function membersRosterProfileLog(
  label: string,
  startedAt: number,
  extra?: Record<string, string | number | boolean | null | undefined>,
) {
  if (!membersRosterProfilingEnabled()) return;
  const ms = membersRosterProfileNow() - startedAt;
  const parts = [`step=${label}`, `ms=${Math.round(ms * 10) / 10}`];
  if (extra) {
    for (const [k, val] of Object.entries(extra)) {
      if (val === undefined) continue;
      parts.push(`${k}=${String(val)}`);
    }
  }
  console.log(`[clubhub:members-roster-profile] ${parts.join(" ")}`);
}

/**
 * Members tab: full per-member roster graph (tags, committees, teams, volunteer, skills, availability,
 * attendance, engagement) without loading announcement bodies, activity RPC, full event cards, reflections,
 * or per-event attendance rows used only for event UI.
 */
export async function getClubDetailForMembersRosterForCurrentUser(clubId: string): Promise<ClubDetail | null> {
  noStore();

  const profileRoot = membersRosterProfileNow();
  const supabase = await createClient();
  let t = membersRosterProfileNow();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  membersRosterProfileLog("auth_getUser", t);

  if (!user) {
    return null;
  }

  t = membersRosterProfileNow();
  const { data: membership, error: membershipError } = await supabase
    .from("club_members")
    .select("role, clubs(id, name, description, join_code, status, require_join_approval)")
    .eq("club_id", clubId)
    .eq("user_id", user.id)
    .maybeSingle();
  membersRosterProfileLog("membership_and_club_row", t);

  if (membershipError || !membership?.clubs) {
    return null;
  }

  const clubRelation = normalizeClubRelation(membership.clubs);
  if (!clubRelation) {
    return null;
  }

  const now = new Date();
  const nowIso = now.toISOString();

  t = membersRosterProfileNow();
  const [
    memberBaseRes,
    membersDataRes,
    tagDefRes,
    committeeRes,
    teamRes,
    announcementCountRes,
    eventsCountRes,
    upcomingPastSlimRes,
    pastEventsIdsRes,
  ] = await Promise.all([
    supabase
      .from("club_members")
      .select("user_id, role, membership_status, joined_at")
      .eq("club_id", clubId)
      .order("role", { ascending: false }),
    supabase.rpc("get_club_members_for_view", { target_club_id: clubId }),
    supabase.from("club_member_tags").select("id, name").eq("club_id", clubId).order("name"),
    supabase.from("club_committees").select("id, name").eq("club_id", clubId).order("name"),
    supabase.from("club_teams").select("id, name").eq("club_id", clubId).order("name"),
    supabase
      .from("announcements")
      .select("id", { count: "exact", head: true })
      .eq("club_id", clubId),
    supabase.from("events").select("id", { count: "exact", head: true }).eq("club_id", clubId),
    Promise.all([
      supabase
        .from("events")
        .select("id, event_date")
        .eq("club_id", clubId)
        .gte("event_date", nowIso)
        .order("event_date", { ascending: true })
        .limit(100),
      supabase
        .from("events")
        .select("id, event_date")
        .eq("club_id", clubId)
        .lt("event_date", nowIso)
        .order("event_date", { ascending: false })
        .limit(150),
    ]),
    supabase.from("events").select("id").eq("club_id", clubId).lt("event_date", nowIso),
  ]);

  membersRosterProfileLog("wave1_parallel_9", t, {
    clubId,
    memberBaseN: memberBaseRes.data?.length ?? 0,
    memberViewRpcN: ((membersDataRes.data ?? []) as unknown[]).length,
    tagDefN: tagDefRes.data?.length ?? 0,
    committeeN: committeeRes.data?.length ?? 0,
    teamN: teamRes.data?.length ?? 0,
    pastEventIdsN: pastEventsIdsRes.data?.length ?? 0,
  });

  const memberBaseData = memberBaseRes.data;
  const { data: membersData } = membersDataRes;
  const memberViewById = new Map(
    ((membersData ?? []) as ClubMemberViewRow[]).map((member) => [member.user_id, member]),
  );

  const tagDefError = tagDefRes.error;
  const tagDefRows = tagDefRes.data;
  const safeTagDefs = tagDefError ? [] : (tagDefRows ?? []);
  const tagIdsForClub = safeTagDefs.map((t) => t.id);
  const tagIdToTag = new Map(safeTagDefs.map((t) => [t.id, { id: t.id, name: t.name }]));

  const committeeDefError = committeeRes.error;
  const committeeRows = committeeRes.data;
  const safeCommittees = committeeDefError ? [] : (committeeRows ?? []);
  const committeeIdsForClub = safeCommittees.map((c) => c.id);
  const committeeIdToSummary = new Map(safeCommittees.map((c) => [c.id, { id: c.id, name: c.name }]));

  const teamDefError = teamRes.error;
  const teamRows = teamRes.data;
  const safeTeams = teamDefError ? [] : (teamRows ?? []);
  const teamIdsForClub = safeTeams.map((t) => t.id);
  const teamIdToSummary = new Map(safeTeams.map((t) => [t.id, { id: t.id, name: t.name }]));

  const [{ data: upcomingSlim }, { data: pastSlim }] = upcomingPastSlimRes;
  const pastEventsData = pastEventsIdsRes.data;

  const engagementEventMetaById = new Map<string, { id: string; event_date: string }>();
  for (const row of upcomingSlim ?? []) {
    engagementEventMetaById.set(row.id, { id: row.id, event_date: row.event_date });
  }
  for (const row of pastSlim ?? []) {
    engagementEventMetaById.set(row.id, { id: row.id, event_date: row.event_date });
  }
  const engagementEventMetas = [...engagementEventMetaById.values()];
  const engagementEventIds = engagementEventMetas.map((e) => e.id);
  const pastEventIds = (pastEventsData ?? []).map((event) => event.id);

  const emptyRsvp = {
    data: [] as {
      event_id: string;
      user_id: string;
      status: EventRsvpStatus;
      created_at: string;
    }[],
  };

  t = membersRosterProfileNow();
  const [
    [{ data: assignRows }, { data: committeeMemberRows }, { data: teamMemberRows }],
    [rsvpRes, pastAttendanceRes, volunteerHoursFetch, skillInterestFetch, availabilityFetch],
  ] = await Promise.all([
    Promise.all([
      tagIdsForClub.length === 0 || tagDefError
        ? Promise.resolve({ data: [] as { user_id: string; tag_id: string }[] })
        : supabase.from("club_member_tag_assignments").select("user_id, tag_id").in("tag_id", tagIdsForClub),
      committeeIdsForClub.length === 0 || committeeDefError
        ? Promise.resolve({ data: [] as { user_id: string; committee_id: string }[] })
        : supabase
            .from("club_committee_members")
            .select("user_id, committee_id")
            .in("committee_id", committeeIdsForClub),
      teamIdsForClub.length === 0 || teamDefError
        ? Promise.resolve({ data: [] as { user_id: string; team_id: string }[] })
        : supabase.from("club_team_members").select("user_id, team_id").in("team_id", teamIdsForClub),
    ]),
    Promise.all([
      engagementEventIds.length > 0
        ? supabase
            .from("rsvps")
            .select("event_id, user_id, status, created_at, waitlisted_at")
            .in("event_id", engagementEventIds)
        : Promise.resolve(emptyRsvp),
      pastEventIds.length > 0
        ? supabase.from("event_attendance").select("event_id, user_id").in("event_id", pastEventIds)
        : Promise.resolve({ data: [] as { event_id: string; user_id: string }[] }),
      supabase
        .from("club_member_volunteer_hours")
        .select("id, user_id, hours, note, service_date, created_at")
        .eq("club_id", clubId),
      supabase
        .from("club_member_skills_interests")
        .select("id, user_id, kind, label, created_at")
        .eq("club_id", clubId)
        .order("created_at", { ascending: true }),
      supabase
        .from("club_member_availability_slots")
        .select("id, user_id, day_of_week, time_start, time_end, created_at")
        .eq("club_id", clubId),
    ]),
  ]);

  const rsvpData = rsvpRes.data;
  const pastAttendanceData = pastAttendanceRes.data;

  membersRosterProfileLog("wave2_assignments_and_wave3_heavy_parallel", t, {
    clubId,
    engagementEventN: engagementEventIds.length,
    pastEventIdsN: pastEventIds.length,
    assignN: (assignRows ?? []).length,
    rsvpN: (rsvpData ?? []).length,
    pastAttN: (pastAttendanceData ?? []).length,
  });

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

  const teamsByUserId = new Map<string, ClubTeamSummary[]>();
  for (const row of teamMemberRows ?? []) {
    const teamSummary = teamIdToSummary.get(row.team_id);
    if (!teamSummary) continue;
    const list = teamsByUserId.get(row.user_id) ?? [];
    list.push(teamSummary);
    teamsByUserId.set(row.user_id, list);
  }
  for (const list of teamsByUserId.values()) {
    list.sort((a, b) => a.name.localeCompare(b.name));
  }

  t = membersRosterProfileNow();
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

  const lastEngagementByUserMs = buildLastEngagementByUserMs({
    now,
    events: engagementEventMetas,
    pastAttendance: pastAttendanceData ?? [],
    rsvps: (rsvpData ?? []) as { event_id: string; user_id: string; created_at: string }[],
  });

  const volunteerRowsRaw = volunteerHoursFetch.error ? [] : (volunteerHoursFetch.data ?? []);

  const volunteerEntriesByUser = new Map<string, ClubVolunteerHourEntry[]>();
  const volunteerTotalByUser = new Map<string, number>();

  for (const row of volunteerRowsRaw as {
    id: string;
    user_id: string;
    hours: string | number;
    note: string | null;
    service_date: string;
    created_at: string;
  }[]) {
    const h = typeof row.hours === "string" ? Number.parseFloat(row.hours) : Number(row.hours);
    if (!Number.isFinite(h)) continue;
    const entry: ClubVolunteerHourEntry = {
      id: row.id,
      hours: h,
      note: row.note,
      serviceDate: row.service_date,
      createdAt: row.created_at,
    };
    const list = volunteerEntriesByUser.get(row.user_id) ?? [];
    list.push(entry);
    volunteerEntriesByUser.set(row.user_id, list);
    volunteerTotalByUser.set(row.user_id, (volunteerTotalByUser.get(row.user_id) ?? 0) + h);
  }
  for (const list of volunteerEntriesByUser.values()) {
    list.sort((a, b) => {
      if (a.serviceDate !== b.serviceDate) return b.serviceDate.localeCompare(a.serviceDate);
      return b.createdAt.localeCompare(a.createdAt);
    });
  }

  const skillInterestRowsRaw = skillInterestFetch.error ? [] : (skillInterestFetch.data ?? []);

  const skillInterestByUser = new Map<string, ClubMemberSkillInterestEntry[]>();
  for (const row of skillInterestRowsRaw as {
    id: string;
    user_id: string;
    kind: string;
    label: string;
    created_at: string;
  }[]) {
    if (row.kind !== "skill" && row.kind !== "interest") continue;
    const entry: ClubMemberSkillInterestEntry = {
      id: row.id,
      kind: row.kind,
      label: row.label.trim(),
      createdAt: row.created_at,
    };
    const list = skillInterestByUser.get(row.user_id) ?? [];
    list.push(entry);
    skillInterestByUser.set(row.user_id, list);
  }

  const availabilityRowsRaw = availabilityFetch.error ? [] : (availabilityFetch.data ?? []);

  const availabilityByUser = new Map<string, ClubMemberAvailabilitySlot[]>();
  for (const row of availabilityRowsRaw as {
    id: string;
    user_id: string;
    day_of_week: number;
    time_start: string | null;
    time_end: string | null;
    created_at: string;
  }[]) {
    const dow = Number(row.day_of_week);
    if (!Number.isFinite(dow) || dow < 1 || dow > 7) continue;
    const slot: ClubMemberAvailabilitySlot = {
      id: row.id,
      dayOfWeek: dow,
      timeStart: normalizeAvailabilityTime(row.time_start),
      timeEnd: normalizeAvailabilityTime(row.time_end),
      createdAt: row.created_at,
    };
    const list = availabilityByUser.get(row.user_id) ?? [];
    list.push(slot);
    availabilityByUser.set(row.user_id, list);
  }
  for (const list of availabilityByUser.values()) {
    list.sort(compareAvailabilitySlots);
  }

  membersRosterProfileLog("sync_maps_and_derived", t, {
    clubId,
    volunteerRowN: volunteerRowsRaw.length,
    skillInterestN: skillInterestRowsRaw.length,
    availabilityUserN: availabilityByUser.size,
  });

  const buildMembersAt = membersRosterProfileNow();
  const membersWithAttendance = ((memberBaseData ?? []) as ClubMemberBaseRow[]).map((member) => {
    const detail = memberViewById.get(member.user_id);
    const attendanceCount = trackedAttendanceByUser.get(member.user_id)?.size ?? 0;
    const attendanceRate =
      totalTrackedEvents > 0 ? Math.round((attendanceCount / totalTrackedEvents) * 100) : 0;
    const membershipStatus = detail?.membership_status ?? member.membership_status;

    const engagement = computeLikelyInactiveMember({
      membershipStatus,
      joinedAtIso: member.joined_at ?? null,
      totalTrackedEvents,
      lastEngagementMs: lastEngagementByUserMs.get(member.user_id),
      now,
    });

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
      lastEngagementAt: engagement.lastEngagementAt,
      engagementSignalWeak: engagement.engagementSignalWeak,
      likelyInactive: engagement.likelyInactive,
      volunteerHoursTotal: volunteerTotalByUser.get(member.user_id) ?? 0,
      volunteerHourEntries: volunteerEntriesByUser.get(member.user_id) ?? [],
      skillInterestEntries: skillInterestByUser.get(member.user_id) ?? [],
      availabilitySlots: availabilityByUser.get(member.user_id) ?? [],
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

  const memberCount = ((memberBaseData ?? []) as ClubMemberBaseRow[]).filter(
    (m) => m.membership_status === "active",
  ).length;

  const lifecycleStatus: ClubStatus = clubRelation.status === "archived" ? "archived" : "active";

  membersRosterProfileLog("build_member_rows_and_averages", buildMembersAt, {
    clubId,
    rosterMemberN: membersWithAttendance.length,
  });
  membersRosterProfileLog("total_members_roster", profileRoot, {
    clubId,
    rosterMemberN: membersWithAttendance.length,
  });

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
    topMembers: [],
    attentionAlerts: [],
    recentActivity: [],
    announcements: [],
    events: [],
    rosterAnnouncementsCount: announcementCountRes.count ?? 0,
    rosterEventsCount: eventsCountRes.count ?? 0,
    memberTagDefinitions: safeTagDefs.map((t) => ({ id: t.id, name: t.name })),
    clubCommittees: safeCommittees.map((c) => ({ id: c.id, name: c.name })),
    clubTeams: safeTeams.map((t) => ({ id: t.id, name: t.name })),
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

/**
 * Leadership-only: internal officer notes for roster members in this club.
 * RLS returns no rows if the current user is not authorized — do not merge into `ClubDetail` / `ClubMember`.
 */
export async function fetchClubMemberOfficerNotesMap(clubId: string): Promise<Record<string, string>> {
  noStore();

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    return {};
  }

  const { data, error } = await supabase
    .from("club_member_officer_notes")
    .select("user_id, body")
    .eq("club_id", clubId);

  if (error || !data) {
    return {};
  }

  const map: Record<string, string> = {};
  for (const row of data as { user_id: string; body: string }[]) {
    map[row.user_id] = row.body ?? "";
  }
  return map;
}

export type ClubMemberDuesStatus = "unpaid" | "paid" | "partial" | "exempt" | "waived";

export type ClubMemberDuesRecord = {
  status: ClubMemberDuesStatus;
  notes: string;
  updatedAt: string | null;
};

/** Club-wide dues term (one row per club). Leadership-only via RLS. */
export type ClubDuesSettings = {
  clubId: string;
  label: string;
  amountCents: number;
  /** `YYYY-MM-DD` from Postgres `date` */
  dueDate: string;
  currency: string;
  updatedAt: string | null;
};

/**
 * Leadership-only: current club dues term. RLS returns no row when unauthorized.
 */
export async function fetchClubDuesSettings(clubId: string): Promise<ClubDuesSettings | null> {
  noStore();

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    return null;
  }

  const { data, error } = await supabase
    .from("club_dues_settings")
    .select("club_id, label, amount_cents, due_date, currency, updated_at")
    .eq("club_id", clubId)
    .maybeSingle();

  if (error || !data) {
    return null;
  }

  const row = data as {
    club_id: string;
    label: string;
    amount_cents: number;
    due_date: string;
    currency: string;
    updated_at: string | null;
  };

  return {
    clubId: row.club_id,
    label: row.label ?? "",
    amountCents: typeof row.amount_cents === "number" ? row.amount_cents : 0,
    dueDate: typeof row.due_date === "string" ? row.due_date : String(row.due_date ?? ""),
    currency: row.currency ?? "USD",
    updatedAt: row.updated_at ?? null,
  };
}

/**
 * Leadership-only: per-member dues status. RLS returns no rows when unauthorized — do not merge into `ClubMember` / roster export.
 */
export async function fetchClubMemberDuesMap(clubId: string): Promise<Record<string, ClubMemberDuesRecord>> {
  noStore();

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    return {};
  }

  const { data, error } = await supabase
    .from("club_member_dues")
    .select("user_id, status, notes, updated_at")
    .eq("club_id", clubId);

  if (error || !data) {
    return {};
  }

  const valid: ClubMemberDuesStatus[] = ["unpaid", "paid", "partial", "exempt", "waived"];
  const map: Record<string, ClubMemberDuesRecord> = {};
  for (const row of data as { user_id: string; status: string; notes: string; updated_at: string | null }[]) {
    if (!valid.includes(row.status as ClubMemberDuesStatus)) continue;
    map[row.user_id] = {
      status: row.status as ClubMemberDuesStatus,
      notes: row.notes ?? "",
      updatedAt: row.updated_at ?? null,
    };
  }
  return map;
}

/** One row per event where this member appears in `event_attendance` (marked present). */
export type ClubMemberAttendanceHistoryEntry = {
  eventId: string;
  title: string;
  /** ISO instant from `events.event_date` */
  eventDateIso: string;
  /** When attendance was recorded, if returned by the API */
  markedAtIso: string | null;
};

/**
 * Past events in this club + attendance rows, grouped by member.
 * RLS on `events` / `event_attendance` applies.
 * Pass `onlyUserIds` to limit rows returned (privacy — regular members should only load their own history).
 */
export async function fetchClubAttendanceHistoryByUserMap(
  clubId: string,
  options?: { onlyUserIds?: string[] },
): Promise<Record<string, ClubMemberAttendanceHistoryEntry[]>> {
  noStore();

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    return {};
  }

  const nowIso = new Date().toISOString();

  const { data: pastEvents, error: pastError } = await supabase
    .from("events")
    .select("id, title, event_date")
    .eq("club_id", clubId)
    .lt("event_date", nowIso)
    .order("event_date", { ascending: false });

  if (pastError || !pastEvents?.length) {
    return {};
  }

  const eventById = new Map(
    (pastEvents as { id: string; title: string; event_date: string }[]).map((e) => [e.id, e]),
  );
  const pastEventIds = pastEvents.map((e) => e.id);

  const onlyUserIds = options?.onlyUserIds;
  let attendanceQuery = supabase
    .from("event_attendance")
    .select("event_id, user_id, marked_at")
    .in("event_id", pastEventIds);

  if (onlyUserIds !== undefined) {
    if (onlyUserIds.length === 0) {
      return {};
    }
    attendanceQuery = attendanceQuery.in("user_id", onlyUserIds);
  }

  const { data: attendanceRows, error: attError } = await attendanceQuery;

  if (attError || !attendanceRows?.length) {
    return {};
  }

  const historyByUser = new Map<string, ClubMemberAttendanceHistoryEntry[]>();

  for (const row of attendanceRows as { event_id: string; user_id: string; marked_at: string | null }[]) {
    const ev = eventById.get(row.event_id);
    if (!ev) continue;

    const entry: ClubMemberAttendanceHistoryEntry = {
      eventId: row.event_id,
      title: ev.title,
      eventDateIso: ev.event_date,
      markedAtIso: row.marked_at ?? null,
    };
    const list = historyByUser.get(row.user_id) ?? [];
    list.push(entry);
    historyByUser.set(row.user_id, list);
  }

  const result: Record<string, ClubMemberAttendanceHistoryEntry[]> = {};
  for (const [userId, list] of historyByUser) {
    list.sort((a, b) => b.eventDateIso.localeCompare(a.eventDateIso));
    result[userId] = list;
  }

  return result;
}
