/**
 * Recent participation window (rolling) — used for activity points and inactive detection.
 * Tune here only; no SQL constants for the window length.
 */

/** Rolling lookback for attendance, RSVPs, activity points, and inactive detection. */
export const PARTICIPATION_ACTIVITY_WINDOW_DAYS = 45;

/** +3 per event attended (marked present) in the window. */
export const ACTIVITY_POINTS_PER_ATTENDANCE = 3;

/** +1 per RSVP "yes" in the window (by response time). */
export const ACTIVITY_POINTS_PER_RSVP_YES = 1;

/**
 * Active members who joined within this many days are not labeled inactive
 * when they have no RSVP/attendance yet.
 */
export const PARTICIPATION_NEW_MEMBER_GRACE_DAYS = 14;

export type ParticipationWindowAttendanceRow = {
  event_id: string;
  user_id: string;
  marked_at: string;
};

export type ParticipationWindowRsvpRow = {
  event_id: string;
  user_id: string;
  status: string;
  created_at: string;
};

export type RecentActivityDerived = {
  /** +3 per attendance + +1 per RSVP yes in window. */
  recentActivityPoints: number;
  /** Distinct past events in window where member was marked present. */
  recentAttendanceCount: number;
  /** RSVP "yes" responses in window (by `created_at`). */
  recentRsvpYesCount: number;
  /** Any RSVP row in window (yes/no/maybe/waitlist). */
  hasRsvpInWindow: boolean;
  /** Latest of `marked_at` or RSVP `created_at` in window; null if none. */
  lastActivityAt: string | null;
  /**
   * True for active members: no attendance and no RSVP in window, outside new-member grace.
   * Alumni are never flagged.
   */
  isInactive: boolean;
};

function maxIso(a: string | null, b: string | null): string | null {
  if (!a) return b;
  if (!b) return a;
  return new Date(a).getTime() >= new Date(b).getTime() ? a : b;
}

/**
 * Aggregates per-user stats from rows already scoped to the club and time window.
 */
export function deriveRecentActivityForMember(args: {
  membershipStatus: "active" | "alumni";
  joinedAtIso: string | null;
  attendanceRows: ParticipationWindowAttendanceRow[];
  rsvpRows: ParticipationWindowRsvpRow[];
  now: Date;
}): RecentActivityDerived {
  const { membershipStatus, joinedAtIso, attendanceRows, rsvpRows, now } = args;

  const recentAttendanceCount = attendanceRows.length;
  const recentRsvpYesCount = rsvpRows.filter((r) => r.status === "yes").length;
  const hasRsvpInWindow = rsvpRows.length > 0;

  let lastActivityAt: string | null = null;
  for (const r of attendanceRows) {
    lastActivityAt = maxIso(lastActivityAt, r.marked_at);
  }
  for (const r of rsvpRows) {
    lastActivityAt = maxIso(lastActivityAt, r.created_at);
  }

  const recentActivityPoints =
    recentAttendanceCount * ACTIVITY_POINTS_PER_ATTENDANCE + recentRsvpYesCount * ACTIVITY_POINTS_PER_RSVP_YES;

  const graceMs = PARTICIPATION_NEW_MEMBER_GRACE_DAYS * 86400000;
  const joined = joinedAtIso ? new Date(joinedAtIso) : null;
  const inNewMemberGrace =
    joined !== null
    && !Number.isNaN(joined.getTime())
    && now.getTime() - joined.getTime() < graceMs;

  let isInactive = false;
  if (membershipStatus === "active" && !inNewMemberGrace) {
    isInactive = recentAttendanceCount === 0 && !hasRsvpInWindow;
  }

  return {
    recentActivityPoints,
    recentAttendanceCount,
    recentRsvpYesCount,
    hasRsvpInWindow,
    lastActivityAt,
    isInactive,
  };
}

export type MemberMembershipLite = {
  membershipStatus: "active" | "alumni";
  joinedAtIso: string | null;
};

/**
 * Builds {@link RecentActivityDerived} for each roster member from window-scoped rows.
 */
export function buildRecentActivityByUserId(args: {
  memberUserIds: string[];
  membershipByUserId: Map<string, MemberMembershipLite>;
  attendanceRows: ParticipationWindowAttendanceRow[];
  rsvpRows: ParticipationWindowRsvpRow[];
  now: Date;
}): Map<string, RecentActivityDerived> {
  const { memberUserIds, membershipByUserId, attendanceRows, rsvpRows, now } = args;

  const attByUser = new Map<string, ParticipationWindowAttendanceRow[]>();
  for (const r of attendanceRows) {
    const list = attByUser.get(r.user_id) ?? [];
    list.push(r);
    attByUser.set(r.user_id, list);
  }

  const rsvpByUser = new Map<string, ParticipationWindowRsvpRow[]>();
  for (const r of rsvpRows) {
    const list = rsvpByUser.get(r.user_id) ?? [];
    list.push(r);
    rsvpByUser.set(r.user_id, list);
  }

  const out = new Map<string, RecentActivityDerived>();
  for (const userId of memberUserIds) {
    const mem = membershipByUserId.get(userId);
    if (!mem) continue;
    out.set(
      userId,
      deriveRecentActivityForMember({
        membershipStatus: mem.membershipStatus,
        joinedAtIso: mem.joinedAtIso,
        attendanceRows: attByUser.get(userId) ?? [],
        rsvpRows: rsvpByUser.get(userId) ?? [],
        now,
      }),
    );
  }
  return out;
}

/** Title text for roster activity score chip. */
export function recentActivityPointsTitle(points: number): string {
  return `Activity ${points} pts — last ${PARTICIPATION_ACTIVITY_WINDOW_DAYS} days: +${ACTIVITY_POINTS_PER_ATTENDANCE} per event attended, +${ACTIVITY_POINTS_PER_RSVP_YES} per RSVP “yes”. RSVP “no” does not add points but counts as engagement for inactive.`;
}
