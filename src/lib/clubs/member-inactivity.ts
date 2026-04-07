/**
 * Derived “likely inactive” signals for active members (no DB writes).
 * Uses RSVP + past attendance already loaded for the club roster.
 */

export const MEMBER_INACTIVITY = {
  /** No engagement signal at least this recent → eligible for label (when other gates pass). */
  INACTIVITY_DAYS: 45,
  /** Active members who joined within this window are not flagged. */
  NEW_MEMBER_GRACE_DAYS: 21,
  /** Need this many past events with attendance tracking before labeling anyone inactive. */
  MIN_TRACKED_EVENTS_FOR_LABEL: 2,
} as const;

export type MembershipStatusLite = "active" | "alumni";

type EventRow = { id: string; event_date: string };

type BuildLastEngagementArgs = {
  now: Date;
  events: EventRow[];
  pastAttendance: { event_id: string; user_id: string }[];
  rsvps: { event_id: string; user_id: string; created_at: string }[];
};

/**
 * Latest engagement timestamp per user (ms since epoch).
 * Past events: attendance or RSVP counts as engagement on the event date.
 * Upcoming events: RSVP counts as engagement on `created_at` (when they responded).
 */
export function buildLastEngagementByUserMs(args: BuildLastEngagementArgs): Map<string, number> {
  const { now, events, pastAttendance, rsvps } = args;
  const nowMs = now.getTime();
  const meta = new Map<string, { atMs: number; isPast: boolean }>();

  for (const e of events) {
    const atMs = new Date(e.event_date).getTime();
    if (Number.isNaN(atMs)) continue;
    meta.set(e.id, { atMs, isPast: atMs < nowMs });
  }

  const lastByUser = new Map<string, number>();

  function bump(userId: string, ts: number) {
    if (Number.isNaN(ts)) return;
    const prev = lastByUser.get(userId) ?? 0;
    if (ts > prev) lastByUser.set(userId, ts);
  }

  for (const row of pastAttendance) {
    const m = meta.get(row.event_id);
    if (!m?.isPast) continue;
    bump(row.user_id, m.atMs);
  }

  for (const row of rsvps) {
    const m = meta.get(row.event_id);
    if (!m) continue;
    const createdMs = new Date(row.created_at).getTime();
    if (Number.isNaN(createdMs)) continue;
    const ts = m.isPast ? m.atMs : createdMs;
    bump(row.user_id, ts);
  }

  return lastByUser;
}

export function computeLikelyInactiveMember(args: {
  membershipStatus: MembershipStatusLite;
  joinedAtIso: string | null;
  totalTrackedEvents: number;
  lastEngagementMs: number | undefined;
  now: Date;
}): { lastEngagementAt: string | null; engagementSignalWeak: boolean; likelyInactive: boolean } {
  const { membershipStatus, joinedAtIso, totalTrackedEvents, lastEngagementMs, now } = args;
  const weak = totalTrackedEvents < MEMBER_INACTIVITY.MIN_TRACKED_EVENTS_FOR_LABEL;
  const nowMs = now.getTime();
  const graceMs = MEMBER_INACTIVITY.NEW_MEMBER_GRACE_DAYS * 86400000;
  const inactiveCutoffMs = nowMs - MEMBER_INACTIVITY.INACTIVITY_DAYS * 86400000;

  const joined = joinedAtIso ? new Date(joinedAtIso) : null;
  const inGrace =
    joined !== null
    && !Number.isNaN(joined.getTime())
    && nowMs - joined.getTime() < graceMs;

  const lastMs = lastEngagementMs ?? 0;
  const lastEngagementAt = lastMs > 0 ? new Date(lastMs).toISOString() : null;

  if (membershipStatus !== "active" || weak || inGrace) {
    return { lastEngagementAt, engagementSignalWeak: weak, likelyInactive: false };
  }

  const likelyInactive = lastMs < inactiveCutoffMs;
  return { lastEngagementAt, engagementSignalWeak: weak, likelyInactive };
}

/** Display last RSVP / event engagement for leadership copy (profile, tooltips). */
export function formatMemberLastEngagementDisplay(iso: string | null): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}

/**
 * Leadership-only profile copy: explains the existing likely-inactive rule or shows last engagement context.
 * Alumni → null (not applicable). Computed from roster fields (no extra queries).
 */
export type LeadershipEngagementProfileBlock =
  | {
      level: "flagged";
      title: string;
      body: string;
    }
  | {
      level: "info";
      body: string;
    };

/** Subset of roster fields used for leadership engagement copy (keeps this module free of `queries` imports). */
export type MemberEngagementFields = {
  membershipStatus: MembershipStatusLite;
  likelyInactive: boolean;
  lastEngagementAt: string | null;
  engagementSignalWeak: boolean;
};

export function buildLeadershipEngagementProfileBlock(
  member: MemberEngagementFields,
): LeadershipEngagementProfileBlock | null {
  if (member.membershipStatus !== "active") {
    return null;
  }

  if (member.likelyInactive) {
    const lastLabel = formatMemberLastEngagementDisplay(member.lastEngagementAt);
    const lastSentence = lastLabel
      ? `Last RSVP or attended event signal: ${lastLabel}.`
      : "No RSVP or attended-event signal appears in this club’s loaded event history for this member.";

    return {
      level: "flagged",
      title: "Likely inactive",
      body: `No RSVP or attended-event signal in the last ${MEMBER_INACTIVITY.INACTIVITY_DAYS} days (after a ${MEMBER_INACTIVITY.NEW_MEMBER_GRACE_DAYS}-day grace from join). Requires at least ${MEMBER_INACTIVITY.MIN_TRACKED_EVENTS_FOR_LABEL} past events with attendance tracking club-wide. ${lastSentence} This recency signal is separate from attendance rate and participation score (those use marked-present counts and volunteer hours, not RSVPs). Hint for outreach only — nothing changes automatically.`,
    };
  }

  if (member.engagementSignalWeak) {
    return {
      level: "info",
      body: `Not enough past events with attendance tracking yet (needs ${MEMBER_INACTIVITY.MIN_TRACKED_EVENTS_FOR_LABEL} club-wide) to evaluate likely inactive. Attendance summaries and participation scores may still show once tracking starts.`,
    };
  }

  const lastLabel = formatMemberLastEngagementDisplay(member.lastEngagementAt);
  if (lastLabel) {
    return {
      level: "info",
      body: `Last RSVP or attended-event signal: ${lastLabel}. (Recency for outreach — separate from attendance % and participation score.)`,
    };
  }

  return {
    level: "info",
    body: "No RSVP or attended-event signal in loaded history for this member yet. Distinct from marked-present attendance totals above.",
  };
}
