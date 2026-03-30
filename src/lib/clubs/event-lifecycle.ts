import type { ClubEvent } from "@/lib/clubs/queries";

/**
 * Past events with `event_date` after this instant are treated as "recently happened"
 * (follow-up window for attendance, reflections, etc.).
 */
export const RECENTLY_HAPPENED_DAYS = 14;

export type EventLifecycleGroup = "upcoming" | "recently_happened" | "past";

export type GroupedClubEvents = {
  upcoming: ClubEvent[];
  recentlyHappened: ClubEvent[];
  past: ClubEvent[];
};

export function getRecentlyHappenedCutoff(now: Date): Date {
  const d = new Date(now);
  d.setDate(d.getDate() - RECENTLY_HAPPENED_DAYS);
  return d;
}

export function partitionEventsByLifecycle(events: ClubEvent[], now: Date): GroupedClubEvents {
  const cutoff = getRecentlyHappenedCutoff(now);
  const upcoming: ClubEvent[] = [];
  const recentlyHappened: ClubEvent[] = [];
  const past: ClubEvent[] = [];

  for (const event of events) {
    const t = event.eventDateRaw.getTime();
    if (t > now.getTime()) {
      upcoming.push(event);
    } else if (t > cutoff.getTime()) {
      recentlyHappened.push(event);
    } else {
      past.push(event);
    }
  }

  upcoming.sort((a, b) => a.eventDateRaw.getTime() - b.eventDateRaw.getTime());
  recentlyHappened.sort((a, b) => b.eventDateRaw.getTime() - a.eventDateRaw.getTime());
  past.sort((a, b) => b.eventDateRaw.getTime() - a.eventDateRaw.getTime());

  return { upcoming, recentlyHappened, past };
}

export type EventReviewFlags = {
  needsAttendanceFollowUp: boolean;
  needsReflectionFollowUp: boolean;
  hasLowRsvpTurnout: boolean;
};

/**
 * Operational cues for officers in the "recently happened" window.
 * Attendance "missing" means no rows in event_attendance for this event (same heuristic as dashboard alerts).
 */
export function getEventReviewFlags(
  event: ClubEvent,
  now: Date,
  opts: {
    canMarkAttendance: boolean;
    canManageReflections: boolean;
    memberCount: number;
  },
): EventReviewFlags {
  const cutoff = getRecentlyHappenedCutoff(now);
  const endedRecently =
    event.eventDateRaw.getTime() <= now.getTime() && event.eventDateRaw.getTime() > cutoff.getTime();

  if (!endedRecently) {
    return {
      needsAttendanceFollowUp: false,
      needsReflectionFollowUp: false,
      hasLowRsvpTurnout: false,
    };
  }

  const totalRsvp = event.rsvpCounts.yes + event.rsvpCounts.no + event.rsvpCounts.maybe;
  const hasLowRsvpTurnout =
    opts.memberCount > 0 && totalRsvp < Math.max(1, Math.ceil(opts.memberCount * 0.15));

  return {
    needsAttendanceFollowUp: opts.canMarkAttendance && event.attendanceCount === 0,
    needsReflectionFollowUp: opts.canManageReflections && event.reflection === null,
    hasLowRsvpTurnout: opts.canMarkAttendance && hasLowRsvpTurnout,
  };
}

export function eventNeedsOfficerReview(flags: EventReviewFlags): boolean {
  return flags.needsAttendanceFollowUp || flags.needsReflectionFollowUp || flags.hasLowRsvpTurnout;
}
