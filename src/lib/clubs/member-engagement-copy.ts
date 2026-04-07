/**
 * Shared wording for engagement-related UI (roster + member profile).
 * Aligns how we describe tracked attendance, participation score, volunteer hours, and leadership recency.
 */

import { PARTICIPATION_VOLUNTEER_HOURS_FOR_FULL_SLICE } from "@/lib/clubs/participation-score";

/** Shown once above the grouped engagement blocks in the member profile. */
export const MEMBER_ENGAGEMENT_SECTION_INTRO =
  "Attendance is the raw record (marked present only). Participation score blends attendance rate with volunteer hours. Leadership recency, when shown, also considers RSVPs — so it can differ from attendance %.";

/** Under the “Attendance” heading — matches roster semantics. */
export const TRACKED_ATTENDANCE_SUBTITLE =
  "Past events where the club recorded attendance — you were marked present (RSVPs are tracked separately). Same totals as the roster.";

/** Under the “Participation score” heading. */
export const PARTICIPATION_SCORE_SUBTITLE =
  "Estimated 0–100 from the same tracked attendance rate as above, plus logged volunteer hours. Not a grade; not the same number as attendance % alone.";

/** Extra line for volunteer hours panel (profile). */
export const VOLUNTEER_HOURS_PARTICIPATION_NOTE = `The participation score uses up to ${PARTICIPATION_VOLUNTEER_HOURS_FOR_FULL_SLICE} h in this club for its volunteer slice (see score details).`;

/** One-line summary for lists and profile summary rows. */
export function formatTrackedAttendanceSummary(args: {
  attendanceCount: number;
  totalTrackedEvents: number;
  attendanceRate: number;
}): string {
  const { attendanceCount, totalTrackedEvents, attendanceRate } = args;
  return `${attendanceCount} of ${totalTrackedEvents} tracked events · ${attendanceRate}% present`;
}

export function trackedAttendanceEmptyCopy(): string {
  return "No past events with attendance tracking yet — nothing to compare against.";
}

/** Tooltip / title for compact participation score chips. */
export function participationScoreCompactTitle(args: {
  score: number;
  attendanceSignalLimited: boolean;
}): string {
  const base = `Participation score ${args.score} (0–100): derived from tracked attendance rate and volunteer hours — not the same as attendance % alone.`;
  return args.attendanceSignalLimited
    ? `${base} Attendance slice uses a neutral placeholder until the club tracks attendance on past events.`
    : base;
}
