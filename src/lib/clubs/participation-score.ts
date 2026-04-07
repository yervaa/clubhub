/**
 * Derived participation score (0–100) for roster / profile display.
 * Pure function — no DB; uses the same inputs already loaded for `ClubMember`.
 */

export type ParticipationScoreInput = {
  /** 0–100 from `ClubMember.attendanceRate` */
  attendanceRate: number;
  /** Past events with any attendance tracked for the club */
  totalTrackedEvents: number;
  /** Sum of logged volunteer hours in the club */
  volunteerHoursTotal: number;
};

export type ParticipationScoreResult = {
  /** Rounded integer 0–100 */
  score: number;
  /**
   * When true, the club has no past events with attendance tracking, so the attendance
   * portion uses a neutral midpoint instead of treating everyone as 0%.
   */
  attendanceSignalLimited: boolean;
};

/** Hours at or above this count earn the full volunteer slice of the score. */
export const PARTICIPATION_VOLUNTEER_HOURS_FOR_FULL_SLICE = 12;

const ATTENDANCE_WEIGHT = 0.75;
const VOLUNTEER_WEIGHT = 0.25;

/**
 * Weighted blend:
 * - 75%: attendance rate over past **tracked** events (when any exist); otherwise a 50% neutral
 *   for that slice so new clubs / no-tracking clubs do not zero everyone out.
 * - 25%: volunteer hours, linear up to {@link PARTICIPATION_VOLUNTEER_HOURS_FOR_FULL_SLICE} hours.
 */
export function computeParticipationScore(input: ParticipationScoreInput): ParticipationScoreResult {
  const hours = Number.isFinite(input.volunteerHoursTotal) ? Math.max(0, input.volunteerHoursTotal) : 0;
  const volNorm = Math.min(hours / PARTICIPATION_VOLUNTEER_HOURS_FOR_FULL_SLICE, 1);
  const volunteerPoints = volNorm * 100 * VOLUNTEER_WEIGHT;

  let attendancePoints: number;
  let attendanceSignalLimited: boolean;

  if (input.totalTrackedEvents > 0) {
    const rate = Math.min(100, Math.max(0, input.attendanceRate));
    attendancePoints = (rate / 100) * 100 * ATTENDANCE_WEIGHT;
    attendanceSignalLimited = false;
  } else {
    attendancePoints = 0.5 * 100 * ATTENDANCE_WEIGHT;
    attendanceSignalLimited = true;
  }

  const score = Math.round(Math.min(100, attendancePoints + volunteerPoints));

  return { score, attendanceSignalLimited };
}

/** Short labels for compact UI (roster / badges). */
export function participationScoreBand(score: number): "high" | "mid" | "low" {
  if (score >= 67) return "high";
  if (score >= 34) return "mid";
  return "low";
}
