import type { ClubDetail, ClubEvent } from "@/lib/clubs/queries";
import type { EventType } from "@/lib/events";

// ─── Output types ────────────────────────────────────────────────────────────

export type TrendDirection = "improving" | "declining" | "stable" | "insufficient";

export type TrendPoint = {
  eventId: string;
  title: string;
  eventType: EventType;
  date: string;
  presentCount: number;
  memberCount: number;
  /** Attendance as a percentage of current membership (0–100) */
  rate: number;
};

export type EventTypeRow = {
  type: EventType;
  avgRate: number;
  eventCount: number;
};

export type EngagementTier = "high" | "moderate" | "low";

export type EngagementSegment = {
  label: string;
  description: string;
  count: number;
  /** Share of total membership (0–100) */
  percent: number;
  tier: EngagementTier;
};

export type ClubInsightData = {
  /** Past events with at least one attendance record, in chronological order */
  trendPoints: TrendPoint[];
  trendDirection: TrendDirection;
  /** Percentage-point change between first and second half of tracked events */
  trendDelta: number;
  eventTypeRows: EventTypeRow[];
  segments: EngagementSegment[];
  /** Up to 4 human-readable takeaway strings */
  highlights: string[];
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

function average(values: number[]): number {
  if (values.length === 0) return 0;
  return values.reduce((a, b) => a + b, 0) / values.length;
}

function cap(value: number): number {
  return Math.min(100, Math.max(0, value));
}

// ─── Main computation ─────────────────────────────────────────────────────────

export function computeClubInsights(club: ClubDetail): ClubInsightData {
  const now = new Date();
  const memberCount = club.memberCount;

  // Past events that have at least one attendance record
  const trackedPast: ClubEvent[] = club.events
    .filter((e) => e.eventDateRaw < now && e.attendanceCount > 0)
    .sort((a, b) => a.eventDateRaw.getTime() - b.eventDateRaw.getTime());

  // ── Trend points ────────────────────────────────────────────────────────────
  const trendPoints: TrendPoint[] = trackedPast.map((e) => ({
    eventId: e.id,
    title: e.title,
    eventType: e.eventType,
    date: e.eventDate,
    presentCount: e.attendanceCount,
    memberCount,
    rate: memberCount > 0 ? cap(Math.round((e.attendanceCount / memberCount) * 100)) : 0,
  }));

  // ── Trend direction ─────────────────────────────────────────────────────────
  // Compare average of first half vs last half. Requires at least 3 data points.
  let trendDirection: TrendDirection = "insufficient";
  let trendDelta = 0;

  if (trendPoints.length >= 3) {
    const n = trendPoints.length;
    const half = Math.floor(n / 2);
    const firstAvg = average(trendPoints.slice(0, half).map((p) => p.rate));
    const secondAvg = average(trendPoints.slice(n - half).map((p) => p.rate));
    trendDelta = Math.round(secondAvg - firstAvg);

    if (trendDelta >= 8) trendDirection = "improving";
    else if (trendDelta <= -8) trendDirection = "declining";
    else trendDirection = "stable";
  }

  // ── Event type stats ────────────────────────────────────────────────────────
  const typeMap = new Map<EventType, { total: number; count: number }>();
  for (const e of trackedPast) {
    const rate = memberCount > 0 ? cap(Math.round((e.attendanceCount / memberCount) * 100)) : 0;
    const existing = typeMap.get(e.eventType) ?? { total: 0, count: 0 };
    typeMap.set(e.eventType, { total: existing.total + rate, count: existing.count + 1 });
  }

  const eventTypeRows: EventTypeRow[] = Array.from(typeMap.entries())
    .map(([type, { total, count }]) => ({
      type,
      avgRate: Math.round(total / count),
      eventCount: count,
    }))
    .sort((a, b) => b.avgRate - a.avgRate);

  // ── Engagement segments ─────────────────────────────────────────────────────
  const segments: EngagementSegment[] = [];
  if (club.totalTrackedEvents > 0 && memberCount > 0) {
    const highCount = club.members.filter((m) => m.attendanceRate >= 70).length;
    const modCount = club.members.filter((m) => m.attendanceRate >= 30 && m.attendanceRate < 70).length;
    const lowCount = club.members.filter((m) => m.attendanceRate < 30).length;

    segments.push({
      label: "Highly Engaged",
      description: "Attended 70%+ of events",
      count: highCount,
      percent: Math.round((highCount / memberCount) * 100),
      tier: "high",
    });
    segments.push({
      label: "Moderate",
      description: "Attended 30–69% of events",
      count: modCount,
      percent: Math.round((modCount / memberCount) * 100),
      tier: "moderate",
    });
    segments.push({
      label: "Low Engagement",
      description: "Attended fewer than 30% of events",
      count: lowCount,
      percent: Math.round((lowCount / memberCount) * 100),
      tier: "low",
    });
  }

  // ── Highlights ──────────────────────────────────────────────────────────────
  const highlights: string[] = [];

  if (trendDirection === "improving") {
    highlights.push(
      `Attendance is up ${Math.abs(trendDelta)} percentage points compared to earlier events.`,
    );
  } else if (trendDirection === "declining") {
    highlights.push(
      `Attendance has dropped ${Math.abs(trendDelta)} percentage points — sending event reminders may help.`,
    );
  } else if (trendDirection === "stable") {
    highlights.push("Attendance has been consistent across recent events.");
  }

  const bestType = eventTypeRows[0];
  if (bestType && eventTypeRows.length > 1) {
    highlights.push(`${bestType.type}s have the highest average attendance at ${bestType.avgRate}%.`);
  } else if (bestType) {
    const plural = bestType.eventCount !== 1;
    highlights.push(
      `Your club has held ${bestType.eventCount} tracked ${bestType.type.toLowerCase()}${plural ? "s" : ""}.`,
    );
  }

  const highSeg = segments.find((s) => s.tier === "high");
  if (highSeg && highSeg.count > 0) {
    const verb = highSeg.count === 1 ? "attends" : "attend";
    highlights.push(
      `${highSeg.count} ${highSeg.count === 1 ? "member" : "members"} ${verb} more than 70% of events — your most committed group.`,
    );
  }

  if (club.clubAverageAttendance >= 70) {
    highlights.push("Overall club attendance is strong. Keep up the momentum.");
  } else if (club.clubAverageAttendance >= 40) {
    highlights.push("Overall attendance is moderate. Pre-event reminders could boost turnout.");
  } else if (club.clubAverageAttendance > 0) {
    highlights.push("Overall attendance is low. Try following up with members before each event.");
  }

  return {
    trendPoints,
    trendDirection,
    trendDelta,
    eventTypeRows,
    segments,
    highlights: highlights.slice(0, 4),
  };
}
