import { csvJoinRow } from "@/lib/csv";
import { getMemberRosterDisplayName } from "@/lib/member-display";
import { computeClubInsights, type ClubInsightData, type TrendDirection } from "@/lib/clubs/insights";
import type { ClubDetail } from "@/lib/clubs/queries";

export type InsightsExportPayload = {
  clubId: string;
  clubName: string;
  exportedAtIso: string;
  memberCount: number;
  totalTrackedEvents: number;
  clubAverageAttendance: number;
  highlyEngagedCount: number;
  insights: ClubInsightData;
  topMembers: Array<{
    rank: number;
    displayName: string;
    role: string;
    attendanceCount: number;
    totalTrackedEvents: number;
    attendanceRate: number;
  }>;
};

function trendDirectionLabel(dir: TrendDirection, delta: number): string {
  switch (dir) {
    case "improving":
      return `Improving (+${delta} pp)`;
    case "declining":
      return `Declining (${delta} pp)`;
    case "stable":
      return "Stable";
    default:
      return "Insufficient data (fewer than 3 tracked events)";
  }
}

export function buildInsightsExportPayload(club: ClubDetail): InsightsExportPayload {
  const insights = computeClubInsights(club);
  const highlyEngagedCount = club.members.filter((m) => m.attendanceRate >= 70).length;

  return {
    clubId: club.id,
    clubName: club.name,
    exportedAtIso: new Date().toISOString(),
    memberCount: club.memberCount,
    totalTrackedEvents: club.totalTrackedEvents,
    clubAverageAttendance: club.clubAverageAttendance,
    highlyEngagedCount,
    insights,
    topMembers: club.topMembers.map((member, index) => ({
      rank: index + 1,
      displayName: getMemberRosterDisplayName(member),
      role: member.role,
      attendanceCount: member.attendanceCount,
      totalTrackedEvents: member.totalTrackedEvents,
      attendanceRate: member.attendanceRate,
    })),
  };
}

export function buildInsightsCsv(payload: InsightsExportPayload): string {
  const { insights } = payload;
  const lines: string[] = [];

  const pushRow = (...cells: string[]) => lines.push(csvJoinRow(cells));
  const pushBlank = () => lines.push("");

  pushRow("Clubora Insights Export");
  pushRow("Club", payload.clubName);
  pushRow("Club ID", payload.clubId);
  pushRow("Exported at (UTC)", payload.exportedAtIso);
  pushBlank();

  pushRow("Summary");
  pushRow("Metric", "Value");
  pushRow("Average attendance (%)", String(payload.clubAverageAttendance));
  pushRow("Tracked events", String(payload.totalTrackedEvents));
  pushRow("Active members", String(payload.memberCount));
  pushRow("Highly engaged members (70%+ attendance)", String(payload.highlyEngagedCount));
  pushRow("Momentum", trendDirectionLabel(insights.trendDirection, insights.trendDelta));
  pushBlank();

  if (insights.highlights.length > 0) {
    pushRow("Highlights");
    pushRow("Takeaway");
    for (const text of insights.highlights) {
      pushRow(text);
    }
    pushBlank();
  }

  pushRow("Attendance by event");
  pushRow("Event title", "Event type", "Date", "Present", "Roster size", "Attendance (%)");
  if (insights.trendPoints.length === 0) {
    pushRow("(No tracked events with attendance yet)");
  } else {
    for (const point of insights.trendPoints) {
      pushRow(
        point.title,
        point.eventType,
        point.date,
        String(point.presentCount),
        String(point.memberCount),
        String(point.rate),
      );
    }
  }
  pushBlank();

  pushRow("Event type effectiveness");
  pushRow("Event type", "Tracked events", "Average attendance (%)");
  if (insights.eventTypeRows.length === 0) {
    pushRow("(No event types to compare yet)");
  } else {
    for (const row of insights.eventTypeRows) {
      pushRow(row.type, String(row.eventCount), String(row.avgRate));
    }
  }
  pushBlank();

  pushRow("Engagement mix");
  pushRow("Segment", "Description", "Member count", "Share of roster (%)");
  if (insights.segments.length === 0) {
    pushRow("(No engagement segments yet)");
  } else {
    for (const seg of insights.segments) {
      pushRow(seg.label, seg.description, String(seg.count), String(seg.percent));
    }
  }
  pushBlank();

  pushRow("Most active members (top 3)");
  pushRow("Rank", "Name", "Role", "Events attended", "Tracked events", "Attendance (%)");
  if (payload.topMembers.length === 0) {
    pushRow("(No member rankings yet)");
  } else {
    for (const member of payload.topMembers) {
      pushRow(
        String(member.rank),
        member.displayName,
        member.role,
        String(member.attendanceCount),
        String(member.totalTrackedEvents),
        String(member.attendanceRate),
      );
    }
  }

  return `\uFEFF${lines.join("\n")}`;
}

export function downloadInsightsCsv(payload: InsightsExportPayload): void {
  const csv = buildInsightsCsv(payload);
  const slug = payload.clubName
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 48);
  const date = payload.exportedAtIso.slice(0, 10);
  const filename = `${slug || "club"}-insights-${date}.csv`;

  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.rel = "noopener";
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}
