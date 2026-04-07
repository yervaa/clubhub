import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { mergeClubRosterIdentities } from "@/lib/clubs/merge-club-roster-identities";
import { formatAvailabilitySlotLine } from "@/lib/clubs/member-availability-display";
import { getClubDetailForCurrentUser } from "@/lib/clubs/queries";
import { csvJoinRow } from "@/lib/csv";
import { getMemberRosterDisplayName } from "@/lib/member-display";
import { actorCanExportMemberRoster } from "@/lib/clubs/member-management-access";
import { getMembersWithRoles } from "@/lib/rbac/role-actions";
import type { MemberWithRoles } from "@/lib/rbac/role-actions";

function formatVolunteerHoursForCsv(n: number): string {
  const r = Math.round(n * 100) / 100;
  if (Number.isInteger(r)) return String(r);
  return r.toFixed(2).replace(/\.?0+$/, "") || "0";
}

function formatRbacForExport(rbacRoles: MemberWithRoles["rbacRoles"]): string {
  const significant = rbacRoles.filter(
    (r) => !(r.isSystem && (r.roleName === "Officer" || r.roleName === "Member")),
  );
  return significant.map((r) => r.roleName).join("; ") || "";
}

function formatJoinedDate(iso: string | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return d.toISOString().slice(0, 10);
}

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ clubId: string }> },
) {
  const { clubId } = await params;

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  if (!(await actorCanExportMemberRoster(user.id, clubId))) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  const [club, membersResult] = await Promise.all([
    getClubDetailForCurrentUser(clubId),
    getMembersWithRoles(clubId),
  ]);

  if (!club) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  const clubForUi =
    membersResult.ok ? mergeClubRosterIdentities(club, membersResult.data) : club;

  const rbacByUser: Record<string, MemberWithRoles["rbacRoles"]> = {};
  if (membersResult.ok) {
    for (const m of membersResult.data) {
      rbacByUser[m.userId] = m.rbacRoles;
    }
  }

  const sorted = [...clubForUi.members].sort((a, b) =>
    getMemberRosterDisplayName(a).localeCompare(getMemberRosterDisplayName(b), undefined, {
      sensitivity: "base",
    }),
  );

  const headers = [
    "Display name",
    "Membership status",
    "Legacy roster role",
    "RBAC roles",
    "Joined (date)",
    "Tags",
    "Committees",
    "Teams",
    "Volunteer hours (club total)",
    "Skills",
    "Interests",
    "Availability summary",
    "Tracked events attended",
    "Tracked events total",
    "Attendance percent",
    "Likely inactive hint",
  ];

  const rows: string[] = [csvJoinRow(headers)];

  for (const m of sorted) {
    const skills = (m.skillInterestEntries ?? [])
      .filter((e) => e.kind === "skill")
      .map((e) => e.label)
      .join("; ");
    const interests = (m.skillInterestEntries ?? [])
      .filter((e) => e.kind === "interest")
      .map((e) => e.label)
      .join("; ");
    const availability = (m.availabilitySlots ?? []).map(formatAvailabilitySlotLine).join(" | ");

    rows.push(
      csvJoinRow([
        getMemberRosterDisplayName(m),
        m.membershipStatus === "alumni" ? "alumni" : "active",
        m.role,
        formatRbacForExport(rbacByUser[m.userId] ?? []),
        formatJoinedDate(m.joinedAt),
        (m.tags ?? []).map((t) => t.name).join("; "),
        (m.committees ?? []).map((c) => c.name).join("; "),
        (m.teams ?? []).map((t) => t.name).join("; "),
        formatVolunteerHoursForCsv(m.volunteerHoursTotal ?? 0),
        skills,
        interests,
        availability,
        String(m.attendanceCount ?? 0),
        String(m.totalTrackedEvents ?? 0),
        String(m.attendanceRate ?? 0),
        m.likelyInactive ? "yes" : "",
      ]),
    );
  }

  const csvBody = rows.join("\r\n");
  const bom = "\uFEFF";
  const safeClub = clubForUi.name.replace(/[^\w\-]+/g, "_").replace(/_+/g, "_").slice(0, 80) || "club";
  const dateStr = new Date().toISOString().slice(0, 10);
  const filename = `${safeClub}_members_${dateStr}.csv`;

  return new NextResponse(bom + csvBody, {
    headers: {
      "Content-Type": "text/csv; charset=utf-8",
      "Content-Disposition": `attachment; filename="${filename}"`,
      "Cache-Control": "no-store",
    },
  });
}
