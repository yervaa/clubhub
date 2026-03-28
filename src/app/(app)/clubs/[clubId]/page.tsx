import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import { getUserPermissions } from "@/lib/rbac/permissions";
import { ClubAttentionNeededSection } from "@/components/ui/club-attention-needed-section";
import { ClubActivityFeed, formatActivityTime } from "@/components/ui/club-activity-feed";
import type { ActivityFeedItem } from "@/components/ui/club-activity-feed";
import { getClubDetailForCurrentUser } from "@/lib/clubs/queries";
import { getMyClubTasks } from "@/lib/tasks/queries";

type ClubOverviewPageProps = {
  params: Promise<{ clubId: string }>;
};

export default async function ClubOverviewPage({ params }: ClubOverviewPageProps) {
  const { clubId } = await params;

  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const [club, userPermissions, myTasks] = await Promise.all([
    getClubDetailForCurrentUser(clubId),
    getUserPermissions(user.id, clubId),
    getMyClubTasks(clubId, user.id),
  ]);

  if (!club) {
    notFound();
  }

  // Derive permission booleans for UI control visibility.
  const canInviteMembers = userPermissions.has("members.invite");
  const canCreateEvents = userPermissions.has("events.create");
  const canPostAnnouncements = userPermissions.has("announcements.create");
  const canMarkAttendance = userPermissions.has("attendance.mark");
  const canViewAudit = userPermissions.has("audit_logs.view");
  // Show management alerts when the user has at least one management-facing permission.
  const showManagementAlerts = canCreateEvents || canPostAnnouncements || canMarkAttendance;

  const memberCount = club.memberCount;
  const now = new Date();
  const nextEvent = [...club.events]
    .filter((event) => event.eventDateRaw.getTime() > now.getTime())
    .sort((a, b) => a.eventDateRaw.getTime() - b.eventDateRaw.getTime())[0] ?? null;
  const latestAnnouncement = club.announcements[0] ?? null;

  // ── Build merged activity feed ─────────────────────────────────────────────
  // Each source builds its own sort key inline — no parallel-index dependency.
  type SortableItem = ActivityFeedItem & { _sortKey: string };

  const hrefByKind: Record<typeof club.recentActivity[number]["kind"], string> = {
    member_joined: `/clubs/${club.id}/members`,
    announcement_posted: `/clubs/${club.id}/announcements`,
    event_created: `/clubs/${club.id}/events`,
    rsvp_updated: `/clubs/${club.id}/events`,
    attendance_marked: `/clubs/${club.id}/events`,
  };

  const rpcItems: SortableItem[] = club.recentActivity.map((item) => ({
    id: item.id,
    type: item.kind,
    message: item.message,
    displayTime: formatActivityTime(item.createdAtIso),
    href: hrefByKind[item.kind],
    _sortKey: item.createdAtIso,
  }));

  // Reflections — visible if the user has reflections permission (RLS already
  // controls whether reflection data was fetched; null reflections are filtered out).
  const reflectionItems: SortableItem[] = club.events
    .filter((e) => e.reflection !== null)
    .map((e) => ({
      id: `reflection-${e.id}`,
      type: "reflection_added" as const,
      message: `Officer reflection added for "${e.title}"`,
      displayTime: formatActivityTime(e.reflection!.updatedAtIso),
      href: `/clubs/${club.id}/events`,
      _sortKey: e.reflection!.updatedAtIso,
    }));

  // Governance events from audit log — only fetched when the user has audit_logs.view.
  let governanceItems: SortableItem[] = [];
  if (canViewAudit) {
    const governanceActions = ["role.assigned", "president.added", "president.removed", "presidency.transferred"] as const;
    type GovernanceAction = typeof governanceActions[number];

    const { data: auditRows } = await supabase
      .from("club_audit_logs")
      .select("id, actor_id, action, target_user_id, target_role_id, metadata, created_at")
      .eq("club_id", clubId)
      .in("action", [...governanceActions])
      .order("created_at", { ascending: false })
      .limit(5);

    if (auditRows && auditRows.length > 0) {
      // Batch-fetch profile names for all actor + target IDs.
      const profileIds = [
        ...new Set([
          ...auditRows.map((r) => r.actor_id),
          ...auditRows.filter((r) => r.target_user_id).map((r) => r.target_user_id as string),
        ]),
      ];
      const { data: profileRows } = await supabase
        .from("profiles")
        .select("id, full_name, email")
        .in("id", profileIds);

      const nameById = new Map(
        (profileRows ?? []).map((p) => [
          p.id,
          p.full_name?.trim() || p.email?.split("@")[0] || "Someone",
        ]),
      );

      const actionToType: Record<GovernanceAction, ActivityFeedItem["type"]> = {
        "role.assigned": "role_assigned",
        "president.added": "president_added",
        "president.removed": "president_removed",
        "presidency.transferred": "presidency_transferred",
      };

      type AuditRow = (typeof auditRows)[number];
      governanceItems = auditRows
        .filter((r): r is Omit<AuditRow, "action"> & { action: GovernanceAction } =>
          (governanceActions as readonly string[]).includes(r.action as string),
        )
        .map((r) => {
          // #region agent log
          fetch("http://127.0.0.1:7752/ingest/8564b646-700d-4bcb-a3b0-4286eed37fa8", {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "4152c2" },
            body: JSON.stringify({
              sessionId: "4152c2",
              location: "clubs/[clubId]/page.tsx:governanceItems.map",
              message: "governance audit row after narrow",
              data: { action: r.action, hypothesisId: "H2-Omit-narrow" },
              timestamp: Date.now(),
              runId: "post-fix",
            }),
          }).catch(() => {});
          // #endregion
          const actor = nameById.get(r.actor_id) ?? "Someone";
          const target = r.target_user_id ? (nameById.get(r.target_user_id) ?? "a member") : "a member";
          const meta = (r.metadata ?? {}) as Record<string, unknown>;
          const roleName = typeof meta.role_name === "string" ? meta.role_name : null;

          let message: string;
          switch (r.action) {
            case "role.assigned":
              message = roleName
                ? `${actor} assigned the ${roleName} role to ${target}`
                : `${actor} assigned a role to ${target}`;
              break;
            case "president.added":
              message = `${actor} added ${target} as President`;
              break;
            case "president.removed":
              message = `${actor} removed ${target} from Presidency`;
              break;
            case "presidency.transferred":
              message = `${actor} transferred Presidency to ${target}`;
              break;
          }

          return {
            id: `audit-${r.id}`,
            type: actionToType[r.action],
            message,
            displayTime: formatActivityTime(r.created_at),
            href: `/clubs/${club.id}/settings/governance`,
            _sortKey: r.created_at,
          };
        });
    }
  }

  const activityItems: ActivityFeedItem[] = [...rpcItems, ...reflectionItems, ...governanceItems]
    .sort((a, b) => b._sortKey.localeCompare(a._sortKey))
    .slice(0, 8)
    .map(({ _sortKey: _, ...item }) => item);

  return (
    <section className="space-y-8">
      {/* Hero header */}
      <header className="card-surface border-2 border-slate-200 bg-gradient-to-br from-slate-50 to-blue-50 p-8">
        <div className="max-w-4xl">
          <p className="section-kicker text-slate-600">Club Command Center</p>
          <h1 className="section-title mt-3 text-3xl md:text-4xl">{club.name}</h1>
          <p className="section-subtitle mt-4 max-w-2xl text-lg text-slate-700">{club.description}</p>

          <div className="mt-8 grid gap-6 md:grid-cols-3">
            <div className="flex items-center gap-3">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-blue-100">
                <svg className="h-6 w-6 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z" />
                </svg>
              </div>
              <div>
                <p className="text-sm font-medium text-slate-600">Members</p>
                <p className="text-xl font-bold text-slate-900">{memberCount}</p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-green-100">
                <svg className="h-6 w-6 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <div>
                <p className="text-sm font-medium text-slate-600">Your Role</p>
                <p className="text-xl font-bold text-slate-900 capitalize">{club.currentUserRole}</p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-purple-100">
                <svg className="h-6 w-6 text-purple-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
              </div>
              <div>
                <p className="text-sm font-medium text-slate-600">Status</p>
                <p className="text-xl font-bold text-slate-900">
                  {club.events.length > 0 ? "Active" : "Getting Started"}
                </p>
              </div>
            </div>
          </div>

          {/* Quick actions — only shown when the user has relevant permissions */}
          {(canInviteMembers || canCreateEvents) && (
            <div className="mt-8 flex flex-col gap-4 sm:flex-row sm:gap-3">
              {canInviteMembers && (
                <Link href={`/clubs/${club.id}/members#invite-members`} className="btn-primary px-6 py-3 text-base font-semibold">
                  Invite Members
                </Link>
              )}
              {canCreateEvents && (
                <Link href={`/clubs/${club.id}/events#create-event`} className="btn-secondary px-6 py-3 text-base font-semibold">
                  Create Event
                </Link>
              )}
              {myTasks.length > 0 && (
                <Link href={`/clubs/${club.id}/tasks`} className="btn-secondary px-6 py-3 text-base font-semibold">
                  View My Tasks ({myTasks.length})
                </Link>
              )}
            </div>
          )}
        </div>
      </header>

      {/* Important Now */}
      <div className="card-surface p-6">
        <div className="section-card-header">
          <div>
            <p className="section-kicker">Now</p>
            <h2 className="mt-1 text-base font-semibold tracking-tight text-slate-900">Important Now</h2>
            <p className="mt-1 text-sm text-slate-600">Key updates and priorities for your club.</p>
          </div>
        </div>

        <div className="mt-5 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {/* Next event */}
          <div className="surface-subcard border-l-4 border-blue-500 p-4">
            <div className="flex items-start gap-3">
              <div className="flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-lg bg-blue-100">
                <svg className="h-5 w-5 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                </svg>
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-xs font-semibold uppercase tracking-[0.1em] text-slate-500">Next Event</p>
                <p className="mt-1 text-sm font-semibold text-slate-900 leading-snug">
                  {nextEvent ? nextEvent.title : "No upcoming events"}
                </p>
                {nextEvent ? (
                  <p className="mt-1 text-xs text-slate-500 truncate">{nextEvent.eventDate} · {nextEvent.location}</p>
                ) : (
                  <p className="mt-1 text-xs text-slate-500">Schedule one on the Events page.</p>
                )}
              </div>
            </div>
          </div>

          {/* Latest announcement */}
          <div className="surface-subcard border-l-4 border-amber-500 p-4">
            <div className="flex items-start gap-3">
              <div className="flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-lg bg-amber-100">
                <svg className="h-5 w-5 text-amber-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5.882V19.24a1.76 1.76 0 01-3.417.592l-2.147-6.15M18 13a3 3 0 100-6M5.436 13.683A4.001 4.001 0 017 6h1.832c4.1 0 7.625-1.234 9.168-3v14c-1.543-1.766-5.067-3-9.168-3H7a3.988 3.988 0 01-1.564-.317z" />
                </svg>
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-xs font-semibold uppercase tracking-[0.1em] text-slate-500">Latest Announcement</p>
                <p className="mt-1 text-sm font-semibold text-slate-900 leading-snug">
                  {latestAnnouncement ? latestAnnouncement.title : "No announcements yet"}
                </p>
                {latestAnnouncement ? (
                  <p className="mt-1 text-xs text-slate-500 line-clamp-2">{latestAnnouncement.content}</p>
                ) : (
                  <p className="mt-1 text-xs text-slate-500">Post one on the Announcements page.</p>
                )}
              </div>
            </div>
          </div>

          {/* My Tasks */}
          <div className="surface-subcard border-l-4 border-emerald-500 p-4">
            <div className="flex items-start gap-3">
              <div className="flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-lg bg-emerald-100">
                <svg className="h-5 w-5 text-emerald-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
                </svg>
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-xs font-semibold uppercase tracking-[0.1em] text-slate-500">My Tasks</p>
                {myTasks.length > 0 ? (
                  <>
                    <p className="mt-1 text-sm font-semibold text-slate-900 leading-snug">
                      {myTasks.length} open task{myTasks.length !== 1 ? "s" : ""}
                    </p>
                    <p className="mt-1 text-xs text-slate-500 truncate">
                      {myTasks.filter((t) => t.isOverdue).length > 0
                        ? `${myTasks.filter((t) => t.isOverdue).length} overdue`
                        : myTasks[0]?.title}
                    </p>
                  </>
                ) : (
                  <>
                    <p className="mt-1 text-sm font-semibold text-slate-900 leading-snug">All caught up</p>
                    <p className="mt-1 text-xs text-slate-500">No tasks assigned to you.</p>
                  </>
                )}
              </div>
            </div>
          </div>

          {/* Key stats */}
          <div className="surface-subcard border-l-4 border-purple-500 p-4">
            <div className="flex items-start gap-3">
              <div className="flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-lg bg-emerald-100">
                <svg className="h-5 w-5 text-emerald-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-xs font-semibold uppercase tracking-[0.1em] text-slate-500">Key Stats</p>
                <p className="mt-1 text-sm font-semibold text-slate-900 leading-snug">
                  {club.events.length} events · {club.announcements.length} updates
                </p>
                <p className="mt-1 text-xs text-slate-500">
                  {club.totalTrackedEvents} tracked · {club.clubAverageAttendance}% avg attendance
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Attention Needed — shown to users with management permissions */}
      {showManagementAlerts && (
        <ClubAttentionNeededSection clubId={club.id} alerts={club.attentionAlerts} />
      )}

      {/* Recent Activity — visible to all members */}
      <ClubActivityFeed items={activityItems} />
    </section>
  );
}
