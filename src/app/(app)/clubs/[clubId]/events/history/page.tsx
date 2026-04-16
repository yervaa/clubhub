import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import { getUserPermissions } from "@/lib/rbac/permissions";
import { ClubEventPastFoldable } from "@/components/ui/club-event-past-foldable";
import { getClubDetailForEventsForCurrentUser } from "@/lib/clubs/queries";
import { partitionEventsByLifecycle } from "@/lib/clubs/event-lifecycle";
import { PageIntro } from "@/components/ui/page-intro";
import { PageEmptyState } from "@/components/ui/page-patterns";

type PageProps = {
  params: Promise<{ clubId: string }>;
};

export default async function ClubEventHistoryPage({ params }: PageProps) {
  const { clubId } = await params;

  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const [club, userPermissions] = await Promise.all([
    getClubDetailForEventsForCurrentUser(clubId),
    getUserPermissions(user.id, clubId),
  ]);

  if (!club) {
    notFound();
  }

  const now = new Date();
  const { past } = partitionEventsByLifecycle(club.events, now);
  const canCreateEvents = userPermissions.has("events.create");
  const canEditEvents = userPermissions.has("events.edit");
  const canDeleteEvents = userPermissions.has("events.delete");
  const canMarkAttendance = userPermissions.has("attendance.mark");
  const canManageReflections = userPermissions.has("reflections.create");
  const canViewAggregatedStats =
    userPermissions.has("attendance.mark") ||
    userPermissions.has("attendance.edit") ||
    userPermissions.has("reflections.create") ||
    userPermissions.has("reflections.edit") ||
    userPermissions.has("events.edit");

  const cardPropsBase = {
    club,
    query: {},
    memberCount: club.memberCount,
    now,
    canCreateEvents,
    canEditEvents,
    canDeleteEvents,
    canMarkAttendance,
    canManageReflections,
    canViewAggregatedStats,
  };

  return (
    <section className="space-y-6">
      <PageIntro
        kicker="Archive"
        title="Event history"
        description="Every completed event stays on record. Expand rows for RSVP, attendance, and reflection details."
        actions={
          <>
            <Link href={`/clubs/${clubId}/events`} className="btn-secondary">
              Back to events
            </Link>
            {userPermissions.has("insights.view") ? (
              <Link href={`/clubs/${clubId}/insights`} className="btn-secondary">
                Club insights
              </Link>
            ) : null}
          </>
        }
      />

      {past.length === 0 ? (
        <PageEmptyState
          title="No past events yet"
          copy="When events end, they appear here for your club timeline."
          action={
            <Link href={`/clubs/${clubId}/events`} className="btn-primary">
              Go to events
            </Link>
          }
        />
      ) : (
        <div className="space-y-3">
          <p className="text-sm text-slate-600">
            <span className="font-semibold text-slate-800">{past.length}</span> past event{past.length === 1 ? "" : "s"}, newest first.
          </p>
          {past.map((event) => (
            <ClubEventPastFoldable key={event.id} {...cardPropsBase} event={event} />
          ))}
        </div>
      )}
    </section>
  );
}
