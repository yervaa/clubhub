import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import { getUserPermissions } from "@/lib/rbac/permissions";
import { ClubEventPastFoldable } from "@/components/ui/club-event-past-foldable";
import { getClubDetailForCurrentUser } from "@/lib/clubs/queries";
import { partitionEventsByLifecycle } from "@/lib/clubs/event-lifecycle";

type PageProps = {
  params: Promise<{ clubId: string }>;
};

export default async function ClubEventHistoryPage({ params }: PageProps) {
  const { clubId } = await params;

  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const [club, userPermissions] = await Promise.all([
    getClubDetailForCurrentUser(clubId),
    getUserPermissions(user.id, clubId),
  ]);

  if (!club) {
    notFound();
  }

  const now = new Date();
  const { past } = partitionEventsByLifecycle(club.events, now);
  const canCreateEvents = userPermissions.has("events.create");
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
    canMarkAttendance,
    canManageReflections,
    canViewAggregatedStats,
  };

  return (
    <section className="space-y-6">
      <header className="card-surface border-2 border-slate-200 bg-gradient-to-br from-slate-50 to-indigo-50/40 p-5 sm:p-8">
        <p className="section-kicker text-slate-600">Archive</p>
        <h1 className="section-title mt-2 text-2xl sm:mt-3 sm:text-3xl md:text-4xl">Event history</h1>
        <p className="section-subtitle mt-3 max-w-2xl text-base sm:mt-4 sm:text-lg text-slate-700">
          Every completed event stays on the record. Expand a row for details, your RSVP, attendance tools, and reflections
          (based on your permissions).
        </p>
        <div className="mt-5 flex flex-col gap-2 sm:mt-6 sm:flex-row sm:flex-wrap sm:gap-3">
          <Link href={`/clubs/${clubId}/events`} className="btn-secondary w-full text-center text-sm sm:w-auto">
            ← Back to events
          </Link>
          {userPermissions.has("insights.view") ? (
            <Link href={`/clubs/${clubId}/insights`} className="btn-secondary w-full text-center text-sm sm:w-auto">
              Club insights
            </Link>
          ) : null}
        </div>
      </header>

      {past.length === 0 ? (
        <div className="rounded-xl border border-dashed border-slate-200 bg-slate-50/80 p-10 text-center">
          <p className="font-semibold text-slate-900">No past events yet</p>
          <p className="mt-2 text-sm text-slate-600">When events end, they appear here for your club&apos;s timeline.</p>
          <Link href={`/clubs/${clubId}/events`} className="btn-primary mt-6 inline-block">
            Go to events
          </Link>
        </div>
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
