import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import { getUserPermissions } from "@/lib/rbac/permissions";
import { getMembersWithRoles } from "@/lib/rbac/role-actions";
import { ClubVolunteerHoursOverview } from "@/components/ui/club-volunteer-hours-overview";
import { getClubDetailForCurrentUser } from "@/lib/clubs/queries";
import { mergeClubRosterIdentities } from "@/lib/clubs/merge-club-roster-identities";

export default async function ClubVolunteerHoursPage({ params }: { params: Promise<{ clubId: string }> }) {
  const { clubId } = await params;

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const [club, membersResult, userPermissions] = await Promise.all([
    getClubDetailForCurrentUser(clubId),
    getMembersWithRoles(clubId),
    getUserPermissions(user.id, clubId),
  ]);

  if (!club) notFound();

  const clubForUi = membersResult.ok ? mergeClubRosterIdentities(club, membersResult.data) : club;

  const canManageVolunteerHours =
    (userPermissions.has("members.manage_volunteer_hours") || clubForUi.currentUserRole === "officer") &&
    clubForUi.status !== "archived";

  return (
    <section className="space-y-4 lg:space-y-6">
      <header className="card-surface border border-slate-200/90 bg-gradient-to-br from-slate-50 to-emerald-50/50 p-4 shadow-sm sm:p-6 lg:border-2 lg:p-8">
        <div className="max-w-4xl">
          <p className="section-kicker text-slate-600">Members</p>
          <h1 className="section-title mt-1 text-xl sm:mt-2 sm:text-3xl md:text-4xl">Volunteer hours</h1>
          <p className="section-subtitle mt-2 max-w-2xl text-sm sm:mt-3 sm:text-base sm:text-lg text-slate-700">
            See every member&apos;s club service total and open a row to review entries or log time
            {canManageVolunteerHours ? "" : " (read-only for you)"}.
          </p>
          <div className="mt-4">
            <Link
              href={`/clubs/${clubId}/members`}
              className="text-sm font-semibold text-emerald-800 underline-offset-2 hover:underline"
            >
              ← Back to roster
            </Link>
          </div>
        </div>
      </header>

      <ClubVolunteerHoursOverview clubId={clubId} members={clubForUi.members} canManage={canManageVolunteerHours} />
    </section>
  );
}
