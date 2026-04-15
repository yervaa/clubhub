import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import { getUserPermissions } from "@/lib/rbac/permissions";
import { getMembersWithRoles } from "@/lib/rbac/role-actions";
import { ClubVolunteerHoursOverview } from "@/components/ui/club-volunteer-hours-overview";
import { getClubDetailForVolunteerHoursForCurrentUser } from "@/lib/clubs/queries";
import { mergeClubRosterIdentities } from "@/lib/clubs/merge-club-roster-identities";
import { PageIntro } from "@/components/ui/page-intro";

export default async function ClubVolunteerHoursPage({ params }: { params: Promise<{ clubId: string }> }) {
  const { clubId } = await params;

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const [club, membersResult, userPermissions] = await Promise.all([
    getClubDetailForVolunteerHoursForCurrentUser(clubId),
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
      <PageIntro
        kicker="Members"
        title="Volunteer hours"
        description={`See each member's service total and open a row to review entries or log time${canManageVolunteerHours ? "" : " (read-only for you)"}.`}
        actions={
          <Link href={`/clubs/${clubId}/members`} className="btn-secondary">
            Back to roster
          </Link>
        }
      />

      <ClubVolunteerHoursOverview clubId={clubId} members={clubForUi.members} canManage={canManageVolunteerHours} />
    </section>
  );
}
