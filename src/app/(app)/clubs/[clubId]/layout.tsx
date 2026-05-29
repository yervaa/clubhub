import Link from "next/link";
import type { ReactNode } from "react";
import { ClubCoverHeader } from "@/components/ui/club-cover-header";
import { ClubSubnav } from "@/components/ui/club-subnav";
import { getClubNameAndStatusIfMember } from "@/lib/clubs/club-status";
import { getUserPermissions } from "@/lib/rbac/permissions";
import { createClient } from "@/lib/supabase/server";

type ClubLayoutProps = {
  children: ReactNode;
  params: Promise<{ clubId: string }>;
};

export default async function ClubLayout({ children, params }: ClubLayoutProps) {
  const { clubId } = await params;
  const [shell, supabase] = await Promise.all([getClubNameAndStatusIfMember(clubId), createClient()]);
  const {
    data: { user },
  } = await supabase.auth.getUser();
  const userPermissions: Set<string> = user ? await getUserPermissions(user.id, clubId) : new Set<string>();
  const canViewSettings =
    userPermissions.has("club.manage_settings") ||
    userPermissions.has("roles.create") ||
    userPermissions.has("roles.edit");
  const canAccessAdvisor =
    userPermissions.has("events.approve") || userPermissions.has("announcements.approve");
  const canInviteMembers = userPermissions.has("members.invite");
  const canCreateEvents = userPermissions.has("events.create");
  const isArchived = shell?.status === "archived";
  const coverActions =
    shell && !isArchived && (canInviteMembers || canCreateEvents) ? (
      <>
        {canInviteMembers ? (
          <Link href={`/clubs/${clubId}/members#invite-members`} className="btn-primary text-sm">
            Invite Members
          </Link>
        ) : null}
        {canCreateEvents ? (
          <Link href={`/clubs/${clubId}/events#create-event`} className="btn-secondary text-sm">
            Create Event
          </Link>
        ) : null}
      </>
    ) : null;

  return (
    <section className="space-y-4 lg:space-y-6">
      {shell ? (
        <div className="club-workspace-chrome -mx-3 sm:-mx-4 md:-mx-6">
          <ClubCoverHeader
            clubName={shell.name}
            memberCount={shell.memberCount}
            userRole={shell.userRole}
            isArchived={isArchived}
            actions={coverActions}
          />
          <div className="club-workspace-subnav px-3 sm:px-4 md:px-6">
            <ClubSubnav clubId={clubId} canViewSettings={canViewSettings} canAccessAdvisor={canAccessAdvisor} />
          </div>
        </div>
      ) : null}
      {shell?.status === "archived" && (
        <div className="rounded-xl border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-950 shadow-sm">
          <p className="font-semibold">Archived club</p>
          <p className="mt-1 text-amber-950/90">
            {shell.name} is archived: it does not appear in active club lists, new members cannot join, and editing
            actions are turned off. You can still browse history or use{" "}
            <a href={`/clubs/${clubId}/settings/club`} className="font-semibold underline">
              Club &amp; exit
            </a>{" "}
            to leave or delete (Presidents).
          </p>
        </div>
      )}
      {children}
    </section>
  );
}
