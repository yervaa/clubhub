import type { ReactNode } from "react";
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

  return (
    <section className="space-y-4 lg:space-y-6">
      {shell ? (
        <header className="rounded-xl border border-slate-200 bg-white px-4 py-3 shadow-sm sm:px-5 sm:py-4">
          <p className="section-kicker">Club workspace</p>
          <div className="mt-1 flex items-center gap-2">
            <h1 className="text-lg font-semibold tracking-tight text-slate-900 sm:text-xl">{shell.name}</h1>
            {shell.status === "archived" ? (
              <span className="rounded-full bg-amber-100 px-2 py-0.5 text-xs font-semibold text-amber-900">Archived</span>
            ) : null}
          </div>
        </header>
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
      <ClubSubnav clubId={clubId} canViewSettings={canViewSettings} canAccessAdvisor={canAccessAdvisor} />
      {children}
    </section>
  );
}
