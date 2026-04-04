import type { ReactNode } from "react";
import { ClubSubnav } from "@/components/ui/club-subnav";
import { getClubNameAndStatusIfMember } from "@/lib/clubs/club-status";

type ClubLayoutProps = {
  children: ReactNode;
  params: Promise<{ clubId: string }>;
};

export default async function ClubLayout({ children, params }: ClubLayoutProps) {
  const { clubId } = await params;
  const shell = await getClubNameAndStatusIfMember(clubId);

  return (
    <section className="space-y-4 lg:space-y-6">
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
      <ClubSubnav clubId={clubId} />
      {children}
    </section>
  );
}
