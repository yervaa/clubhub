import type { ReactNode } from "react";
import { ClubMembersSubnav } from "@/components/ui/club-members-subnav";

type MembersLayoutProps = {
  children: ReactNode;
  params: Promise<{ clubId: string }>;
};

export default async function MembersLayout({ children, params }: MembersLayoutProps) {
  const { clubId } = await params;

  return (
    <div className="space-y-4 lg:space-y-5">
      <ClubMembersSubnav clubId={clubId} />
      {children}
    </div>
  );
}
