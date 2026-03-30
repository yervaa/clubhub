import type { ReactNode } from "react";
import { ClubSubnav } from "@/components/ui/club-subnav";

type ClubLayoutProps = {
  children: ReactNode;
  params: Promise<{ clubId: string }>;
};

export default async function ClubLayout({ children, params }: ClubLayoutProps) {
  const { clubId } = await params;

  return (
    <section className="space-y-4 lg:space-y-6">
      <ClubSubnav clubId={clubId} />
      {children}
    </section>
  );
}
