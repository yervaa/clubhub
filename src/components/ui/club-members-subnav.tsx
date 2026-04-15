"use client";

import { usePathname } from "next/navigation";
import { ResponsiveSubnav } from "@/components/ui/responsive-subnav";

type ClubMembersSubnavProps = {
  clubId: string;
};

export function ClubMembersSubnav({ clubId }: ClubMembersSubnavProps) {
  const pathname = usePathname();
  const rosterHref = `/clubs/${clubId}/members`;
  const volunteerHref = `/clubs/${clubId}/members/volunteer-hours`;
  const isRoster = pathname === rosterHref;
  const isVolunteer = pathname.startsWith(volunteerHref);
  const items = [
    { label: "Roster", href: rosterHref, active: isRoster },
    { label: "Volunteer hours", href: volunteerHref, active: isVolunteer },
  ];

  return (
    <ResponsiveSubnav items={items} ariaLabel="Members sections" pickerLabel="Members section" />
  );
}
