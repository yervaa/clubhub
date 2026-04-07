"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

type ClubMembersSubnavProps = {
  clubId: string;
};

export function ClubMembersSubnav({ clubId }: ClubMembersSubnavProps) {
  const pathname = usePathname();
  const rosterHref = `/clubs/${clubId}/members`;
  const volunteerHref = `/clubs/${clubId}/members/volunteer-hours`;
  const isRoster = pathname === rosterHref;
  const isVolunteer = pathname.startsWith(volunteerHref);

  const linkClass = (active: boolean) =>
    `inline-flex items-center rounded-lg px-4 py-2.5 text-sm font-semibold transition sm:py-2 ${
      active
        ? "bg-slate-900 text-white shadow-sm"
        : "border border-slate-200 bg-white text-slate-700 shadow-sm hover:bg-slate-50"
    }`;

  return (
    <nav aria-label="Members sections" className="flex flex-wrap gap-2 border-b border-slate-200 pb-3">
      <Link href={rosterHref} className={linkClass(isRoster)} aria-current={isRoster ? "page" : undefined}>
        Roster
      </Link>
      <Link
        href={volunteerHref}
        className={linkClass(isVolunteer)}
        aria-current={isVolunteer ? "page" : undefined}
      >
        Volunteer hours
      </Link>
    </nav>
  );
}
