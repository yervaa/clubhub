"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

type ClubSubnavProps = {
  clubId: string;
};

const CLUB_TABS = [
  { label: "Overview", href: "" },
  { label: "Events", href: "/events" },
  { label: "Members", href: "/members" },
  { label: "Announcements", href: "/announcements" },
  { label: "Insights", href: "/insights" },
] as const;

export function ClubSubnav({ clubId }: ClubSubnavProps) {
  const pathname = usePathname();
  const basePath = `/clubs/${clubId}`;

  return (
    <nav aria-label="Club sections">
      <div className="club-subnav">
        <ul className="club-subnav-list" role="list">
          {CLUB_TABS.map((tab) => {
            const href = `${basePath}${tab.href}`;
            const isActive = pathname === href;

            return (
              <li key={href}>
                <Link
                  href={href}
                  aria-current={isActive ? "page" : undefined}
                  className={`club-subnav-link${isActive ? " is-active" : ""}`}
                >
                  {tab.label}
                </Link>
              </li>
            );
          })}
        </ul>
      </div>
    </nav>
  );
}
