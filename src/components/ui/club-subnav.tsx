"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";

type ClubSubnavProps = {
  clubId: string;
};

const CLUB_TABS = [
  { label: "Overview", href: "" },
  { label: "Events", href: "/events" },
  { label: "Members", href: "/members" },
  { label: "Announcements", href: "/announcements" },
  { label: "Tasks", href: "/tasks" },
  { label: "Insights", href: "/insights" },
  { label: "Settings", href: "/settings" },
] as const;

export function ClubSubnav({ clubId }: ClubSubnavProps) {
  const pathname = usePathname();
  const router = useRouter();
  const basePath = `/clubs/${clubId}`;

  function activeHrefForPicker(): string {
    for (const tab of CLUB_TABS) {
      const href = `${basePath}${tab.href}`;
      if (tab.href === "/settings" || tab.href === "/tasks") {
        if (pathname.startsWith(href)) return href;
      } else if (pathname === href) {
        return href;
      }
    }
    if (pathname.startsWith(`${basePath}/events`)) return `${basePath}/events`;
    if (pathname.startsWith(`${basePath}/members`)) return `${basePath}/members`;
    if (pathname.startsWith(`${basePath}/announcements`)) return `${basePath}/announcements`;
    if (pathname.startsWith(`${basePath}/insights`)) return `${basePath}/insights`;
    return basePath;
  }

  const currentHref = activeHrefForPicker();

  return (
    <nav aria-label="Club sections" className="space-y-2">
      {/* Mobile: single control — avoids cramped horizontal tabs */}
      <div className="lg:hidden">
        <label htmlFor="club-section-picker" className="sr-only">
          Club section
        </label>
        <select
          id="club-section-picker"
          value={currentHref}
          onChange={(e) => router.push(e.target.value)}
          className="w-full rounded-xl border border-slate-200 bg-white py-3 pl-3 pr-10 text-sm font-semibold text-slate-800 shadow-sm focus:border-slate-400 focus:outline-none focus:ring-2 focus:ring-slate-200"
        >
          {CLUB_TABS.map((tab) => {
            const href = `${basePath}${tab.href}`;
            return (
              <option key={href} value={href}>
                {tab.label}
              </option>
            );
          })}
        </select>
      </div>

      {/* Desktop: horizontal tabs */}
      <div className="club-subnav hidden lg:block">
        <ul className="club-subnav-list" role="list">
          {CLUB_TABS.map((tab) => {
            const href = `${basePath}${tab.href}`;
            const isActive =
              tab.href === "/settings" || tab.href === "/tasks"
                ? pathname.startsWith(href)
                : tab.href === "/members"
                  ? pathname === href || pathname.startsWith(`${href}/`)
                  : pathname === href;

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
