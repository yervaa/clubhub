"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { NavIcon, type NavIconName } from "@/components/layout/nav-icons";

const MOBILE_BOTTOM_TABS: ReadonlyArray<{
  href: string;
  label: string;
  icon: NavIconName;
}> = [
  { href: "/dashboard", label: "Home", icon: "home" },
  { href: "/my-clubs", label: "Clubs", icon: "users" },
  { href: "/events", label: "Events", icon: "calendar-event" },
  { href: "/announcements", label: "News", icon: "speakerphone" },
  { href: "/activity", label: "Activity", icon: "activity" },
];

type MobileBottomNavProps = {
  unreadNotificationCount?: number;
  className?: string;
};

function isTabActive(pathname: string, href: string): boolean {
  if (href === "/dashboard") {
    return pathname === href;
  }
  return pathname === href || pathname.startsWith(`${href}/`);
}

export function MobileBottomNav({ unreadNotificationCount = 0, className = "" }: MobileBottomNavProps) {
  const pathname = usePathname();
  const showActivityDot = unreadNotificationCount > 0;

  return (
    <nav
      aria-label="Primary"
      className={["mobile-bottom-nav", "md:hidden", className].filter(Boolean).join(" ")}
    >
      <ul className="mobile-bottom-nav-list" role="list">
        {MOBILE_BOTTOM_TABS.map((tab) => {
          const active = isTabActive(pathname, tab.href);
          const isActivity = tab.href === "/activity";

          return (
            <li key={tab.href} className="mobile-bottom-nav-item-wrap">
              <Link
                href={tab.href}
                aria-current={active ? "page" : undefined}
                className={`mobile-bottom-nav-item${active ? " is-active" : ""}`}
              >
                <span className="mobile-bottom-nav-icon-wrap">
                  <NavIcon name={tab.icon} className="mobile-bottom-nav-icon" width={22} height={22} />
                  {isActivity && showActivityDot ? (
                    <span className="mobile-bottom-nav-dot" aria-hidden />
                  ) : null}
                </span>
                <span className="mobile-bottom-nav-label">{tab.label}</span>
              </Link>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}
