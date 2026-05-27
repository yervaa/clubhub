import type { NavIconName } from "@/components/layout/nav-icons";
import type { NavMatchMode } from "@/lib/routing/nav-active";

export type AppNavItem = {
  href: string;
  label: string;
  /** One-word label under the icon in the narrow sidebar */
  shortLabel: string;
  icon: NavIconName;
  match?: NavMatchMode;
};

export const APP_PRIMARY_NAV: readonly AppNavItem[] = [
  { href: "/dashboard", label: "Dashboard", shortLabel: "Home", icon: "home", match: "exact" },
  { href: "/my-clubs", label: "My Clubs", shortLabel: "Clubs", icon: "users", match: "exact" },
  { href: "/events", label: "Events", shortLabel: "Events", icon: "calendar-event", match: "prefix" },
  { href: "/announcements", label: "Announcements", shortLabel: "News", icon: "speakerphone", match: "prefix" },
  { href: "/activity", label: "Activity", shortLabel: "Feed", icon: "activity", match: "prefix" },
];

export const APP_SECONDARY_NAV: readonly AppNavItem[] = [
  { href: "/settings", label: "Settings", shortLabel: "Settings", icon: "settings", match: "prefix" },
];
