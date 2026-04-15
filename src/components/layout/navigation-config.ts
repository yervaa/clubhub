import type { NavMatchMode } from "@/lib/routing/nav-active";

export type AppNavItem = {
  href: string;
  label: string;
  match?: NavMatchMode;
};

export const APP_PRIMARY_NAV: readonly AppNavItem[] = [
  { href: "/dashboard", label: "Dashboard", match: "exact" },
  { href: "/my-clubs", label: "My Clubs", match: "exact" },
  { href: "/events", label: "Events", match: "prefix" },
  { href: "/announcements", label: "Announcements", match: "prefix" },
  { href: "/activity", label: "Activity", match: "prefix" },
];

export const APP_SECONDARY_NAV: readonly AppNavItem[] = [{ href: "/settings", label: "Settings", match: "prefix" }];
