"use client";

import { usePathname } from "next/navigation";
import { ResponsiveSubnav } from "@/components/ui/responsive-subnav";

type SettingsSubnavProps = {
  clubId: string;
};

const SETTINGS_TABS = [
  { label: "Roles & Permissions", href: "" },
  { label: "Governance", href: "/governance" },
  { label: "Club & exit", href: "/club" },
] as const;

export function SettingsSubnav({ clubId }: SettingsSubnavProps) {
  const pathname = usePathname();
  const basePath = `/clubs/${clubId}/settings`;
  const items = SETTINGS_TABS.map((tab) => {
    const href = `${basePath}${tab.href}`;
    const active =
      tab.href === ""
        ? pathname === basePath
        : tab.href === "/club"
          ? pathname === `${basePath}/club` || pathname.startsWith(`${basePath}/club/`)
          : pathname.startsWith(href);
    return { label: tab.label, href, active };
  });

  return (
    <ResponsiveSubnav items={items} ariaLabel="Settings sections" pickerLabel="Settings section" />
  );
}
