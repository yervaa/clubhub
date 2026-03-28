"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

type SettingsSubnavProps = {
  clubId: string;
};

const SETTINGS_TABS = [
  { label: "Roles & Permissions", href: "" },
  { label: "Governance", href: "/governance" },
] as const;

export function SettingsSubnav({ clubId }: SettingsSubnavProps) {
  const pathname = usePathname();
  const basePath = `/clubs/${clubId}/settings`;

  return (
    <nav aria-label="Settings sections">
      <div className="flex gap-1 rounded-xl border border-slate-200 bg-slate-50 p-1">
        {SETTINGS_TABS.map((tab) => {
          const href = `${basePath}${tab.href}`;
          const isActive = tab.href === "" ? pathname === basePath : pathname.startsWith(href);

          return (
            <Link
              key={href}
              href={href}
              aria-current={isActive ? "page" : undefined}
              className={`flex-1 rounded-lg px-4 py-2 text-center text-sm font-semibold transition-all ${
                isActive
                  ? "bg-white text-slate-900 shadow-sm"
                  : "text-slate-500 hover:bg-white/60 hover:text-slate-700"
              }`}
            >
              {tab.label}
            </Link>
          );
        })}
      </div>
    </nav>
  );
}
