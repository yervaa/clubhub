"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { APP_PRIMARY_NAV, APP_SECONDARY_NAV } from "@/components/layout/navigation-config";
import type { UserClub } from "@/lib/clubs/queries";
import { getActiveClubId, isPathActive } from "@/lib/routing/nav-active";

type AppSidebarProps = {
  clubs: UserClub[];
};

export function AppSidebar({ clubs }: AppSidebarProps) {
  const pathname = usePathname();
  const activeClubId = getActiveClubId(pathname);

  return (
    <aside className="hidden w-56 flex-none border-r border-slate-200 bg-white lg:block">
      <div className="sticky top-16 flex min-h-[calc(100vh-4rem)] flex-col p-4">
        {/* Top navigation */}
        <nav className="space-y-0.5">
          {APP_PRIMARY_NAV.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              className={`block rounded-lg px-3 py-2.5 text-sm font-medium transition ${
                isPathActive(pathname, link.href, link.match)
                  ? "bg-slate-100 text-slate-900"
                  : "text-slate-600 hover:bg-slate-100 hover:text-slate-900"
              }`}
            >
              {link.label}
            </Link>
          ))}
          {APP_SECONDARY_NAV.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              className={`block rounded-lg px-3 py-2 text-sm transition ${
                isPathActive(pathname, link.href, link.match)
                  ? "bg-slate-100 font-medium text-slate-800"
                  : "text-slate-500 hover:bg-slate-50 hover:text-slate-800"
              }`}
            >
              {link.label}
            </Link>
          ))}
        </nav>

        {/* Your Clubs quick-jump */}
        {clubs.length > 0 && (
          <div className="mt-6">
            <p className="mb-1.5 px-3 text-xs font-semibold uppercase tracking-[0.08em] text-slate-400">
              Your Clubs
            </p>
            <nav className="space-y-0.5">
              {clubs.map((club) => {
                const active = activeClubId === club.id;
                return (
                  <Link
                    key={club.id}
                    href={`/clubs/${club.id}`}
                    className={`flex items-center gap-2 rounded-lg px-3 py-2.5 text-sm transition ${
                      active
                        ? "bg-slate-900 font-semibold text-white"
                        : "font-medium text-slate-600 hover:bg-slate-100 hover:text-slate-900"
                    }`}
                  >
                    <span className="min-w-0 flex-1 truncate">{club.name}</span>
                    {club.role === "officer" && (
                      <span
                        className={`flex-shrink-0 rounded-full px-1.5 py-0.5 text-[10px] font-semibold ${
                          active
                            ? "bg-white/20 text-white"
                            : "bg-slate-100 text-slate-500"
                        }`}
                      >
                        Officer
                      </span>
                    )}
                  </Link>
                );
              })}
            </nav>
          </div>
        )}
      </div>
    </aside>
  );
}
