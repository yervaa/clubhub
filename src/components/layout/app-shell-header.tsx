"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { logoutAction } from "@/app/auth/actions";
import { MobileNavDrawer } from "@/components/layout/mobile-nav-drawer";
import { NotificationBell } from "@/components/ui/notification-bell";
import type { UserClub } from "@/lib/clubs/queries";
import { getMemberRosterInitials } from "@/lib/member-display";
import type { NotificationItem } from "@/lib/notifications/queries";

type AppShellHeaderProps = {
  clubs: UserClub[];
  unreadCount: number;
  notifications: NotificationItem[];
  userDisplayLabel: string;
};

function LogoutButton({ className }: { className?: string }) {
  return (
    <form action={logoutAction}>
      <button
        type="submit"
        className={
          className ??
          "rounded-lg px-2.5 py-2 text-sm font-medium text-slate-600 transition hover:bg-slate-100 hover:text-slate-900"
        }
      >
        Log out
      </button>
    </form>
  );
}

export function AppShellHeader({ clubs, unreadCount, notifications, userDisplayLabel }: AppShellHeaderProps) {
  const pathname = usePathname();
  if (pathname === "/dashboard") {
    return null;
  }

  const initials = getMemberRosterInitials({ fullName: userDisplayLabel, email: null });

  return (
    <>
      <header className="app-shell-header-mobile flex h-14 shrink-0 items-center justify-between gap-2 border-b border-slate-200 bg-white px-3 md:hidden">
        <MobileNavDrawer clubs={clubs} />
        <div className="flex items-center gap-1">
          <NotificationBell unreadCount={unreadCount} notifications={notifications} />
          <Link
            href="/settings"
            className="member-avatar is-current-user flex h-9 w-9 items-center justify-center text-sm font-bold"
            aria-label="Account settings"
            title={userDisplayLabel}
          >
            {initials}
          </Link>
        </div>
      </header>

      <header className="app-shell-header-desktop hidden h-14 shrink-0 items-center justify-end gap-2 border-b border-slate-200 bg-white px-4 md:flex lg:px-6">
        <NotificationBell unreadCount={unreadCount} notifications={notifications} />
        <Link
          href="/settings"
          className="member-avatar is-current-user flex h-9 w-9 items-center justify-center text-sm font-bold"
          aria-label="Account settings"
          title={userDisplayLabel}
        >
          {initials}
        </Link>
        <LogoutButton />
      </header>
    </>
  );
}
