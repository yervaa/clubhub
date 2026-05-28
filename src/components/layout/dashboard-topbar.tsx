import Link from "next/link";
import { logoutAction } from "@/app/auth/actions";
import { getMemberRosterInitials } from "@/lib/member-display";

type DashboardTopbarProps = {
  greetingName: string;
  unreadNotificationCount: number;
  userDisplayLabel: string;
};

function getTimeGreeting(): string {
  const hour = new Date().getHours();
  if (hour < 12) return "Good morning";
  if (hour < 17) return "Good afternoon";
  return "Good evening";
}

function NotificationsBellIcon({ className }: { className?: string }) {
  return (
    <svg className={className} width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" aria-hidden>
      <path
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"
      />
    </svg>
  );
}

export function DashboardTopbar({
  greetingName,
  unreadNotificationCount,
  userDisplayLabel,
}: DashboardTopbarProps) {
  const greeting = getTimeGreeting();
  const initials = getMemberRosterInitials({ fullName: userDisplayLabel, email: null });

  return (
    <header className="dashboard-topbar -mx-3 mb-6 flex items-center justify-between gap-3 border-b border-slate-200 bg-white px-3 py-4 sm:-mx-4 sm:px-4 md:-mx-6 md:px-6">
      <h1 className="app-page-title min-w-0 flex-1 truncate">
        {greeting}, {greetingName}
      </h1>
      <div className="flex shrink-0 items-center gap-2 sm:gap-3">
        <Link
          href="/notifications"
          className="relative flex h-10 w-10 items-center justify-center rounded-full text-slate-600 transition hover:bg-slate-100 hover:text-slate-900"
          aria-label={
            unreadNotificationCount > 0
              ? `Notifications, ${unreadNotificationCount} unread`
              : "Notifications"
          }
        >
          <NotificationsBellIcon />
          {unreadNotificationCount > 0 ? (
            <span className="absolute right-1.5 top-1.5 h-2 w-2 rounded-full bg-red-500 ring-2 ring-white" aria-hidden />
          ) : null}
        </Link>
        <Link
          href="/settings"
          className="member-avatar is-current-user flex h-10 w-10 items-center justify-center text-sm font-bold"
          aria-label="Account settings"
          title={userDisplayLabel}
        >
          {initials}
        </Link>
        <form action={logoutAction} className="hidden md:block">
          <button
            type="submit"
            className="rounded-lg px-2.5 py-2 text-sm font-medium text-slate-600 transition hover:bg-slate-100 hover:text-slate-900"
          >
            Log out
          </button>
        </form>
      </div>
    </header>
  );
}

export function resolveDashboardGreetingName(
  fullName: string | null | undefined,
  email: string | null | undefined,
): string {
  const first = fullName?.trim().split(/\s+/).filter(Boolean)[0];
  if (first) return first;
  const prefix = email?.split("@")[0]?.trim();
  if (prefix) return prefix;
  return "there";
}
