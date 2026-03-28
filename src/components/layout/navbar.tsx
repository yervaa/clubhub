import Link from "next/link";
import { unstable_noStore as noStore } from "next/cache";
import { logoutAction } from "@/app/auth/actions";
import { createClient } from "@/lib/supabase/server";
import { getRecentNotifications, getUnreadNotificationCount } from "@/lib/notifications/queries";
import { NotificationBell } from "@/components/ui/notification-bell";

export async function Navbar() {
  noStore();

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  const [notifications, unreadCount] = user
    ? await Promise.all([getRecentNotifications(10), getUnreadNotificationCount()])
    : [[], 0];

  return (
    <header className="sticky top-0 z-30 border-b border-slate-200/80 bg-white/90 shadow-sm backdrop-blur">
      <nav className="mx-auto flex h-16 w-full max-w-7xl items-center justify-between px-4 sm:px-6">
        <Link href={user ? "/dashboard" : "/"} className="flex items-center gap-3 text-slate-900">
          <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-slate-900 text-sm font-bold text-white">CH</span>
          <span className="text-lg font-bold tracking-tight">ClubHub</span>
        </Link>
        <ul className="flex items-center gap-1 sm:gap-2">
          {user ? (
            <>
              <li>
                <NotificationBell unreadCount={unreadCount} notifications={notifications} />
              </li>
              <li className="hidden rounded-full border border-slate-200 bg-white px-3 py-1 text-sm text-slate-500 sm:block">
                {user.email}
              </li>
              <li>
                <form action={logoutAction}>
                  <button
                    type="submit"
                    className="rounded-md px-3 py-2 text-sm font-medium text-slate-600 transition hover:bg-slate-100 hover:text-slate-900"
                  >
                    Logout
                  </button>
                </form>
              </li>
            </>
          ) : (
            <>
              <li>
                <Link
                  href="/login"
                  className="rounded-md px-3 py-2 text-sm font-medium text-slate-600 transition hover:bg-slate-100 hover:text-slate-900"
                >
                  Log In
                </Link>
              </li>
              <li>
                <Link href="/signup" className="btn-primary px-4 py-2 text-sm">
                  Sign Up
                </Link>
              </li>
            </>
          )}
        </ul>
      </nav>
    </header>
  );
}
