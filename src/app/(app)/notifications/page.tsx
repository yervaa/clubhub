import { unstable_noStore as noStore } from "next/cache";
import Link from "next/link";
import { getRecentNotifications, getUnreadNotificationCount } from "@/lib/notifications/queries";
import type { NotificationItem } from "@/lib/notifications/queries";
import { markAllNotificationsReadAction } from "@/lib/notifications/actions";

// ─── Relative time formatter ──────────────────────────────────────────────────

function formatTime(isoString: string): string {
  const now = new Date();
  const then = new Date(isoString);
  const diffMs = now.getTime() - then.getTime();
  const diffMins = Math.floor(diffMs / 60_000);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffMins < 1) return "just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays === 1) return "yesterday";
  if (diffDays < 7) return `${diffDays}d ago`;
  return then.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}

function isToday(isoString: string): boolean {
  const then = new Date(isoString);
  const now = new Date();
  return then.toDateString() === now.toDateString();
}

// ─── Icon helpers ─────────────────────────────────────────────────────────────

type TypeConfig = {
  bg: string;
  text: string;
  label: string;
  icon: React.ReactNode;
};

function getTypeConfig(type: string): TypeConfig {
  switch (type) {
    case "announcement.posted":
      return {
        bg: "bg-amber-100",
        text: "text-amber-600",
        label: "Announcement",
        icon: (
          <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5.882V19.24a1.76 1.76 0 01-3.417.592l-2.147-6.15M18 13a3 3 0 100-6M5.436 13.683A4.001 4.001 0 017 6h1.832c4.1 0 7.625-1.234 9.168-3v14c-1.543-1.766-5.067-3-9.168-3H7a3.988 3.988 0 01-1.564-.317z" />
          </svg>
        ),
      };
    case "event.created":
      return {
        bg: "bg-blue-100",
        text: "text-blue-600",
        label: "Event",
        icon: (
          <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
          </svg>
        ),
      };
    case "role.assigned":
      return {
        bg: "bg-violet-100",
        text: "text-violet-600",
        label: "Role assigned",
        icon: (
          <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4M7.835 4.697a3.42 3.42 0 001.946-.806 3.42 3.42 0 014.438 0 3.42 3.42 0 001.946.806 3.42 3.42 0 013.138 3.138 3.42 3.42 0 00.806 1.946 3.42 3.42 0 010 4.438 3.42 3.42 0 00-.806 1.946 3.42 3.42 0 01-3.138 3.138 3.42 3.42 0 00-1.946.806 3.42 3.42 0 01-4.438 0 3.42 3.42 0 00-1.946-.806 3.42 3.42 0 01-3.138-3.138 3.42 3.42 0 00-.806-1.946 3.42 3.42 0 010-4.438 3.42 3.42 0 00.806-1.946 3.42 3.42 0 013.138-3.138z" />
          </svg>
        ),
      };
    case "role.removed":
      return {
        bg: "bg-orange-100",
        text: "text-orange-600",
        label: "Role removed",
        icon: (
          <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7a4 4 0 11-8 0 4 4 0 018 0zM9 14a6 6 0 00-6 6v1h12v-1a6 6 0 00-6-6zM21 12h-6" />
          </svg>
        ),
      };
    case "task.assigned":
      return {
        bg: "bg-emerald-100",
        text: "text-emerald-600",
        label: "Task assigned",
        icon: (
          <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
          </svg>
        ),
      };

    default:
      return {
        bg: "bg-slate-100",
        text: "text-slate-500",
        label: "Notification",
        icon: (
          <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
          </svg>
        ),
      };
  }
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default async function NotificationsPage() {
  noStore();

  const [notifications, unreadCount] = await Promise.all([
    getRecentNotifications(50),
    getUnreadNotificationCount(),
  ]);

  const todayItems = notifications.filter((n) => isToday(n.createdAt));
  const earlierItems = notifications.filter((n) => !isToday(n.createdAt));

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Notifications</h1>
          {unreadCount > 0 && (
            <p className="mt-0.5 text-sm text-slate-500">
              {unreadCount} unread notification{unreadCount !== 1 ? "s" : ""}
            </p>
          )}
        </div>
        {unreadCount > 0 && (
          <form action={markAllNotificationsReadAction}>
            <button
              type="submit"
              className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-600 transition hover:bg-slate-50 hover:text-slate-900"
            >
              Mark all as read
            </button>
          </form>
        )}
      </div>

      {/* Empty state */}
      {notifications.length === 0 && (
        <div className="rounded-xl border border-slate-200 bg-white px-6 py-16 text-center">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-slate-100">
            <svg className="h-6 w-6 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
            </svg>
          </div>
          <p className="mt-4 text-base font-semibold text-slate-700">No notifications yet</p>
          <p className="mt-1.5 text-sm text-slate-500">
            You will be notified when announcements are posted, events are created, or your roles change.
          </p>
          <Link
            href="/dashboard"
            className="mt-6 inline-block rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white transition hover:bg-slate-700"
          >
            Go to Dashboard
          </Link>
        </div>
      )}

      {/* Today */}
      {todayItems.length > 0 && (
        <section>
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-400">Today</h2>
          <NotificationList items={todayItems} />
        </section>
      )}

      {/* Earlier */}
      {earlierItems.length > 0 && (
        <section>
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-400">Earlier</h2>
          <NotificationList items={earlierItems} />
        </section>
      )}
    </div>
  );
}

// ─── Notification list ────────────────────────────────────────────────────────

function NotificationList({ items }: { items: NotificationItem[] }) {
  return (
    <ul className="overflow-hidden rounded-xl border border-slate-200 bg-white">
      {items.map((item, idx) => {
        const config = getTypeConfig(item.type);
        const content = (
          <div className={`flex items-start gap-4 px-5 py-4 ${!item.isRead ? "bg-blue-50/40" : ""}`}>
            <div
              className={`mt-0.5 flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-full ${config.bg} ${config.text}`}
            >
              {config.icon}
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex items-start justify-between gap-3">
                <p className={`text-sm leading-snug ${!item.isRead ? "font-semibold text-slate-900" : "font-medium text-slate-700"}`}>
                  {item.title}
                </p>
                {!item.isRead && (
                  <span className="mt-1 h-2 w-2 flex-shrink-0 rounded-full bg-slate-900" />
                )}
              </div>
              {item.body && (
                <p className="mt-0.5 text-sm text-slate-500">{item.body}</p>
              )}
              <p className="mt-1.5 flex items-center gap-1.5 text-xs text-slate-400">
                <span className="rounded-full bg-slate-100 px-1.5 py-0.5 font-medium text-slate-500">
                  {config.label}
                </span>
                <span>·</span>
                <span>{formatTime(item.createdAt)}</span>
              </p>
            </div>
          </div>
        );

        return (
          <li key={item.id} className={idx > 0 ? "border-t border-slate-100" : ""}>
            {item.href ? (
              <Link href={item.href} className="block transition hover:bg-slate-50">
                {content}
              </Link>
            ) : (
              <div>{content}</div>
            )}
          </li>
        );
      })}
    </ul>
  );
}
