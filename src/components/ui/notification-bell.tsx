"use client";

import { useState, useRef, useEffect, useTransition } from "react";
import Link from "next/link";
import { markNotificationReadAction, markAllNotificationsReadAction } from "@/lib/notifications/actions";
import type { NotificationItem } from "@/lib/notifications/queries";

function notificationsSignature(items: NotificationItem[], unread: number): string {
  return `${unread}:${items.map((n) => `${n.id}:${n.isRead ? 1 : 0}`).join(",")}`;
}

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
  return then.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

// ─── Per-type icon + color config ────────────────────────────────────────────

type TypeConfig = {
  bg: string;
  text: string;
  icon: React.ReactNode;
};

function getTypeConfig(type: string): TypeConfig {
  switch (type) {
    case "announcement.posted":
      return {
        bg: "bg-amber-100",
        text: "text-amber-600",
        icon: (
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5.882V19.24a1.76 1.76 0 01-3.417.592l-2.147-6.15M18 13a3 3 0 100-6M5.436 13.683A4.001 4.001 0 017 6h1.832c4.1 0 7.625-1.234 9.168-3v14c-1.543-1.766-5.067-3-9.168-3H7a3.988 3.988 0 01-1.564-.317z" />
          </svg>
        ),
      };

    case "event.created":
      return {
        bg: "bg-blue-100",
        text: "text-blue-600",
        icon: (
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
          </svg>
        ),
      };

    case "role.assigned":
      return {
        bg: "bg-violet-100",
        text: "text-violet-600",
        icon: (
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4M7.835 4.697a3.42 3.42 0 001.946-.806 3.42 3.42 0 014.438 0 3.42 3.42 0 001.946.806 3.42 3.42 0 013.138 3.138 3.42 3.42 0 00.806 1.946 3.42 3.42 0 010 4.438 3.42 3.42 0 00-.806 1.946 3.42 3.42 0 01-3.138 3.138 3.42 3.42 0 00-1.946.806 3.42 3.42 0 01-4.438 0 3.42 3.42 0 00-1.946-.806 3.42 3.42 0 01-3.138-3.138 3.42 3.42 0 00-.806-1.946 3.42 3.42 0 010-4.438 3.42 3.42 0 00.806-1.946 3.42 3.42 0 013.138-3.138z" />
          </svg>
        ),
      };

    case "role.removed":
      return {
        bg: "bg-orange-100",
        text: "text-orange-600",
        icon: (
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7a4 4 0 11-8 0 4 4 0 018 0zM9 14a6 6 0 00-6 6v1h12v-1a6 6 0 00-6-6zM21 12h-6" />
          </svg>
        ),
      };

    case "task.assigned":
      return {
        bg: "bg-emerald-100",
        text: "text-emerald-600",
        icon: (
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
          </svg>
        ),
      };

    default:
      return {
        bg: "bg-slate-100",
        text: "text-slate-500",
        icon: (
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
          </svg>
        ),
      };
  }
}

// ─── Bell icon ────────────────────────────────────────────────────────────────

function BellIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
    </svg>
  );
}

// ─── Component ────────────────────────────────────────────────────────────────

type NotificationBellProps = {
  unreadCount: number;
  notifications: NotificationItem[];
};

export function NotificationBell({ unreadCount, notifications }: NotificationBellProps) {
  const [isOpen, setIsOpen] = useState(false);
  const serverSig = notificationsSignature(notifications, unreadCount);
  const [localItems, setLocalItems] = useState(notifications);
  const [localUnread, setLocalUnread] = useState(unreadCount);
  const [syncedSig, setSyncedSig] = useState(serverSig);
  const [, startTransition] = useTransition();
  const containerRef = useRef<HTMLDivElement>(null);

  // When the server payload changes (e.g. after revalidation), reset local optimistic state.
  if (serverSig !== syncedSig) {
    setSyncedSig(serverSig);
    setLocalItems(notifications);
    setLocalUnread(unreadCount);
  }

  // Close on click outside.
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  function handleMarkRead(id: string) {
    // Optimistic update.
    setLocalItems((prev) =>
      prev.map((n) => (n.id === id ? { ...n, isRead: true } : n)),
    );
    setLocalUnread((prev) => Math.max(0, prev - 1));
    startTransition(() => markNotificationReadAction(id));
  }

  function handleMarkAllRead() {
    setLocalItems((prev) => prev.map((n) => ({ ...n, isRead: true })));
    setLocalUnread(0);
    startTransition(() => markAllNotificationsReadAction());
  }

  return (
    <div ref={containerRef} className="relative">
      {/* Bell button */}
      <button
        onClick={() => setIsOpen((v) => !v)}
        aria-label={`Notifications${localUnread > 0 ? `, ${localUnread} unread` : ""}`}
        className="relative flex h-10 w-10 items-center justify-center rounded-xl text-slate-500 transition hover:bg-slate-100 hover:text-slate-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-slate-400 sm:h-9 sm:w-9 sm:rounded-lg"
      >
        <BellIcon className="h-5 w-5" />
        {localUnread > 0 && (
          <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-slate-900 px-1 text-[10px] font-bold leading-none text-white">
            {localUnread > 9 ? "9+" : localUnread}
          </span>
        )}
      </button>

      {/* Dropdown */}
      {isOpen && (
        <div className="absolute right-0 top-full z-50 mt-2 w-[min(22rem,calc(100vw-2rem))] overflow-hidden rounded-xl border border-slate-200 bg-white shadow-xl sm:w-96">
          {/* Header */}
          <div className="flex items-center justify-between border-b border-slate-100 px-4 py-3">
            <span className="text-sm font-semibold text-slate-900">Notifications</span>
            {localUnread > 0 && (
              <button
                onClick={handleMarkAllRead}
                className="text-xs font-medium text-slate-500 transition hover:text-slate-900"
              >
                Mark all as read
              </button>
            )}
          </div>

          {/* List */}
          <div className="max-h-96 overflow-y-auto">
            {localItems.length === 0 ? (
              <div className="flex flex-col items-center justify-center px-6 py-10 text-center">
                <div className="flex h-10 w-10 items-center justify-center rounded-full bg-slate-100">
                  <BellIcon className="h-5 w-5 text-slate-400" />
                </div>
                <p className="mt-3 text-sm font-semibold text-slate-600">No notifications yet</p>
                <p className="mt-1 text-xs text-slate-400">
                  You will be notified about announcements, events, and role changes.
                </p>
              </div>
            ) : (
              <ul role="list">
                {localItems.map((item) => {
                  const config = getTypeConfig(item.type);
                  const inner = (
                    <div className={`flex gap-3 px-4 py-3.5 transition hover:bg-slate-50 ${!item.isRead ? "bg-blue-50/40" : ""}`}>
                      {/* Type icon */}
                      <div
                        className={`mt-0.5 flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full ${config.bg} ${config.text}`}
                      >
                        {config.icon}
                      </div>
                      {/* Content */}
                      <div className="min-w-0 flex-1">
                        <p className={`text-sm leading-snug ${!item.isRead ? "font-semibold text-slate-900" : "font-medium text-slate-700"}`}>
                          {item.title}
                        </p>
                        {item.body && (
                          <p className="mt-0.5 truncate text-xs text-slate-500">{item.body}</p>
                        )}
                        <p className="mt-1 text-xs text-slate-400">{formatTime(item.createdAt)}</p>
                      </div>
                      {/* Unread dot */}
                      {!item.isRead && (
                        <div className="mt-1.5 h-2 w-2 flex-shrink-0 rounded-full bg-slate-900" />
                      )}
                    </div>
                  );

                  return (
                    <li key={item.id} className="border-b border-slate-100 last:border-0">
                      {item.href ? (
                        <Link
                          href={item.href}
                          onClick={() => {
                            if (!item.isRead) handleMarkRead(item.id);
                            setIsOpen(false);
                          }}
                        >
                          {inner}
                        </Link>
                      ) : (
                        <div
                          role="button"
                          tabIndex={0}
                          onClick={() => !item.isRead && handleMarkRead(item.id)}
                          onKeyDown={(e) => e.key === "Enter" && !item.isRead && handleMarkRead(item.id)}
                          className="cursor-default"
                        >
                          {inner}
                        </div>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
          </div>

          {/* Footer */}
          {localItems.length > 0 && (
            <div className="border-t border-slate-100 px-4 py-2.5 text-center">
              <Link
                href="/notifications"
                onClick={() => setIsOpen(false)}
                className="text-xs font-medium text-slate-500 transition hover:text-slate-900"
              >
                View all notifications
              </Link>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
