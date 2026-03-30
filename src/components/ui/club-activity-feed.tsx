"use client";

import Link from "next/link";
import { useMediaLg } from "@/lib/hooks/use-media-lg";

// ─── Public types ─────────────────────────────────────────────────────────────

export type ActivityItemType =
  | "member_joined"
  | "announcement_posted"
  | "event_created"
  | "rsvp_updated"
  | "attendance_marked"
  | "reflection_added"
  // Governance / RBAC events (sourced from audit log; only visible to Presidents)
  | "role_assigned"
  | "president_added"
  | "president_removed"
  | "presidency_transferred";

export type ActivityFeedItem = {
  id: string;
  type: ActivityItemType;
  message: string;
  displayTime: string;
  href?: string;
};

// ─── Per-type visual config ───────────────────────────────────────────────────

type TypeConfig = {
  label: string;
  dotBg: string;
  dotText: string;
  pillBg: string;
  pillText: string;
  pillBorder: string;
  icon: React.ReactNode;
};

function getTypeConfig(type: ActivityItemType): TypeConfig {
  switch (type) {
    case "member_joined":
      return {
        label: "Member",
        dotBg: "bg-blue-100",
        dotText: "text-blue-600",
        pillBg: "bg-blue-50",
        pillText: "text-blue-700",
        pillBorder: "border-blue-200",
        icon: (
          <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
          </svg>
        ),
      };

    case "announcement_posted":
      return {
        label: "Announcement",
        dotBg: "bg-amber-100",
        dotText: "text-amber-600",
        pillBg: "bg-amber-50",
        pillText: "text-amber-700",
        pillBorder: "border-amber-200",
        icon: (
          <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5.882V19.24a1.76 1.76 0 01-3.417.592l-2.147-6.15M18 13a3 3 0 100-6M5.436 13.683A4.001 4.001 0 017 6h1.832c4.1 0 7.625-1.234 9.168-3v14c-1.543-1.766-5.067-3-9.168-3H7a3.988 3.988 0 01-1.564-.317z" />
          </svg>
        ),
      };

    case "event_created":
      return {
        label: "Event",
        dotBg: "bg-purple-100",
        dotText: "text-purple-600",
        pillBg: "bg-purple-50",
        pillText: "text-purple-700",
        pillBorder: "border-purple-200",
        icon: (
          <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
          </svg>
        ),
      };

    case "rsvp_updated":
      return {
        label: "RSVP",
        dotBg: "bg-emerald-100",
        dotText: "text-emerald-600",
        pillBg: "bg-emerald-50",
        pillText: "text-emerald-700",
        pillBorder: "border-emerald-200",
        icon: (
          <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        ),
      };

    case "attendance_marked":
      return {
        label: "Attendance",
        dotBg: "bg-teal-100",
        dotText: "text-teal-600",
        pillBg: "bg-teal-50",
        pillText: "text-teal-700",
        pillBorder: "border-teal-200",
        icon: (
          <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
          </svg>
        ),
      };

    case "reflection_added":
      return {
        label: "Reflection",
        dotBg: "bg-slate-100",
        dotText: "text-slate-500",
        pillBg: "bg-slate-50",
        pillText: "text-slate-600",
        pillBorder: "border-slate-200",
        icon: (
          <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
          </svg>
        ),
      };

    case "role_assigned":
      return {
        label: "Role",
        dotBg: "bg-violet-100",
        dotText: "text-violet-600",
        pillBg: "bg-violet-50",
        pillText: "text-violet-700",
        pillBorder: "border-violet-200",
        icon: (
          <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4M7.835 4.697a3.42 3.42 0 001.946-.806 3.42 3.42 0 014.438 0 3.42 3.42 0 001.946.806 3.42 3.42 0 013.138 3.138 3.42 3.42 0 00.806 1.946 3.42 3.42 0 010 4.438 3.42 3.42 0 00-.806 1.946 3.42 3.42 0 01-3.138 3.138 3.42 3.42 0 00-1.946.806 3.42 3.42 0 01-4.438 0 3.42 3.42 0 00-1.946-.806 3.42 3.42 0 01-3.138-3.138 3.42 3.42 0 00-.806-1.946 3.42 3.42 0 010-4.438 3.42 3.42 0 00.806-1.946 3.42 3.42 0 013.138-3.138z" />
          </svg>
        ),
      };

    case "president_added":
      return {
        label: "Governance",
        dotBg: "bg-yellow-100",
        dotText: "text-yellow-700",
        pillBg: "bg-yellow-50",
        pillText: "text-yellow-800",
        pillBorder: "border-yellow-200",
        icon: (
          <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 3v4M3 5h4M6 17v4m-2-2h4m5-16l2.286 6.857L21 12l-5.714 2.143L13 21l-2.286-6.857L5 12l5.714-2.143L13 3z" />
          </svg>
        ),
      };

    case "president_removed":
      return {
        label: "Governance",
        dotBg: "bg-orange-100",
        dotText: "text-orange-600",
        pillBg: "bg-orange-50",
        pillText: "text-orange-700",
        pillBorder: "border-orange-200",
        icon: (
          <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7a4 4 0 11-8 0 4 4 0 018 0zM9 14a6 6 0 00-6 6v1h12v-1a6 6 0 00-6-6zM21 12h-6" />
          </svg>
        ),
      };

    case "presidency_transferred":
      return {
        label: "Governance",
        dotBg: "bg-violet-100",
        dotText: "text-violet-600",
        pillBg: "bg-violet-50",
        pillText: "text-violet-700",
        pillBorder: "border-violet-200",
        icon: (
          <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" />
          </svg>
        ),
      };

    default: {
      const _exhaustive: never = type;
      void _exhaustive;
      return {
        label: "Activity",
        dotBg: "bg-slate-100",
        dotText: "text-slate-500",
        pillBg: "bg-slate-50",
        pillText: "text-slate-600",
        pillBorder: "border-slate-200",
        icon: (
          <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        ),
      };
    }
  }
}

// ─── Component ────────────────────────────────────────────────────────────────

type ClubActivityFeedProps = {
  items: ActivityFeedItem[];
};

export function ClubActivityFeed({ items }: ClubActivityFeedProps) {
  const isLg = useMediaLg();

  const header = (
    <div className="section-card-header">
      <div>
        <p className="section-kicker">Activity</p>
        <h2 className="mt-1 text-base font-semibold tracking-tight text-slate-900">Recent Activity</h2>
        <p className="mt-1 text-sm text-slate-600">Latest actions across the club.</p>
      </div>
      {items.length > 0 && <span className="badge-soft">{items.length} recent</span>}
    </div>
  );

  const body =
    items.length === 0 ? (
      <div className="mt-4 rounded-xl border border-dashed border-slate-200 bg-slate-50/60 p-6 text-center lg:mt-5 lg:p-8">
        <div className="mx-auto flex h-10 w-10 items-center justify-center rounded-full bg-slate-100">
          <svg className="h-5 w-5 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        </div>
        <p className="mt-3 text-sm font-semibold text-slate-600">No activity yet</p>
        <p className="mt-1 text-sm text-slate-400">
          Actions like joining, posting, and RSVPing will appear here.
        </p>
      </div>
    ) : (
      <ul className="mt-4 lg:mt-5" role="list">
        {items.map((item, index) => {
          const config = getTypeConfig(item.type);
          const isLast = index === items.length - 1;

          return (
            <li key={item.id} className="relative flex gap-3.5">
              {!isLast && (
                <div className="absolute bottom-0 left-[15px] top-8 w-px bg-slate-100" aria-hidden="true" />
              )}

              <div
                className={`relative z-10 mt-0.5 flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full ${config.dotBg} ${config.dotText}`}
              >
                {config.icon}
              </div>

              <div className={`min-w-0 flex-1 py-1 ${!isLast ? "pb-5" : ""}`}>
                {item.href ? (
                  <Link
                    href={item.href}
                    className="text-sm leading-snug text-slate-700 decoration-slate-300 underline-offset-2 transition-colors hover:text-slate-900 hover:underline"
                  >
                    {item.message}
                  </Link>
                ) : (
                  <p className="text-sm leading-snug text-slate-700">{item.message}</p>
                )}
                <div className="mt-1.5 flex flex-wrap items-center gap-2">
                  <span
                    className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${config.pillBg} ${config.pillText} ${config.pillBorder}`}
                  >
                    {config.label}
                  </span>
                  <span className="text-xs text-slate-400">{item.displayTime}</span>
                </div>
              </div>
            </li>
          );
        })}
      </ul>
    );

  if (!isLg) {
    return (
      <details className="group card-surface overflow-hidden p-4 open:shadow-md">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-2 pr-2 [&::-webkit-details-marker]:hidden">
          <div>
            <p className="section-kicker">Activity</p>
            <h2 className="mt-0.5 text-base font-semibold tracking-tight text-slate-900">Recent activity</h2>
            <p className="mt-0.5 text-xs text-slate-500">
              {items.length === 0 ? "Nothing yet" : `${items.length} updates · tap to expand`}
            </p>
          </div>
          <span className="text-[10px] font-bold uppercase tracking-wider text-blue-600 group-open:hidden">Open</span>
          <span className="hidden text-[10px] font-bold uppercase tracking-wider text-slate-500 group-open:inline">Close</span>
        </summary>
        <div className="mt-3 border-t border-slate-100 pt-4">{body}</div>
      </details>
    );
  }

  return (
    <div className="card-surface p-6">
      {header}
      {body}
    </div>
  );
}
