import Link from "next/link";
import type { ActivityFeedItem } from "@/lib/activity/types";
import { CardSection, PageEmptyState, SectionHeader } from "@/components/ui/page-patterns";
import type { ReactNode } from "react";

type ActivityFeedProps = {
  items: ActivityFeedItem[];
  title?: string;
  description?: string;
  viewMoreHref?: string;
  variant?: "primary" | "secondary";
  emptyAction?: ReactNode;
  emptyHint?: string;
};

function formatTime(iso: string): string {
  const now = Date.now();
  const then = new Date(iso).getTime();
  const mins = Math.floor((now - then) / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 7) return `${days}d ago`;
  return new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function typeBadge(type: ActivityFeedItem["type"]) {
  switch (type) {
    case "announcement.created":
      return "Announcement";
    case "event.created":
      return "Event";
    case "rsvp.submitted":
      return "RSVP";
    case "attendance.marked":
      return "Attendance";
    case "role.assigned":
      return "Role assigned";
    case "role.removed":
      return "Role removed";
    default:
      return "Activity";
  }
}

export function ActivityFeed({
  items,
  title = "Activity Feed",
  description = "Recent actions across your clubs.",
  viewMoreHref,
  variant = "secondary",
  emptyAction,
  emptyHint,
}: ActivityFeedProps) {
  return (
    <CardSection className={variant === "primary" ? "sm:p-6" : ""}>
      <SectionHeader
        kicker="Activity"
        title={title}
        description={description}
        action={viewMoreHref ? <Link href={viewMoreHref} className="text-sm font-semibold text-slate-700 hover:text-slate-900">View more</Link> : null}
      />

      {items.length === 0 ? (
        <div className="mt-4">
          <PageEmptyState
            title="No recent activity"
            copy={
              emptyHint
                ?? "New announcements, RSVPs, events, and role updates will appear here."
            }
            action={emptyAction}
          />
        </div>
      ) : (
        <ul className="mt-4 space-y-2">
          {items.map((item, index) => (
            <li
              key={item.id}
              className={`activity-feed-item rounded-lg border border-slate-200 bg-slate-50/60 px-3 py-2.5 ${index === 0 ? "activity-feed-item--fresh" : ""}`}
              style={{ ["--activity-index" as string]: index }}
            >
              {item.href ? (
                <Link href={item.href} className="block">
                  <p className="text-sm text-slate-800">
                    <span className="font-semibold text-slate-900">{item.actorName}</span> {item.actionLabel}{" "}
                    <span className="font-semibold text-slate-900">{item.targetLabel}</span>
                  </p>
                </Link>
              ) : (
                <p className="text-sm text-slate-800">
                  <span className="font-semibold text-slate-900">{item.actorName}</span> {item.actionLabel}{" "}
                  <span className="font-semibold text-slate-900">{item.targetLabel}</span>
                </p>
              )}
              <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-slate-500">
                <span className="rounded-full bg-slate-100 px-2 py-0.5 font-medium text-slate-600">{typeBadge(item.type)}</span>
                <span>{item.clubName ?? "Club"}</span>
                <span>·</span>
                <span>{formatTime(item.timestamp)}</span>
              </div>
            </li>
          ))}
        </ul>
      )}
    </CardSection>
  );
}
