import Link from "next/link";
import { ClubColorDot } from "@/components/ui/club-color-dot";
import { getClubAccentColor } from "@/lib/clubs/club-visual";
import type { DashboardAnnouncement } from "@/lib/clubs/queries";

function groupAnnouncementsByClub(announcements: DashboardAnnouncement[]) {
  const order: string[] = [];
  const groups = new Map<string, { clubName: string; items: DashboardAnnouncement[] }>();

  for (const item of announcements) {
    if (!groups.has(item.clubId)) {
      order.push(item.clubId);
      groups.set(item.clubId, { clubName: item.clubName, items: [] });
    }
    groups.get(item.clubId)!.items.push(item);
  }

  return order.map((clubId) => ({
    clubId,
    clubName: groups.get(clubId)!.clubName,
    items: groups.get(clubId)!.items,
  }));
}

function formatAnnouncementDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

function AnnouncementRow({ item }: { item: DashboardAnnouncement }) {
  const accent = getClubAccentColor(item.clubName);
  const dateLabel = formatAnnouncementDate(item.createdAtRaw);

  return (
    <Link
      href={`/clubs/${item.clubId}/announcements`}
      className="flex gap-3 px-4 py-3 transition hover:bg-slate-50/80 sm:px-5"
    >
      <ClubColorDot clubName={item.clubName} size="sm" className="mt-0.5 shrink-0" />
      <div className="min-w-0 flex-1">
        <div className="flex items-start justify-between gap-3">
          <p className="min-w-0 text-sm font-medium leading-snug text-slate-900">{item.title}</p>
          <time
            dateTime={item.createdAtRaw}
            className="shrink-0 text-xs text-slate-400 tabular-nums"
          >
            {dateLabel}
          </time>
        </div>
        <p className="mt-0.5 text-xs text-slate-500">
          <span style={{ color: accent }} className="font-medium">
            {item.clubName}
          </span>
        </p>
      </div>
    </Link>
  );
}

type GlobalAnnouncementsListProps = {
  announcements: DashboardAnnouncement[];
};

export function GlobalAnnouncementsList({ announcements }: GlobalAnnouncementsListProps) {
  const groups = groupAnnouncementsByClub(announcements);

  return (
    <div className="overflow-hidden rounded-xl border border-slate-200/95 bg-white shadow-[0_1px_2px_rgb(15_23_42/0.04)]">
      {groups.map((group, groupIndex) => (
        <section key={group.clubId} className={groupIndex > 0 ? "border-t border-slate-200" : ""}>
          <p className="border-b border-slate-100 bg-slate-50/60 px-4 py-2 text-[11px] font-semibold uppercase tracking-wide text-slate-500 sm:px-5">
            {group.clubName}
          </p>
          <ul role="list">
            {group.items.map((item, itemIndex) => (
              <li
                key={item.id}
                className={itemIndex > 0 ? "border-t border-slate-100" : ""}
              >
                <AnnouncementRow item={item} />
              </li>
            ))}
          </ul>
        </section>
      ))}
    </div>
  );
}
