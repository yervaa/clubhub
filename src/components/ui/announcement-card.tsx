import type { MockAnnouncement } from "@/lib/mock-data";

type AnnouncementCardProps = {
  announcement: MockAnnouncement;
};

export function AnnouncementCard({ announcement }: AnnouncementCardProps) {
  return (
    <article className="rounded-xl border border-slate-200 bg-white p-5">
      <p className="text-xs font-semibold uppercase tracking-[0.08em] text-slate-500">
        {announcement.clubName}
      </p>
      <h3 className="mt-2 text-base font-semibold text-slate-900">{announcement.title}</h3>
      <p className="mt-2 text-sm text-slate-600">{announcement.content}</p>
      <p className="mt-4 text-xs text-slate-500">
        {announcement.author} • {announcement.createdAt}
      </p>
    </article>
  );
}
