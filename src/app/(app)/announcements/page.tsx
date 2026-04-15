import Link from "next/link";
import { ContentSummaryListLink } from "@/components/ui/event-summary";
import { PageIntro } from "@/components/ui/page-intro";
import { PageEmptyState } from "@/components/ui/page-patterns";
import { getDashboardData } from "@/lib/clubs/queries";

export default async function AnnouncementsPage() {
  const { recentAnnouncements } = await getDashboardData();

  return (
    <section className="space-y-4 lg:space-y-6">
      <PageIntro
        kicker="Global"
        title="Announcements"
        description="Recent updates from all your clubs in one place."
        actions={
          <Link href="/dashboard" className="btn-secondary">
            Back to Dashboard
          </Link>
        }
      />

      {recentAnnouncements.length === 0 ? (
        <PageEmptyState
          title="No announcements yet"
          copy="Announcements from your clubs will appear here. If you are an officer, post the first update to make this feed useful for everyone."
          action={
            <Link href="/my-clubs" className="btn-primary">
              Open my clubs
            </Link>
          }
        />
      ) : (
        <div className="overflow-hidden rounded-xl border border-slate-200/95 bg-white shadow-[0_1px_2px_rgb(15_23_42/0.04)]">
          {recentAnnouncements.map((announcement) => (
            <div key={announcement.id} className="border-b border-slate-100 last:border-b-0">
              <ContentSummaryListLink
                href={`/clubs/${announcement.clubId}/announcements`}
                title={announcement.title}
                secondaryLine={announcement.clubName}
                timestamp={announcement.createdAtRaw}
              />
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
