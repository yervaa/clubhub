import Link from "next/link";
import { GlobalAnnouncementsList } from "@/components/ui/global-announcements-list";
import { PageEmptyState } from "@/components/ui/page-patterns";
import { getDashboardData } from "@/lib/clubs/queries";

export default async function AnnouncementsPage() {
  const { recentAnnouncements } = await getDashboardData();

  return (
    <section className="space-y-4 lg:space-y-6">
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
        <GlobalAnnouncementsList announcements={recentAnnouncements} />
      )}
    </section>
  );
}
