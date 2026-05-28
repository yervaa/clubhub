import Link from "next/link";
import { MyClubsGrid } from "@/components/ui/my-clubs-grid";
import { PageEmptyState } from "@/components/ui/page-patterns";
import { getCurrentUserClubs } from "@/lib/clubs/queries";

export default async function MyClubsPage() {
  const clubs = await getCurrentUserClubs();

  return (
    <section className="space-y-4 lg:space-y-6">
      <h1 className="app-page-title">My clubs</h1>

      {clubs.length === 0 ? (
        <PageEmptyState
          title="Your club list is empty"
          copy="Join with an invite code to jump into a live workspace, or start your own club to organize events, announcements, and members."
          action={
            <Link href="/clubs/join" className="btn-primary">
              Join your first club
            </Link>
          }
        />
      ) : (
        <MyClubsGrid clubs={clubs} />
      )}
    </section>
  );
}
