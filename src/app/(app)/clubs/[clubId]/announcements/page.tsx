import { notFound } from "next/navigation";
import { ClubAnnouncementsSection } from "@/components/ui/club-announcements-section";
import { getClubDetailForCurrentUser } from "@/lib/clubs/queries";

type ClubAnnouncementsPageProps = {
  params: Promise<{ clubId: string }>;
  searchParams: Promise<{
    annError?: string;
    annSuccess?: string;
  }>;
};

export default async function ClubAnnouncementsPage({ params, searchParams }: ClubAnnouncementsPageProps) {
  const { clubId } = await params;
  const query = await searchParams;
  const club = await getClubDetailForCurrentUser(clubId);

  if (!club) {
    notFound();
  }

  return <ClubAnnouncementsSection club={club} query={query} />;
}
