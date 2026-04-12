import { notFound } from "next/navigation";
import { ClubInsightsSection } from "@/components/ui/club-insights-section";
import { getClubDetailForInsightsForCurrentUser } from "@/lib/clubs/queries";

type ClubInsightsPageProps = {
  params: Promise<{ clubId: string }>;
};

export default async function ClubInsightsPage({ params }: ClubInsightsPageProps) {
  const { clubId } = await params;
  const club = await getClubDetailForInsightsForCurrentUser(clubId);

  if (!club) {
    notFound();
  }

  return <ClubInsightsSection club={club} />;
}
