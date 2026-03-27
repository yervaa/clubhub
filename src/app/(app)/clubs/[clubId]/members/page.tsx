import { notFound } from "next/navigation";
import { ClubMembersSection } from "@/components/ui/club-members-section";
import { getClubDetailForCurrentUser } from "@/lib/clubs/queries";

type ClubMembersPageProps = {
  params: Promise<{ clubId: string }>;
  searchParams: Promise<{
    memberError?: string;
    memberSuccess?: string;
  }>;
};

export default async function ClubMembersPage({ params, searchParams }: ClubMembersPageProps) {
  const { clubId } = await params;
  const query = await searchParams;
  const club = await getClubDetailForCurrentUser(clubId);

  if (!club) {
    notFound();
  }

  return <ClubMembersSection club={club} query={query} />;
}
