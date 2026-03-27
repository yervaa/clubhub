import { notFound } from "next/navigation";
import { ClubEventsSection } from "@/components/ui/club-events-section";
import { getClubDetailForCurrentUser } from "@/lib/clubs/queries";

type ClubEventsPageProps = {
  params: Promise<{ clubId: string }>;
  searchParams: Promise<{
    eventError?: string;
    eventSuccess?: string;
    duplicateEventId?: string;
    reflectionError?: string;
    reflectionSuccess?: string;
    reflectionEventId?: string;
    rsvpError?: string;
    rsvpSuccess?: string;
    rsvpEventId?: string;
    attendanceError?: string;
    attendanceSuccess?: string;
    attendanceEventId?: string;
    attendanceUserId?: string;
    attendancePresent?: string;
  }>;
};

export default async function ClubEventsPage({ params, searchParams }: ClubEventsPageProps) {
  const { clubId } = await params;
  const query = await searchParams;
  const club = await getClubDetailForCurrentUser(clubId);

  if (!club) {
    notFound();
  }

  return <ClubEventsSection club={club} query={query} />;
}
