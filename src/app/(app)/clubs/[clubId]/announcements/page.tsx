import { notFound, redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import { getUserPermissions } from "@/lib/rbac/permissions";
import { ClubAnnouncementsSection } from "@/components/ui/club-announcements-section";
import { getClubDetailForAnnouncementsForCurrentUser } from "@/lib/clubs/queries";

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

  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const [club, userPermissions] = await Promise.all([
    getClubDetailForAnnouncementsForCurrentUser(clubId),
    getUserPermissions(user.id, clubId),
  ]);

  if (!club) {
    notFound();
  }

  const permissions = {
    canPostAnnouncements: userPermissions.has("announcements.create"),
    canEditAnnouncements: userPermissions.has("announcements.edit"),
    canDeleteAnnouncements: userPermissions.has("announcements.delete"),
    canViewReadersList:
      userPermissions.has("announcements.edit") || club.currentUserRole === "officer",
  };

  return <ClubAnnouncementsSection club={club} query={query} permissions={permissions} />;
}
