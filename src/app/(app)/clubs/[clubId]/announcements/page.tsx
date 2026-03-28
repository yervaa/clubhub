import { notFound, redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import { getUserPermissions } from "@/lib/rbac/permissions";
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

  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const [club, userPermissions] = await Promise.all([
    getClubDetailForCurrentUser(clubId),
    getUserPermissions(user.id, clubId),
  ]);

  if (!club) {
    notFound();
  }

  const permissions = {
    canPostAnnouncements: userPermissions.has("announcements.create"),
    canEditAnnouncements: userPermissions.has("announcements.edit"),
    canDeleteAnnouncements: userPermissions.has("announcements.delete"),
  };

  return <ClubAnnouncementsSection club={club} query={query} permissions={permissions} />;
}
