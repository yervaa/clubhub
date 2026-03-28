import { notFound, redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import { getUserPermissions } from "@/lib/rbac/permissions";
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
    canCreateEvents: userPermissions.has("events.create"),
    canMarkAttendance: userPermissions.has("attendance.mark"),
    canManageReflections: userPermissions.has("reflections.create"),
  };

  return <ClubEventsSection club={club} query={query} permissions={permissions} />;
}
