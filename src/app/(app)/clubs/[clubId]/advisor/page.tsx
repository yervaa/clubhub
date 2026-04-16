import { notFound, redirect } from "next/navigation";
import { AdvisorDashboard, type AdvisorDashboardProps } from "@/components/ui/advisor-dashboard";
import { createClient } from "@/lib/supabase/server";
import { hasPermission } from "@/lib/rbac/permissions";

type AdvisorPageProps = {
  params: Promise<{ clubId: string }>;
  searchParams: Promise<{ success?: string; error?: string }>;
};

export default async function AdvisorPage({ params, searchParams }: AdvisorPageProps) {
  const { clubId } = await params;
  const query = await searchParams;

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const { data: membership } = await supabase
    .from("club_members")
    .select("user_id")
    .eq("club_id", clubId)
    .eq("user_id", user.id)
    .maybeSingle();

  if (!membership) notFound();

  const [canEvents, canAnnouncements] = await Promise.all([
    hasPermission(user.id, clubId, "events.approve"),
    hasPermission(user.id, clubId, "announcements.approve"),
  ]);

  if (!canEvents && !canAnnouncements) {
    notFound();
  }

  const { data: club } = await supabase
    .from("clubs")
    .select("name, require_event_approval, require_announcement_approval")
    .eq("id", clubId)
    .maybeSingle();

  if (!club) notFound();

  const [pendingEventsRes, pendingAnnRes] = await Promise.all([
    canEvents
      ? supabase
          .from("events")
          .select("id, title, event_date, location, series_id, series_occurrence")
          .eq("club_id", clubId)
          .eq("approval_status", "pending")
          .order("event_date", { ascending: true })
          .limit(50)
      : Promise.resolve({ data: [] as { id: string; title: string; event_date: string; location: string | null; series_id: string | null; series_occurrence: number | null }[] }),
    canAnnouncements
      ? supabase
          .from("announcements")
          .select("id, title, created_at, scheduled_for")
          .eq("club_id", clubId)
          .eq("approval_status", "pending")
          .order("created_at", { ascending: false })
          .limit(50)
      : Promise.resolve({ data: [] as { id: string; title: string; created_at: string; scheduled_for: string | null }[] }),
  ]);

  return (
    <AdvisorDashboard
      clubId={clubId}
      clubName={club.name}
      requireEventApproval={Boolean(club.require_event_approval)}
      requireAnnouncementApproval={Boolean(club.require_announcement_approval)}
      canEvents={canEvents}
      canAnnouncements={canAnnouncements}
      pendingEvents={(pendingEventsRes.data ?? []) as AdvisorDashboardProps["pendingEvents"]}
      pendingAnnouncements={(pendingAnnRes.data ?? []) as AdvisorDashboardProps["pendingAnnouncements"]}
      query={query}
    />
  );
}
