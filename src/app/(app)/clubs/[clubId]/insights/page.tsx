import { notFound } from "next/navigation";
import { ClubInsightsSection } from "@/components/ui/club-insights-section";
import { buildInsightsExportPayload } from "@/lib/clubs/insights-export";
import { getClubDetailForInsightsForCurrentUser } from "@/lib/clubs/queries";
import { hasPermission } from "@/lib/rbac/permissions";
import { createClient } from "@/lib/supabase/server";

type ClubInsightsPageProps = {
  params: Promise<{ clubId: string }>;
};

export default async function ClubInsightsPage({ params }: ClubInsightsPageProps) {
  const { clubId } = await params;
  const [club, supabase] = await Promise.all([
    getClubDetailForInsightsForCurrentUser(clubId),
    createClient(),
  ]);

  if (!club) {
    notFound();
  }

  const {
    data: { user },
  } = await supabase.auth.getUser();

  const canExportInsights = user
    ? await hasPermission(user.id, clubId, "insights.export")
    : false;

  const exportPayload = canExportInsights ? buildInsightsExportPayload(club) : null;

  return (
    <ClubInsightsSection
      club={club}
      canExportInsights={canExportInsights}
      exportPayload={exportPayload}
    />
  );
}
