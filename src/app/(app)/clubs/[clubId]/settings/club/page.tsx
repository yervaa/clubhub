import { notFound, redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import { getUserPermissions, isClubPresident } from "@/lib/rbac/permissions";
import { ClubLifecycleSection } from "@/components/ui/club-lifecycle-section";

type ClubSettingsLifecyclePageProps = {
  params: Promise<{ clubId: string }>;
  searchParams: Promise<{
    success?: string;
    error?: string;
  }>;
};

export default async function ClubSettingsLifecyclePage({ params, searchParams }: ClubSettingsLifecyclePageProps) {
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

  const [clubResult, presidencyCheck, permissions] = await Promise.all([
    supabase.from("clubs").select("name, status").eq("id", clubId).maybeSingle(),
    isClubPresident(user.id, clubId),
    getUserPermissions(user.id, clubId),
  ]);

  if (!clubResult.data) notFound();

  const presidentRoleResult = await supabase
    .from("club_roles")
    .select("id")
    .eq("club_id", clubId)
    .eq("name", "President")
    .eq("is_system", true)
    .maybeSingle();

  let presidentCount = 0;
  if (presidentRoleResult.data?.id) {
    const { count } = await supabase
      .from("member_roles")
      .select("user_id", { count: "exact", head: true })
      .eq("club_id", clubId)
      .eq("role_id", presidentRoleResult.data.id);
    presidentCount = count ?? 0;
  }

  const status = clubResult.data.status === "archived" ? "archived" : "active";
  const canArchive = permissions.has("club.archive");
  const canDelete = permissions.has("club.delete");

  return (
    <ClubLifecycleSection
      clubId={clubId}
      clubName={clubResult.data.name}
      clubStatus={status}
      isPresident={presidencyCheck}
      presidentCount={presidentCount}
      canArchive={canArchive}
      canDelete={canDelete}
      query={query}
    />
  );
}
