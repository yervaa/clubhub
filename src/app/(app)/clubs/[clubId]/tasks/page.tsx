import { notFound, redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import { getUserPermissions } from "@/lib/rbac/permissions";
import { getClubTasks, getMyClubTasks } from "@/lib/tasks/queries";
import { ClubTasksSection } from "@/components/ui/club-tasks-section";

type ClubTasksPageProps = {
  params: Promise<{ clubId: string }>;
};

export default async function ClubTasksPage({ params }: ClubTasksPageProps) {
  const { clubId } = await params;

  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  // Verify club membership.
  const { data: membership } = await supabase
    .from("club_members")
    .select("user_id")
    .eq("club_id", clubId)
    .eq("user_id", user.id)
    .maybeSingle();

  if (!membership) notFound();

  // Fetch in parallel: permissions, all visible tasks, my assigned tasks, members.
  const [userPermissions, allTasks, myTasks, clubMembersRes, clubRow] = await Promise.all([
    getUserPermissions(user.id, clubId),
    getClubTasks(clubId),
    getMyClubTasks(clubId, user.id),
    supabase
      .from("club_members")
      .select("user_id, profiles ( full_name, email )")
      .eq("club_id", clubId),
    supabase
      .from("clubs")
      .select("name")
      .eq("id", clubId)
      .maybeSingle(),
  ]);

  if (!clubRow.data) notFound();

  type RawMember = { user_id: string; profiles: { full_name: string | null; email: string | null } | null };
  const clubMembers = ((clubMembersRes.data ?? []) as unknown as RawMember[]).map((m) => ({
    userId: m.user_id,
    fullName: m.profiles?.full_name ?? null,
    email: m.profiles?.email ?? null,
  }));

  const permissions = {
    canView: userPermissions.has("tasks.view"),
    canCreate: userPermissions.has("tasks.create"),
    canEdit: userPermissions.has("tasks.edit"),
    canDelete: userPermissions.has("tasks.delete"),
    canAssign: userPermissions.has("tasks.assign"),
    canComplete: userPermissions.has("tasks.complete"),
  };

  return (
    <ClubTasksSection
      clubId={clubId}
      clubName={clubRow.data.name}
      currentUserId={user.id}
      tasks={allTasks}
      myTasks={myTasks}
      clubMembers={clubMembers}
      permissions={permissions}
    />
  );
}
