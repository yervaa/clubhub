import "server-only";
import { createClient } from "@/lib/supabase/server";

export type ClubStatus = "active" | "archived";

/**
 * Returns whether the club is archived for mutation guards (server actions).
 */
export async function assertClubActiveForMutations(
  clubId: string,
): Promise<{ ok: true } | { ok: false; message: string }> {
  const supabase = await createClient();
  const { data, error } = await supabase.from("clubs").select("status").eq("id", clubId).maybeSingle();

  if (error || !data) {
    return { ok: false, message: "Club not found." };
  }

  const status = data.status as string | undefined;
  if (status === "archived") {
    return { ok: false, message: "This club is archived and can no longer be edited." };
  }

  return { ok: true };
}

export type ClubLayoutShell = {
  name: string;
  status: ClubStatus;
  memberCount: number;
  userRole: "member" | "officer";
};

/**
 * Club name + status (+ roster context) for layouts when the user is a member (else null).
 */
export async function getClubNameAndStatusIfMember(clubId: string): Promise<ClubLayoutShell | null> {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return null;

  const { data: membership } = await supabase
    .from("club_members")
    .select("club_id, role")
    .eq("club_id", clubId)
    .eq("user_id", user.id)
    .maybeSingle();

  if (!membership) return null;

  const [{ data: club }, { count: memberCount }] = await Promise.all([
    supabase.from("clubs").select("name, status").eq("id", clubId).maybeSingle(),
    supabase
      .from("club_members")
      .select("*", { count: "exact", head: true })
      .eq("club_id", clubId)
      .eq("membership_status", "active"),
  ]);

  if (!club?.name) return null;

  const status = (club.status as ClubStatus | undefined) ?? "active";
  const role = membership.role === "officer" ? "officer" : "member";

  return {
    name: club.name,
    status,
    memberCount: memberCount ?? 0,
    userRole: role,
  };
}
