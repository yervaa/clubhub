"use server";

import { revalidatePath } from "next/cache";
import { assertClubActiveForMutations } from "@/lib/clubs/club-status";
import { isViewerActiveLegacyOfficer } from "@/lib/clubs/member-management-access";
import { hasPermission } from "@/lib/rbac/permissions";
import { createClient } from "@/lib/supabase/server";
import {
  clubTeamAssignSchema,
  clubTeamCreateSchema,
  clubTeamDeleteSchema,
  clubTeamRemoveMemberSchema,
  clubTeamRenameSchema,
} from "@/lib/validation/clubs";

type ActionResult = { ok: true } | { ok: false; error: string };

async function assertCanManageTeams(userId: string, clubId: string): Promise<ActionResult> {
  const supabase = await createClient();
  const allowedByRbac = await hasPermission(userId, clubId, "members.manage_teams");
  if (allowedByRbac) return { ok: true };

  const { data: row } = await supabase
    .from("club_members")
    .select("role, membership_status")
    .eq("club_id", clubId)
    .eq("user_id", userId)
    .maybeSingle();

  if (isViewerActiveLegacyOfficer(row ?? null)) {
    return { ok: true };
  }

  return { ok: false, error: "You do not have permission to manage teams." };
}

export async function createClubTeamAction(formData: FormData): Promise<ActionResult> {
  const parsed = clubTeamCreateSchema.safeParse({
    clubId: formData.get("club_id"),
    name: formData.get("name"),
  });

  if (!parsed.success) {
    return { ok: false, error: parsed.error.issues[0]?.message ?? "Invalid team name." };
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    return { ok: false, error: "You must be signed in." };
  }

  const active = await assertClubActiveForMutations(parsed.data.clubId);
  if (!active.ok) {
    return { ok: false, error: active.message };
  }

  const gate = await assertCanManageTeams(user.id, parsed.data.clubId);
  if (!gate.ok) return gate;

  const { error } = await supabase.from("club_teams").insert({
    club_id: parsed.data.clubId,
    name: parsed.data.name,
  });

  if (error) {
    if (error.code === "23505") {
      return { ok: false, error: "A team with this name already exists in this club." };
    }
    return { ok: false, error: "Could not create team. Please retry." };
  }

  revalidatePath(`/clubs/${parsed.data.clubId}/members`);
  revalidatePath(`/clubs/${parsed.data.clubId}`);
  return { ok: true };
}

export async function renameClubTeamAction(formData: FormData): Promise<ActionResult> {
  const parsed = clubTeamRenameSchema.safeParse({
    clubId: formData.get("club_id"),
    teamId: formData.get("team_id"),
    name: formData.get("name"),
  });

  if (!parsed.success) {
    return { ok: false, error: parsed.error.issues[0]?.message ?? "Invalid input." };
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    return { ok: false, error: "You must be signed in." };
  }

  const active = await assertClubActiveForMutations(parsed.data.clubId);
  if (!active.ok) {
    return { ok: false, error: active.message };
  }

  const gate = await assertCanManageTeams(user.id, parsed.data.clubId);
  if (!gate.ok) return gate;

  const { error } = await supabase
    .from("club_teams")
    .update({ name: parsed.data.name })
    .eq("id", parsed.data.teamId)
    .eq("club_id", parsed.data.clubId);

  if (error) {
    if (error.code === "23505") {
      return { ok: false, error: "A team with this name already exists in this club." };
    }
    return { ok: false, error: "Could not rename team. Please retry." };
  }

  revalidatePath(`/clubs/${parsed.data.clubId}/members`);
  revalidatePath(`/clubs/${parsed.data.clubId}`);
  return { ok: true };
}

export async function deleteClubTeamAction(formData: FormData): Promise<ActionResult> {
  const parsed = clubTeamDeleteSchema.safeParse({
    clubId: formData.get("club_id"),
    teamId: formData.get("team_id"),
  });

  if (!parsed.success) {
    return { ok: false, error: "Invalid request." };
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    return { ok: false, error: "You must be signed in." };
  }

  const active = await assertClubActiveForMutations(parsed.data.clubId);
  if (!active.ok) {
    return { ok: false, error: active.message };
  }

  const gate = await assertCanManageTeams(user.id, parsed.data.clubId);
  if (!gate.ok) return gate;

  const { error } = await supabase
    .from("club_teams")
    .delete()
    .eq("id", parsed.data.teamId)
    .eq("club_id", parsed.data.clubId);

  if (error) {
    return { ok: false, error: "Could not delete team. Please retry." };
  }

  revalidatePath(`/clubs/${parsed.data.clubId}/members`);
  revalidatePath(`/clubs/${parsed.data.clubId}`);
  return { ok: true };
}

export async function assignClubTeamMemberAction(formData: FormData): Promise<ActionResult> {
  const parsed = clubTeamAssignSchema.safeParse({
    clubId: formData.get("club_id"),
    teamId: formData.get("team_id"),
    userId: formData.get("user_id"),
  });

  if (!parsed.success) {
    return { ok: false, error: "Invalid request." };
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    return { ok: false, error: "You must be signed in." };
  }

  const active = await assertClubActiveForMutations(parsed.data.clubId);
  if (!active.ok) {
    return { ok: false, error: active.message };
  }

  const gate = await assertCanManageTeams(user.id, parsed.data.clubId);
  if (!gate.ok) return gate;

  const { data: team } = await supabase
    .from("club_teams")
    .select("id")
    .eq("id", parsed.data.teamId)
    .eq("club_id", parsed.data.clubId)
    .maybeSingle();

  if (!team) {
    return { ok: false, error: "Team not found." };
  }

  const { error } = await supabase.from("club_team_members").insert({
    team_id: parsed.data.teamId,
    user_id: parsed.data.userId,
    added_by: user.id,
  });

  if (error) {
    if (error.code === "23505") {
      return { ok: false, error: "This member is already on that team." };
    }
    if (error.message?.includes("User must be a member")) {
      return { ok: false, error: "That person must be a member of this club." };
    }
    return { ok: false, error: "Could not assign team. Please retry." };
  }

  revalidatePath(`/clubs/${parsed.data.clubId}/members`);
  revalidatePath(`/clubs/${parsed.data.clubId}`);
  return { ok: true };
}

export async function removeClubTeamMemberAction(formData: FormData): Promise<ActionResult> {
  const parsed = clubTeamRemoveMemberSchema.safeParse({
    clubId: formData.get("club_id"),
    teamId: formData.get("team_id"),
    userId: formData.get("user_id"),
  });

  if (!parsed.success) {
    return { ok: false, error: "Invalid request." };
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    return { ok: false, error: "You must be signed in." };
  }

  const active = await assertClubActiveForMutations(parsed.data.clubId);
  if (!active.ok) {
    return { ok: false, error: active.message };
  }

  const gate = await assertCanManageTeams(user.id, parsed.data.clubId);
  if (!gate.ok) return gate;

  const { error } = await supabase
    .from("club_team_members")
    .delete()
    .eq("team_id", parsed.data.teamId)
    .eq("user_id", parsed.data.userId);

  if (error) {
    return { ok: false, error: "Could not remove from team. Please retry." };
  }

  revalidatePath(`/clubs/${parsed.data.clubId}/members`);
  revalidatePath(`/clubs/${parsed.data.clubId}`);
  return { ok: true };
}
