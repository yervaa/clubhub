"use server";

import { revalidatePath } from "next/cache";
import { assertClubActiveForMutations } from "@/lib/clubs/club-status";
import { hasPermission } from "@/lib/rbac/permissions";
import { createClient } from "@/lib/supabase/server";
import {
  clubCommitteeAssignSchema,
  clubCommitteeCreateSchema,
  clubCommitteeDeleteSchema,
  clubCommitteeRemoveMemberSchema,
  clubCommitteeRenameSchema,
} from "@/lib/validation/clubs";

type ActionResult = { ok: true } | { ok: false; error: string };

async function assertCanManageCommittees(userId: string, clubId: string): Promise<ActionResult> {
  const supabase = await createClient();
  const allowedByRbac = await hasPermission(userId, clubId, "members.manage_committees");
  if (allowedByRbac) return { ok: true };

  const { data: row } = await supabase
    .from("club_members")
    .select("role")
    .eq("club_id", clubId)
    .eq("user_id", userId)
    .maybeSingle();

  if (row?.role === "officer") {
    return { ok: true };
  }

  return { ok: false, error: "You do not have permission to manage committees." };
}

export async function createClubCommitteeAction(formData: FormData): Promise<ActionResult> {
  const parsed = clubCommitteeCreateSchema.safeParse({
    clubId: formData.get("club_id"),
    name: formData.get("name"),
  });

  if (!parsed.success) {
    return { ok: false, error: parsed.error.issues[0]?.message ?? "Invalid committee name." };
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

  const gate = await assertCanManageCommittees(user.id, parsed.data.clubId);
  if (!gate.ok) return gate;

  const { error } = await supabase.from("club_committees").insert({
    club_id: parsed.data.clubId,
    name: parsed.data.name,
  });

  if (error) {
    if (error.code === "23505") {
      return { ok: false, error: "A committee with this name already exists in this club." };
    }
    return { ok: false, error: "Could not create committee. Please retry." };
  }

  revalidatePath(`/clubs/${parsed.data.clubId}/members`);
  revalidatePath(`/clubs/${parsed.data.clubId}`);
  return { ok: true };
}

export async function renameClubCommitteeAction(formData: FormData): Promise<ActionResult> {
  const parsed = clubCommitteeRenameSchema.safeParse({
    clubId: formData.get("club_id"),
    committeeId: formData.get("committee_id"),
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

  const gate = await assertCanManageCommittees(user.id, parsed.data.clubId);
  if (!gate.ok) return gate;

  const { error } = await supabase
    .from("club_committees")
    .update({ name: parsed.data.name })
    .eq("id", parsed.data.committeeId)
    .eq("club_id", parsed.data.clubId);

  if (error) {
    if (error.code === "23505") {
      return { ok: false, error: "A committee with this name already exists in this club." };
    }
    return { ok: false, error: "Could not rename committee. Please retry." };
  }

  revalidatePath(`/clubs/${parsed.data.clubId}/members`);
  revalidatePath(`/clubs/${parsed.data.clubId}`);
  return { ok: true };
}

export async function deleteClubCommitteeAction(formData: FormData): Promise<ActionResult> {
  const parsed = clubCommitteeDeleteSchema.safeParse({
    clubId: formData.get("club_id"),
    committeeId: formData.get("committee_id"),
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

  const gate = await assertCanManageCommittees(user.id, parsed.data.clubId);
  if (!gate.ok) return gate;

  const { error } = await supabase
    .from("club_committees")
    .delete()
    .eq("id", parsed.data.committeeId)
    .eq("club_id", parsed.data.clubId);

  if (error) {
    return { ok: false, error: "Could not delete committee. Please retry." };
  }

  revalidatePath(`/clubs/${parsed.data.clubId}/members`);
  revalidatePath(`/clubs/${parsed.data.clubId}`);
  return { ok: true };
}

export async function assignClubCommitteeMemberAction(formData: FormData): Promise<ActionResult> {
  const parsed = clubCommitteeAssignSchema.safeParse({
    clubId: formData.get("club_id"),
    committeeId: formData.get("committee_id"),
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

  const gate = await assertCanManageCommittees(user.id, parsed.data.clubId);
  if (!gate.ok) return gate;

  const { data: committee } = await supabase
    .from("club_committees")
    .select("id")
    .eq("id", parsed.data.committeeId)
    .eq("club_id", parsed.data.clubId)
    .maybeSingle();

  if (!committee) {
    return { ok: false, error: "Committee not found." };
  }

  const { error } = await supabase.from("club_committee_members").insert({
    committee_id: parsed.data.committeeId,
    user_id: parsed.data.userId,
    added_by: user.id,
  });

  if (error) {
    if (error.code === "23505") {
      return { ok: false, error: "This member is already on that committee." };
    }
    if (error.message?.includes("User must be a member")) {
      return { ok: false, error: "That person must be a member of this club." };
    }
    return { ok: false, error: "Could not assign committee. Please retry." };
  }

  revalidatePath(`/clubs/${parsed.data.clubId}/members`);
  revalidatePath(`/clubs/${parsed.data.clubId}`);
  return { ok: true };
}

export async function removeClubCommitteeMemberAction(formData: FormData): Promise<ActionResult> {
  const parsed = clubCommitteeRemoveMemberSchema.safeParse({
    clubId: formData.get("club_id"),
    committeeId: formData.get("committee_id"),
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

  const gate = await assertCanManageCommittees(user.id, parsed.data.clubId);
  if (!gate.ok) return gate;

  const { error } = await supabase
    .from("club_committee_members")
    .delete()
    .eq("committee_id", parsed.data.committeeId)
    .eq("user_id", parsed.data.userId);

  if (error) {
    return { ok: false, error: "Could not remove from committee. Please retry." };
  }

  revalidatePath(`/clubs/${parsed.data.clubId}/members`);
  revalidatePath(`/clubs/${parsed.data.clubId}`);
  return { ok: true };
}
