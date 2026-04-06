"use server";

import { revalidatePath } from "next/cache";
import { assertClubActiveForMutations } from "@/lib/clubs/club-status";
import { hasPermission } from "@/lib/rbac/permissions";
import { createClient } from "@/lib/supabase/server";
import {
  clubMemberTagAssignSchema,
  clubMemberTagCreateSchema,
  clubMemberTagDeleteSchema,
  clubMemberTagRemoveSchema,
} from "@/lib/validation/clubs";

type ActionResult = { ok: true } | { ok: false; error: string };

async function assertCanManageTags(userId: string, clubId: string): Promise<ActionResult> {
  const supabase = await createClient();
  const allowedByRbac = await hasPermission(userId, clubId, "members.manage_tags");
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

  return { ok: false, error: "You do not have permission to manage member tags." };
}

export async function createClubMemberTagAction(formData: FormData): Promise<ActionResult> {
  const parsed = clubMemberTagCreateSchema.safeParse({
    clubId: formData.get("club_id"),
    name: formData.get("name"),
  });

  if (!parsed.success) {
    return { ok: false, error: parsed.error.issues[0]?.message ?? "Invalid tag name." };
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

  const gate = await assertCanManageTags(user.id, parsed.data.clubId);
  if (!gate.ok) return gate;

  const { error } = await supabase.from("club_member_tags").insert({
    club_id: parsed.data.clubId,
    name: parsed.data.name,
  });

  if (error) {
    if (error.code === "23505") {
      return { ok: false, error: "A tag with this name already exists in this club." };
    }
    return { ok: false, error: "Could not create tag. Please retry." };
  }

  revalidatePath(`/clubs/${parsed.data.clubId}/members`);
  revalidatePath(`/clubs/${parsed.data.clubId}`);
  return { ok: true };
}

export async function assignClubMemberTagAction(formData: FormData): Promise<ActionResult> {
  const parsed = clubMemberTagAssignSchema.safeParse({
    clubId: formData.get("club_id"),
    tagId: formData.get("tag_id"),
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

  const gate = await assertCanManageTags(user.id, parsed.data.clubId);
  if (!gate.ok) return gate;

  const { error } = await supabase.from("club_member_tag_assignments").insert({
    tag_id: parsed.data.tagId,
    user_id: parsed.data.userId,
    assigned_by: user.id,
  });

  if (error) {
    if (error.code === "23505") {
      return { ok: false, error: "This member already has that tag." };
    }
    if (error.message?.includes("User must be a member")) {
      return { ok: false, error: "That person must be an active member of this club." };
    }
    return { ok: false, error: "Could not assign tag. Please retry." };
  }

  revalidatePath(`/clubs/${parsed.data.clubId}/members`);
  revalidatePath(`/clubs/${parsed.data.clubId}`);
  return { ok: true };
}

export async function removeClubMemberTagAction(formData: FormData): Promise<ActionResult> {
  const parsed = clubMemberTagRemoveSchema.safeParse({
    clubId: formData.get("club_id"),
    tagId: formData.get("tag_id"),
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

  const gate = await assertCanManageTags(user.id, parsed.data.clubId);
  if (!gate.ok) return gate;

  const { error } = await supabase
    .from("club_member_tag_assignments")
    .delete()
    .eq("tag_id", parsed.data.tagId)
    .eq("user_id", parsed.data.userId);

  if (error) {
    return { ok: false, error: "Could not remove tag. Please retry." };
  }

  revalidatePath(`/clubs/${parsed.data.clubId}/members`);
  revalidatePath(`/clubs/${parsed.data.clubId}`);
  return { ok: true };
}

export async function deleteClubMemberTagAction(formData: FormData): Promise<ActionResult> {
  const parsed = clubMemberTagDeleteSchema.safeParse({
    clubId: formData.get("club_id"),
    tagId: formData.get("tag_id"),
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

  const gate = await assertCanManageTags(user.id, parsed.data.clubId);
  if (!gate.ok) return gate;

  const { error } = await supabase
    .from("club_member_tags")
    .delete()
    .eq("id", parsed.data.tagId)
    .eq("club_id", parsed.data.clubId);

  if (error) {
    return { ok: false, error: "Could not delete tag. Please retry." };
  }

  revalidatePath(`/clubs/${parsed.data.clubId}/members`);
  revalidatePath(`/clubs/${parsed.data.clubId}`);
  return { ok: true };
}
