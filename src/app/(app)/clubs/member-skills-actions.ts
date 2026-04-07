"use server";

import { revalidatePath } from "next/cache";
import { assertClubActiveForMutations } from "@/lib/clubs/club-status";
import { isViewerActiveLegacyOfficer } from "@/lib/clubs/member-management-access";
import { hasPermission } from "@/lib/rbac/permissions";
import { createClient } from "@/lib/supabase/server";
import {
  clubMemberSkillInterestAddSchema,
  clubMemberSkillInterestDeleteSchema,
} from "@/lib/validation/clubs";

type ActionResult = { ok: true } | { ok: false; error: string };

const MAX_PER_KIND = 15;

async function assertCanMutateMemberSkills(
  actorId: string,
  clubId: string,
  targetUserId: string,
): Promise<ActionResult> {
  const supabase = await createClient();

  const { data: targetRow, error: targetErr } = await supabase
    .from("club_members")
    .select("membership_status")
    .eq("club_id", clubId)
    .eq("user_id", targetUserId)
    .maybeSingle();

  if (targetErr || !targetRow) {
    return { ok: false, error: "That person is not in this club." };
  }

  if (actorId === targetUserId) {
    if (targetRow.membership_status !== "active") {
      return {
        ok: false,
        error: "Only active members can update their own skills and interests. Ask leadership for changes.",
      };
    }
    return { ok: true };
  }

  if (await hasPermission(actorId, clubId, "members.manage_member_skills")) {
    return { ok: true };
  }

  const { data: actorRow } = await supabase
    .from("club_members")
    .select("role, membership_status")
    .eq("club_id", clubId)
    .eq("user_id", actorId)
    .maybeSingle();

  if (isViewerActiveLegacyOfficer(actorRow ?? null)) {
    return { ok: true };
  }

  return { ok: false, error: "You do not have permission to edit this member’s skills and interests." };
}

export async function addClubMemberSkillInterestAction(formData: FormData): Promise<ActionResult> {
  const parsed = clubMemberSkillInterestAddSchema.safeParse({
    clubId: formData.get("club_id"),
    userId: formData.get("user_id"),
    kind: formData.get("kind"),
    label: formData.get("label"),
  });

  if (!parsed.success) {
    return { ok: false, error: parsed.error.issues[0]?.message ?? "Invalid entry." };
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

  const gate = await assertCanMutateMemberSkills(user.id, parsed.data.clubId, parsed.data.userId);
  if (!gate.ok) return gate;

  const { count, error: countErr } = await supabase
    .from("club_member_skills_interests")
    .select("id", { count: "exact", head: true })
    .eq("club_id", parsed.data.clubId)
    .eq("user_id", parsed.data.userId)
    .eq("kind", parsed.data.kind);

  if (countErr) {
    return { ok: false, error: "Could not verify limits. Please retry." };
  }
  if ((count ?? 0) >= MAX_PER_KIND) {
    return {
      ok: false,
      error: `You can add at most ${MAX_PER_KIND} ${parsed.data.kind === "skill" ? "skills" : "interests"} per member.`,
    };
  }

  const { error } = await supabase.from("club_member_skills_interests").insert({
    club_id: parsed.data.clubId,
    user_id: parsed.data.userId,
    kind: parsed.data.kind,
    label: parsed.data.label,
  });

  if (error) {
    if (error.code === "23505") {
      return { ok: false, error: "That entry is already listed (duplicate)." };
    }
    if (error.message?.includes("Skills and interests can only")) {
      return { ok: false, error: "Skills and interests can only be saved for current club members." };
    }
    return { ok: false, error: "Could not save. Please retry." };
  }

  revalidatePath(`/clubs/${parsed.data.clubId}/members`);
  revalidatePath(`/clubs/${parsed.data.clubId}/members/volunteer-hours`);
  revalidatePath(`/clubs/${parsed.data.clubId}`);
  return { ok: true };
}

export async function deleteClubMemberSkillInterestAction(formData: FormData): Promise<ActionResult> {
  const parsed = clubMemberSkillInterestDeleteSchema.safeParse({
    clubId: formData.get("club_id"),
    entryId: formData.get("entry_id"),
  });

  if (!parsed.success) {
    return { ok: false, error: parsed.error.issues[0]?.message ?? "Invalid request." };
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

  const { data: row, error: fetchErr } = await supabase
    .from("club_member_skills_interests")
    .select("user_id")
    .eq("id", parsed.data.entryId)
    .eq("club_id", parsed.data.clubId)
    .maybeSingle();

  if (fetchErr || !row) {
    return { ok: false, error: "That entry was not found." };
  }

  const gate = await assertCanMutateMemberSkills(user.id, parsed.data.clubId, row.user_id);
  if (!gate.ok) return gate;

  const { error } = await supabase
    .from("club_member_skills_interests")
    .delete()
    .eq("id", parsed.data.entryId)
    .eq("club_id", parsed.data.clubId);

  if (error) {
    return { ok: false, error: "Could not remove. Please retry." };
  }

  revalidatePath(`/clubs/${parsed.data.clubId}/members`);
  revalidatePath(`/clubs/${parsed.data.clubId}/members/volunteer-hours`);
  revalidatePath(`/clubs/${parsed.data.clubId}`);
  return { ok: true };
}
