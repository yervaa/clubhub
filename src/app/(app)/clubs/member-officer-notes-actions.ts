"use server";

import { revalidatePath } from "next/cache";
import { assertClubActiveForMutations } from "@/lib/clubs/club-status";
import { assertPermissionOrActiveLegacyOfficer } from "@/lib/clubs/member-management-access";
import { createClient } from "@/lib/supabase/server";
import { clubMemberOfficerNoteSetSchema } from "@/lib/validation/clubs";

type ActionResult = { ok: true } | { ok: false; error: string };

export async function setClubMemberOfficerNoteAction(formData: FormData): Promise<ActionResult> {
  const parsed = clubMemberOfficerNoteSetSchema.safeParse({
    clubId: formData.get("club_id"),
    targetUserId: formData.get("target_user_id"),
    body: formData.get("body") ?? "",
  });

  if (!parsed.success) {
    return { ok: false, error: parsed.error.issues[0]?.message ?? "Invalid note." };
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

  const gate = await assertPermissionOrActiveLegacyOfficer(
    user.id,
    parsed.data.clubId,
    "members.manage_officer_notes",
    "You do not have permission to manage officer notes.",
  );
  if (!gate.ok) return gate;

  const { data: targetRow } = await supabase
    .from("club_members")
    .select("user_id")
    .eq("club_id", parsed.data.clubId)
    .eq("user_id", parsed.data.targetUserId)
    .maybeSingle();

  if (!targetRow) {
    return { ok: false, error: "That person is not in this club." };
  }

  const trimmed = parsed.data.body.trim();

  if (trimmed === "") {
    const { error } = await supabase
      .from("club_member_officer_notes")
      .delete()
      .eq("club_id", parsed.data.clubId)
      .eq("user_id", parsed.data.targetUserId);

    if (error) {
      return { ok: false, error: "Could not clear the note. Please retry." };
    }
  } else {
    const nowIso = new Date().toISOString();
    const { error } = await supabase.from("club_member_officer_notes").upsert(
      {
        club_id: parsed.data.clubId,
        user_id: parsed.data.targetUserId,
        body: trimmed,
        updated_at: nowIso,
        updated_by: user.id,
      },
      { onConflict: "club_id,user_id" },
    );

    if (error) {
      if (error.message?.includes("Officer notes can only be stored")) {
        return { ok: false, error: "Notes can only be saved for current club members." };
      }
      return { ok: false, error: "Could not save the note. Please retry." };
    }
  }

  revalidatePath(`/clubs/${parsed.data.clubId}/members`);
  revalidatePath(`/clubs/${parsed.data.clubId}`);
  return { ok: true };
}
