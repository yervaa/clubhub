"use server";

import { revalidatePath } from "next/cache";
import { assertClubActiveForMutations } from "@/lib/clubs/club-status";
import { assertPermissionOrActiveLegacyOfficer } from "@/lib/clubs/member-management-access";
import { createClient } from "@/lib/supabase/server";
import { clubMemberDuesSetSchema } from "@/lib/validation/clubs";

type ActionResult = { ok: true } | { ok: false; error: string };

export async function setClubMemberDuesAction(formData: FormData): Promise<ActionResult> {
  const parsed = clubMemberDuesSetSchema.safeParse({
    clubId: formData.get("club_id"),
    targetUserId: formData.get("target_user_id"),
    status: formData.get("status"),
    notes: formData.get("notes") ?? "",
  });

  if (!parsed.success) {
    return { ok: false, error: parsed.error.issues[0]?.message ?? "Invalid dues data." };
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
    "members.manage_member_dues",
    "You do not have permission to manage member dues.",
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

  if (parsed.data.status === "unset") {
    const { error } = await supabase
      .from("club_member_dues")
      .delete()
      .eq("club_id", parsed.data.clubId)
      .eq("user_id", parsed.data.targetUserId);

    if (error) {
      return { ok: false, error: "Could not clear dues status. Please retry." };
    }
  } else {
    const notesTrimmed = parsed.data.notes.trim();
    const nowIso = new Date().toISOString();
    const { error } = await supabase.from("club_member_dues").upsert(
      {
        club_id: parsed.data.clubId,
        user_id: parsed.data.targetUserId,
        status: parsed.data.status,
        notes: notesTrimmed,
        updated_at: nowIso,
        updated_by: user.id,
      },
      { onConflict: "club_id,user_id" },
    );

    if (error) {
      if (error.message?.includes("Dues can only be recorded")) {
        return { ok: false, error: "Dues can only be saved for current club members." };
      }
      return { ok: false, error: "Could not save dues status. Please retry." };
    }
  }

  revalidatePath(`/clubs/${parsed.data.clubId}/members`);
  revalidatePath(`/clubs/${parsed.data.clubId}`);
  return { ok: true };
}
