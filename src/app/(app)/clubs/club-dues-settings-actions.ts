"use server";

import { revalidatePath } from "next/cache";
import { assertClubActiveForMutations } from "@/lib/clubs/club-status";
import { assertPermissionOrActiveLegacyOfficer } from "@/lib/clubs/member-management-access";
import { createClient } from "@/lib/supabase/server";
import { clubDuesSettingsUpsertSchema } from "@/lib/validation/clubs";

type ActionResult = { ok: true } | { ok: false; error: string };

export async function upsertClubDuesSettingsAction(formData: FormData): Promise<ActionResult> {
  const parsed = clubDuesSettingsUpsertSchema.safeParse({
    clubId: formData.get("club_id"),
    label: formData.get("label"),
    dueDate: formData.get("due_date"),
    amount: formData.get("amount"),
    currency: formData.get("currency"),
  });

  if (!parsed.success) {
    return { ok: false, error: parsed.error.issues[0]?.message ?? "Invalid dues settings." };
  }

  const { clubId, label, dueDate, amountCents, currency } = parsed.data;

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    return { ok: false, error: "You must be signed in." };
  }

  const active = await assertClubActiveForMutations(clubId);
  if (!active.ok) {
    return { ok: false, error: active.message };
  }

  const gate = await assertPermissionOrActiveLegacyOfficer(
    user.id,
    clubId,
    "members.manage_member_dues",
    "You do not have permission to manage member dues.",
  );
  if (!gate.ok) return gate;

  const { error } = await supabase.from("club_dues_settings").upsert(
    {
      club_id: clubId,
      label,
      amount_cents: amountCents,
      due_date: dueDate,
      currency,
    },
    { onConflict: "club_id" },
  );

  if (error) {
    return { ok: false, error: "Could not save dues settings. Please retry." };
  }

  revalidatePath(`/clubs/${clubId}/members`);
  revalidatePath(`/clubs/${clubId}`);
  return { ok: true };
}
