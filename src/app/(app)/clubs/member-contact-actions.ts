"use server";

import { revalidatePath } from "next/cache";
import { assertClubActiveForMutations } from "@/lib/clubs/club-status";
import { createClient } from "@/lib/supabase/server";
import { clubMemberContactUpsertSchema } from "@/lib/validation/clubs";
import { z } from "zod";

const contactLookupSchema = z.object({
  clubId: z.uuid("Invalid club."),
  memberUserId: z.uuid("Invalid member."),
});

export type ClubMemberContactView = {
  phoneNumber: string | null;
  preferredContactMethod: "email" | "phone" | "either" | null;
};

/**
 * Loads one member’s club contact row. RLS allows: own row, or leadership with
 * `members.view_member_contact` / active officer. Returns null when no row or no access.
 */
export async function getClubMemberContactAction(
  clubId: string,
  memberUserId: string,
): Promise<{ ok: true; contact: ClubMemberContactView | null } | { ok: false; error: string }> {
  const parsed = contactLookupSchema.safeParse({ clubId, memberUserId });
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

  const { data, error } = await supabase
    .from("club_member_contact")
    .select("phone_number, preferred_contact_method")
    .eq("club_id", parsed.data.clubId)
    .eq("user_id", parsed.data.memberUserId)
    .maybeSingle();

  if (error) {
    return { ok: false, error: "Could not load contact info." };
  }

  if (!data) {
    return { ok: true, contact: null };
  }

  return {
    ok: true,
    contact: {
      phoneNumber: (data.phone_number as string | null) ?? null,
      preferredContactMethod: (data.preferred_contact_method as ClubMemberContactView["preferredContactMethod"]) ?? null,
    },
  };
}

/** Active members only; self only (RLS + trigger). Clears row when both fields empty. */
export async function upsertClubMemberContactAction(
  input: unknown,
): Promise<{ ok: true } | { ok: false; error: string }> {
  const parsed = clubMemberContactUpsertSchema.safeParse(input);
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

  const { clubId, phoneNumber } = parsed.data;
  const preferredContactMethod = parsed.data.preferredContactMethod ?? null;

  if (phoneNumber === null && preferredContactMethod === null) {
    const { error } = await supabase
      .from("club_member_contact")
      .delete()
      .eq("club_id", clubId)
      .eq("user_id", user.id);

    if (error) {
      return { ok: false, error: "Could not clear contact info." };
    }

    revalidatePath(`/clubs/${clubId}/members`);
    return { ok: true };
  }

  const { error } = await supabase.from("club_member_contact").upsert(
    {
      club_id: clubId,
      user_id: user.id,
      phone_number: phoneNumber,
      preferred_contact_method: preferredContactMethod,
    },
    { onConflict: "club_id,user_id" },
  );

  if (error) {
    if (error.message?.toLowerCase().includes("active membership")) {
      return { ok: false, error: "Only active members can update club contact." };
    }
    return { ok: false, error: "Could not save contact info." };
  }

  revalidatePath(`/clubs/${clubId}/members`);
  return { ok: true };
}
