"use server";

import { revalidatePath } from "next/cache";
import { assertClubActiveForMutations } from "@/lib/clubs/club-status";
import { isViewerActiveLegacyOfficer } from "@/lib/clubs/member-management-access";
import { hasPermission } from "@/lib/rbac/permissions";
import { createClient } from "@/lib/supabase/server";
import {
  volunteerHoursAddSchema,
  volunteerHoursDeleteSchema,
  volunteerHoursUpdateSchema,
} from "@/lib/validation/clubs";

type ActionResult = { ok: true } | { ok: false; error: string };

async function assertCanManageVolunteerHours(userId: string, clubId: string): Promise<ActionResult> {
  if (await hasPermission(userId, clubId, "members.manage_volunteer_hours")) {
    return { ok: true };
  }
  const supabase = await createClient();
  const { data: row } = await supabase
    .from("club_members")
    .select("role, membership_status")
    .eq("club_id", clubId)
    .eq("user_id", userId)
    .maybeSingle();
  if (isViewerActiveLegacyOfficer(row ?? null)) {
    return { ok: true };
  }
  return { ok: false, error: "You do not have permission to manage volunteer hours." };
}

export async function addVolunteerHoursEntryAction(formData: FormData): Promise<ActionResult> {
  const parsed = volunteerHoursAddSchema.safeParse({
    clubId: formData.get("club_id"),
    userId: formData.get("user_id"),
    hours: formData.get("hours"),
    note: formData.get("note") ?? undefined,
    serviceDate: formData.get("service_date"),
  });

  if (!parsed.success) {
    return { ok: false, error: parsed.error.issues[0]?.message ?? "Invalid volunteer hours entry." };
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

  const gate = await assertCanManageVolunteerHours(user.id, parsed.data.clubId);
  if (!gate.ok) return gate;

  const { error } = await supabase.from("club_member_volunteer_hours").insert({
    club_id: parsed.data.clubId,
    user_id: parsed.data.userId,
    hours: parsed.data.hours,
    note: parsed.data.note ?? null,
    service_date: parsed.data.serviceDate,
    created_by: user.id,
    updated_by: user.id,
  });

  if (error) {
    if (error.code === "23514" || error.message?.includes("enforce_volunteer_hours")) {
      return { ok: false, error: "Hours can only be logged for current members of this club." };
    }
    return { ok: false, error: "Could not save volunteer hours. Please retry." };
  }

  revalidatePath(`/clubs/${parsed.data.clubId}/members`);
  revalidatePath(`/clubs/${parsed.data.clubId}`);
  return { ok: true };
}

export async function updateVolunteerHoursEntryAction(formData: FormData): Promise<ActionResult> {
  const parsed = volunteerHoursUpdateSchema.safeParse({
    clubId: formData.get("club_id"),
    entryId: formData.get("entry_id"),
    hours: formData.get("hours"),
    note: formData.get("note") ?? undefined,
    serviceDate: formData.get("service_date"),
  });

  if (!parsed.success) {
    return { ok: false, error: parsed.error.issues[0]?.message ?? "Invalid volunteer hours update." };
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

  const gate = await assertCanManageVolunteerHours(user.id, parsed.data.clubId);
  if (!gate.ok) return gate;

  const { data: existing, error: fetchErr } = await supabase
    .from("club_member_volunteer_hours")
    .select("id")
    .eq("id", parsed.data.entryId)
    .eq("club_id", parsed.data.clubId)
    .maybeSingle();

  if (fetchErr || !existing) {
    return { ok: false, error: "That entry was not found." };
  }

  const nowIso = new Date().toISOString();
  const { error } = await supabase
    .from("club_member_volunteer_hours")
    .update({
      hours: parsed.data.hours,
      note: parsed.data.note ?? null,
      service_date: parsed.data.serviceDate,
      updated_at: nowIso,
      updated_by: user.id,
    })
    .eq("id", parsed.data.entryId)
    .eq("club_id", parsed.data.clubId);

  if (error) {
    return { ok: false, error: "Could not update volunteer hours. Please retry." };
  }

  revalidatePath(`/clubs/${parsed.data.clubId}/members`);
  revalidatePath(`/clubs/${parsed.data.clubId}`);
  return { ok: true };
}

export async function deleteVolunteerHoursEntryAction(formData: FormData): Promise<ActionResult> {
  const parsed = volunteerHoursDeleteSchema.safeParse({
    clubId: formData.get("club_id"),
    entryId: formData.get("entry_id"),
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

  const gate = await assertCanManageVolunteerHours(user.id, parsed.data.clubId);
  if (!gate.ok) return gate;

  const { error } = await supabase
    .from("club_member_volunteer_hours")
    .delete()
    .eq("id", parsed.data.entryId)
    .eq("club_id", parsed.data.clubId);

  if (error) {
    return { ok: false, error: "Could not remove volunteer hours. Please retry." };
  }

  revalidatePath(`/clubs/${parsed.data.clubId}/members`);
  revalidatePath(`/clubs/${parsed.data.clubId}`);
  return { ok: true };
}
