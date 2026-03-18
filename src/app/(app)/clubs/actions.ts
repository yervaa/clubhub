"use server";

import { randomBytes, randomUUID } from "crypto";
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { createAdminClient } from "@/lib/supabase/admin";
import { sanitizeInlineText } from "@/lib/sanitize";
import { createClient } from "@/lib/supabase/server";
import {
  announcementCreateSchema,
  clubCreateSchema,
  clubMembershipSchema,
  eventCreateSchema,
  joinCodeSchema,
  rsvpSchema,
} from "@/lib/validation/clubs";

function generateJoinCode() {
  return randomBytes(4).toString("hex").toUpperCase();
}

function getSafeValidationErrorMessage(result: { error: { issues: Array<{ message: string }> } }) {
  return result.error.issues[0]?.message ?? "Please review your input and try again.";
}

export async function createClubAction(formData: FormData) {
  const parsed = clubCreateSchema.safeParse({
    name: formData.get("name"),
    description: formData.get("description"),
  });

  if (!parsed.success) {
    redirect(`/clubs/create?error=${encodeURIComponent(getSafeValidationErrorMessage(parsed))}`);
  }

  const supabase = await createClient();
  const admin = createAdminClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    redirect("/login");
  }

  const { error: profileError } = await supabase.from("profiles").upsert(
    {
      id: user.id,
      email: user.email ?? "",
      full_name:
        typeof user.user_metadata?.full_name === "string"
          ? sanitizeInlineText(user.user_metadata.full_name).slice(0, 80)
          : "",
    },
    { onConflict: "id" },
  );

  if (profileError) {
    redirect("/clubs/create?error=Unable+to+prepare+your+profile.+Please+retry.");
  }

  const clubId = randomUUID();
  let created = false;

  for (let attempt = 0; attempt < 5; attempt += 1) {
    const joinCode = generateJoinCode();
    const { error: clubInsertError } = await supabase.from("clubs").insert({
      id: clubId,
      name: parsed.data.name,
      description: parsed.data.description,
      join_code: joinCode,
      created_by: user.id,
    });

    if (!clubInsertError) {
      created = true;
      break;
    }

    if (clubInsertError.code !== "23505") {
      redirect("/clubs/create?error=Could+not+create+club.+Please+retry.");
    }
  }

  if (!created) {
    redirect("/clubs/create?error=Could+not+generate+a+join+code.+Please+retry.");
  }

  const membershipPayload = clubMembershipSchema.parse({
    clubId,
    userId: user.id,
    role: "officer",
  });
  const { error: memberError } = await admin.from("club_members").insert({
    club_id: membershipPayload.clubId,
    user_id: membershipPayload.userId,
    role: membershipPayload.role,
  });

  if (memberError) {
    redirect("/clubs/create?error=Club+created+but+membership+failed.+Contact+support.");
  }

  revalidatePath("/dashboard");
  revalidatePath("/clubs");
  redirect("/clubs?success=Club+created+successfully.");
}

export async function joinClubAction(formData: FormData) {
  const parsed = joinCodeSchema.safeParse({
    joinCode: formData.get("join_code"),
  });

  if (!parsed.success) {
    redirect(`/clubs/join?error=${encodeURIComponent(getSafeValidationErrorMessage(parsed))}`);
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    redirect("/login");
  }

  const admin = createAdminClient();
  const { data: club, error: clubLookupError } = await admin
    .from("clubs")
    .select("id")
    .eq("join_code", parsed.data.joinCode)
    .maybeSingle();

  if (clubLookupError) {
    redirect("/clubs/join?error=Could+not+validate+join+code.+Please+retry.");
  }

  if (!club) {
    redirect("/clubs/join?error=Invalid+join+code.");
  }

  const { data: existingMembership } = await supabase
    .from("club_members")
    .select("id")
    .eq("club_id", club.id)
    .eq("user_id", user.id)
    .maybeSingle();

  if (existingMembership) {
    redirect("/clubs/join?error=You+are+already+a+member+of+this+club.");
  }

  const membershipPayload = clubMembershipSchema.parse({
    clubId: club.id,
    userId: user.id,
    role: "member",
  });
  const { error: joinError } = await supabase.from("club_members").insert({
    club_id: membershipPayload.clubId,
    user_id: membershipPayload.userId,
    role: membershipPayload.role,
  });

  if (joinError) {
    if (joinError.code === "23505") {
      redirect("/clubs/join?error=You+are+already+a+member+of+this+club.");
    }
    redirect("/clubs/join?error=Unable+to+join+club.+Please+retry.");
  }

  revalidatePath("/dashboard");
  revalidatePath("/clubs");
  redirect("/clubs?success=You+joined+the+club.");
}

export async function createAnnouncementAction(formData: FormData) {
  const parsed = announcementCreateSchema.safeParse({
    clubId: formData.get("club_id"),
    title: formData.get("title"),
    content: formData.get("content"),
  });

  if (!parsed.success) {
    const fallbackClubId = typeof formData.get("club_id") === "string" ? formData.get("club_id") : "";
    if (fallbackClubId) {
      redirect(`/clubs/${fallbackClubId}?annError=${encodeURIComponent(getSafeValidationErrorMessage(parsed))}`);
    }
    redirect("/clubs?error=Invalid+club.");
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    redirect("/login");
  }

  const { data: membership, error: membershipError } = await supabase
    .from("club_members")
    .select("role")
    .eq("club_id", parsed.data.clubId)
    .eq("user_id", user.id)
    .maybeSingle();

  if (membershipError || !membership) {
    redirect(`/clubs/${parsed.data.clubId}?annError=You+do+not+have+access+to+this+club.`);
  }

  if (membership.role !== "officer") {
    redirect(`/clubs/${parsed.data.clubId}?annError=Only+officers+can+create+announcements.`);
  }

  const { error: insertError } = await supabase.from("announcements").insert({
    club_id: parsed.data.clubId,
    title: parsed.data.title,
    content: parsed.data.content,
    created_by: user.id,
  });

  if (insertError) {
    redirect(`/clubs/${parsed.data.clubId}?annError=Unable+to+create+announcement.+Please+retry.`);
  }

  revalidatePath(`/clubs/${parsed.data.clubId}`);
  redirect(`/clubs/${parsed.data.clubId}?annSuccess=Announcement+posted.`);
}

export async function createEventAction(formData: FormData) {
  const parsed = eventCreateSchema.safeParse({
    clubId: formData.get("club_id"),
    title: formData.get("title"),
    description: formData.get("description"),
    location: formData.get("location"),
    eventDate: formData.get("event_date"),
  });

  if (!parsed.success) {
    const fallbackClubId = typeof formData.get("club_id") === "string" ? formData.get("club_id") : "";
    if (fallbackClubId) {
      redirect(`/clubs/${fallbackClubId}?eventError=${encodeURIComponent(getSafeValidationErrorMessage(parsed))}`);
    }
    redirect("/clubs?error=Invalid+club.");
  }
  const eventDate = new Date(parsed.data.eventDate);

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    redirect("/login");
  }

  const { data: membership, error: membershipError } = await supabase
    .from("club_members")
    .select("role")
    .eq("club_id", parsed.data.clubId)
    .eq("user_id", user.id)
    .maybeSingle();

  if (membershipError || !membership) {
    redirect(`/clubs/${parsed.data.clubId}?eventError=You+do+not+have+access+to+this+club.`);
  }

  if (membership.role !== "officer") {
    redirect(`/clubs/${parsed.data.clubId}?eventError=Only+officers+can+create+events.`);
  }

  const { error: insertError } = await supabase.from("events").insert({
    club_id: parsed.data.clubId,
    title: parsed.data.title,
    description: parsed.data.description,
    location: parsed.data.location,
    event_date: eventDate.toISOString(),
    created_by: user.id,
  });

  if (insertError) {
    redirect(`/clubs/${parsed.data.clubId}?eventError=Unable+to+create+event.+Please+retry.`);
  }

  revalidatePath(`/clubs/${parsed.data.clubId}`);
  redirect(`/clubs/${parsed.data.clubId}?eventSuccess=Event+created.`);
}

export async function upsertRsvpAction(formData: FormData) {
  const parsed = rsvpSchema.safeParse({
    clubId: formData.get("club_id"),
    eventId: formData.get("event_id"),
    status: formData.get("status"),
  });

  if (!parsed.success) {
    const fallbackClubId = typeof formData.get("club_id") === "string" ? formData.get("club_id") : "";
    if (fallbackClubId) {
      redirect(`/clubs/${fallbackClubId}?rsvpError=${encodeURIComponent(getSafeValidationErrorMessage(parsed))}`);
    }
    redirect("/clubs?error=Invalid+event+request.");
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    redirect("/login");
  }

  const { data: membership, error: membershipError } = await supabase
    .from("club_members")
    .select("id")
    .eq("club_id", parsed.data.clubId)
    .eq("user_id", user.id)
    .maybeSingle();

  if (membershipError || !membership) {
    redirect(`/clubs/${parsed.data.clubId}?rsvpError=You+do+not+have+access+to+this+club+event.`);
  }

  const { data: eventRow, error: eventError } = await supabase
    .from("events")
    .select("id, club_id")
    .eq("id", parsed.data.eventId)
    .maybeSingle();

  if (eventError || !eventRow || eventRow.club_id !== parsed.data.clubId) {
    redirect(`/clubs/${parsed.data.clubId}?rsvpError=Event+not+found+for+this+club.`);
  }

  const { error: upsertError } = await supabase.from("rsvps").upsert(
    {
      event_id: parsed.data.eventId,
      user_id: user.id,
      status: parsed.data.status,
    },
    { onConflict: "event_id,user_id" },
  );

  if (upsertError) {
    redirect(`/clubs/${parsed.data.clubId}?rsvpError=Unable+to+save+RSVP.+Please+retry.`);
  }

  revalidatePath(`/clubs/${parsed.data.clubId}`);
  redirect(`/clubs/${parsed.data.clubId}?rsvpSuccess=RSVP+saved.`);
}
