"use server";

import { randomBytes, randomUUID } from "crypto";
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { enforceRateLimit, getRateLimitErrorMessage } from "@/lib/rate-limit";
import { sanitizeInlineText } from "@/lib/sanitize";
import { createClient } from "@/lib/supabase/server";
import {
  announcementCreateSchema,
  clubCreateSchema,
  eventCreateSchema,
  joinCodeSchema,
  memberRemovalSchema,
  memberRoleUpdateSchema,
  rsvpSchema,
} from "@/lib/validation/clubs";

function generateJoinCode() {
  return randomBytes(4).toString("hex").toUpperCase();
}

function getSafeValidationErrorMessage(result: { error: { issues: Array<{ message: string }> } }) {
  return result.error.issues[0]?.message ?? "Please review your input and try again.";
}

function logClubCreateError(stage: string, details: Record<string, unknown>) {
  console.error(`[club-create:${stage}]`, details);
}

async function ensureCreatorOfficerMembership(supabase: Awaited<ReturnType<typeof createClient>>, clubId: string, userId: string) {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const { data: membership, error: membershipError } = await supabase
      .from("club_members")
      .select("role")
      .eq("club_id", clubId)
      .eq("user_id", userId)
      .maybeSingle();

    if (membershipError) {
      return { ok: false as const };
    }

    if (membership?.role === "officer") {
      return { ok: true as const, repaired: false };
    }

    if (attempt < 2) {
      await new Promise((resolve) => setTimeout(resolve, 150));
    }
  }

  console.warn(`Club creator membership missing after club insert for club ${clubId}. Falling back to ensure_club_creator_membership().`);

  const { data: fallbackApplied, error: fallbackError } = await supabase.rpc("ensure_club_creator_membership", {
    target_club_id: clubId,
  });

  if (fallbackError || !fallbackApplied) {
    return { ok: false as const };
  }

  const { data: verifiedMembership, error: verifyError } = await supabase
    .from("club_members")
    .select("role")
    .eq("club_id", clubId)
    .eq("user_id", userId)
    .maybeSingle();

  if (verifyError || verifiedMembership?.role !== "officer") {
    return { ok: false as const };
  }

  return { ok: true as const, repaired: true };
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
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    redirect("/login");
  }

  const rateLimit = await enforceRateLimit({
    policy: "clubCreate",
    userId: user.id,
  });
  if (!rateLimit.success) {
    redirect(`/clubs/create?error=${encodeURIComponent(getRateLimitErrorMessage())}`);
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
    logClubCreateError("profile-upsert", {
      userId: user.id,
      code: profileError.code,
      message: profileError.message,
      details: profileError.details,
    });
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

    logClubCreateError("club-insert", {
      userId: user.id,
      clubId,
      joinCode,
      code: clubInsertError.code,
      message: clubInsertError.message,
      details: clubInsertError.details,
    });

    if (clubInsertError.code !== "23505") {
      const membershipCheck = await ensureCreatorOfficerMembership(supabase, clubId, user.id);

      if (membershipCheck.ok) {
        created = true;
        break;
      }

      redirect("/clubs/create?error=Club+was+created,+but+setup+did+not+finish+correctly.");
    }
  }

  if (!created) {
    redirect("/clubs/create?error=Could+not+generate+a+join+code.+Please+retry.");
  }

  const membershipCheck = await ensureCreatorOfficerMembership(supabase, clubId, user.id);

  if (!membershipCheck.ok) {
    logClubCreateError("membership-verify", {
      userId: user.id,
      clubId,
    });
    redirect("/clubs/create?error=Club+created+but+officer+membership+verification+failed.+Apply+the+latest+database+migration.");
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

  const rateLimit = await enforceRateLimit({
    policy: "clubJoin",
    userId: user.id,
  });
  if (!rateLimit.success) {
    redirect(`/clubs/join?error=${encodeURIComponent(getRateLimitErrorMessage())}`);
  }

  const { data: clubId, error: clubLookupError } = await supabase.rpc("find_club_by_join_code", {
    target_join_code: parsed.data.joinCode,
  });

  if (clubLookupError) {
    redirect("/clubs/join?error=Could+not+validate+join+code.+Please+retry.");
  }

  if (!clubId) {
    redirect("/clubs/join?error=Invalid+join+code.");
  }

  const { data: existingMembership } = await supabase
    .from("club_members")
    .select("id")
    .eq("club_id", clubId)
    .eq("user_id", user.id)
    .maybeSingle();

  if (existingMembership) {
    redirect("/clubs/join?error=You+are+already+a+member+of+this+club.");
  }

  const { error: joinError } = await supabase.from("club_members").insert({
    club_id: clubId,
    user_id: user.id,
    role: "member",
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

  const rateLimit = await enforceRateLimit({
    policy: "announcementCreate",
    userId: user.id,
  });
  if (!rateLimit.success) {
    redirect(`/clubs/${parsed.data.clubId}?annError=${encodeURIComponent(getRateLimitErrorMessage())}`);
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

function getMemberManagementErrorMessage(status: string) {
  switch (status) {
    case "cannot_edit_self":
      return "You cannot change your own membership from this screen.";
    case "last_officer":
      return "This club must keep at least one officer.";
    case "not_found":
      return "That member could not be found in this club.";
    case "not_allowed":
      return "Only officers can manage members.";
    default:
      return "Unable to update this member right now.";
  }
}

export async function updateMemberRoleAction(formData: FormData) {
  const parsed = memberRoleUpdateSchema.safeParse({
    clubId: formData.get("club_id"),
    userId: formData.get("user_id"),
    role: formData.get("role"),
  });

  if (!parsed.success) {
    const fallbackClubId = typeof formData.get("club_id") === "string" ? formData.get("club_id") : "";
    if (fallbackClubId) {
      redirect(`/clubs/${fallbackClubId}?memberError=${encodeURIComponent(getSafeValidationErrorMessage(parsed))}`);
    }
    redirect("/clubs?error=Invalid+member+request.");
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    redirect("/login");
  }

  const { data: status, error } = await supabase.rpc("update_club_member_role", {
    target_club_id: parsed.data.clubId,
    target_user_id: parsed.data.userId,
    new_role: parsed.data.role,
  });

  if (error || status !== "ok") {
    redirect(`/clubs/${parsed.data.clubId}?memberError=${encodeURIComponent(getMemberManagementErrorMessage(status ?? "unknown"))}`);
  }

  revalidatePath(`/clubs/${parsed.data.clubId}`);
  revalidatePath("/clubs");
  revalidatePath("/dashboard");
  redirect(`/clubs/${parsed.data.clubId}?memberSuccess=Member+updated.`);
}

export async function removeMemberAction(formData: FormData) {
  const parsed = memberRemovalSchema.safeParse({
    clubId: formData.get("club_id"),
    userId: formData.get("user_id"),
  });

  if (!parsed.success) {
    const fallbackClubId = typeof formData.get("club_id") === "string" ? formData.get("club_id") : "";
    if (fallbackClubId) {
      redirect(`/clubs/${fallbackClubId}?memberError=${encodeURIComponent(getSafeValidationErrorMessage(parsed))}`);
    }
    redirect("/clubs?error=Invalid+member+request.");
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    redirect("/login");
  }

  const { data: status, error } = await supabase.rpc("remove_club_member", {
    target_club_id: parsed.data.clubId,
    target_user_id: parsed.data.userId,
  });

  if (error || status !== "ok") {
    redirect(`/clubs/${parsed.data.clubId}?memberError=${encodeURIComponent(getMemberManagementErrorMessage(status ?? "unknown"))}`);
  }

  revalidatePath(`/clubs/${parsed.data.clubId}`);
  revalidatePath("/clubs");
  revalidatePath("/dashboard");
  redirect(`/clubs/${parsed.data.clubId}?memberSuccess=Member+removed.`);
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

  const rateLimit = await enforceRateLimit({
    policy: "eventCreate",
    userId: user.id,
  });
  if (!rateLimit.success) {
    redirect(`/clubs/${parsed.data.clubId}?eventError=${encodeURIComponent(getRateLimitErrorMessage())}`);
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

  const rateLimit = await enforceRateLimit({
    policy: "rsvpWrite",
    userId: user.id,
  });
  if (!rateLimit.success) {
    redirect(`/clubs/${parsed.data.clubId}?rsvpError=${encodeURIComponent(getRateLimitErrorMessage())}`);
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
