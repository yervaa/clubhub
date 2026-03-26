"use server";

import { randomBytes, randomUUID } from "crypto";
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { enforceRateLimit, getRateLimitErrorMessage } from "@/lib/rate-limit";
import { upsertCurrentUserProfile } from "@/lib/profiles";
import { sanitizeInlineText } from "@/lib/sanitize";
import { createAdminClient } from "@/lib/supabase/admin";
import { createClient } from "@/lib/supabase/server";
import {
  announcementCreateSchema,
  attendanceToggleSchema,
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

function logJoinClub(step: string, details: Record<string, unknown>) {
  console.info(`[club-join:${step}]`, details);
}

function logAttendance(step: string, details: Record<string, unknown>) {
  console.info(`[attendance:${step}]`, details);
}

function getAttendanceErrorMessage(code?: string, message?: string) {
  if (code === "42P01") {
    return "Attendance table is missing. Apply the latest database migration.";
  }

  if (code === "42501") {
    return "Attendance permissions are not configured correctly.";
  }

  if (code === "23503") {
    return "This member profile is missing. Have them sign in again, then retry.";
  }

  if (message?.toLowerCase().includes("row-level security")) {
    return "Attendance permissions are not configured correctly.";
  }

  return "Unable to save attendance. Please retry.";
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

  const { error: profileError } = await upsertCurrentUserProfile(supabase, user);

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
    const { error: clubInsertError } = await supabase.rpc("create_club_with_creator_membership", {
      target_club_id: clubId,
      target_name: parsed.data.name,
      target_description: parsed.data.description,
      target_join_code: joinCode,
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
      redirect("/clubs/create?error=Could+not+create+club.+Please+retry.");
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
  revalidatePath(`/clubs/${clubId}`);
  redirect("/clubs?success=Club+created+successfully.");
}

export async function joinClubAction(formData: FormData) {
  const parsed = joinCodeSchema.safeParse({
    joinCode: formData.get("join_code"),
  });

  if (!parsed.success) {
    redirect(`/join?error=${encodeURIComponent(getSafeValidationErrorMessage(parsed))}`);
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    redirect("/login");
  }

  const normalizedJoinCode = parsed.data.joinCode;
  logJoinClub("start", {
    userId: user.id,
    joinCode: normalizedJoinCode,
  });

  const rateLimit = await enforceRateLimit({
    policy: "clubJoin",
    userId: user.id,
  });
  if (!rateLimit.success) {
    redirect(`/join?code=${encodeURIComponent(normalizedJoinCode)}&error=${encodeURIComponent(getRateLimitErrorMessage())}`);
  }

  const admin = createAdminClient();
  const { data: clubRow, error: clubLookupError } = await admin
    .from("clubs")
    .select("id")
    .eq("join_code", normalizedJoinCode)
    .maybeSingle();

  if (clubLookupError) {
    logJoinClub("lookup-error", {
      userId: user.id,
      joinCode: normalizedJoinCode,
      code: clubLookupError.code,
      message: clubLookupError.message,
      details: clubLookupError.details,
    });
    redirect(`/join?code=${encodeURIComponent(normalizedJoinCode)}&error=Unexpected+DB+error.+Please+retry.`);
  }

  if (!clubRow?.id) {
    logJoinClub("invalid-code", {
      userId: user.id,
      joinCode: normalizedJoinCode,
    });
    redirect(`/join?code=${encodeURIComponent(normalizedJoinCode)}&error=Invalid+join+code.`);
  }

  const clubId = clubRow.id;
  logJoinClub("lookup-success", {
    userId: user.id,
    clubId,
    joinCode: normalizedJoinCode,
  });

  const { data: existingMembership } = await supabase
    .from("club_members")
    .select("id")
    .eq("club_id", clubId)
    .eq("user_id", user.id)
    .maybeSingle();

  if (existingMembership) {
    logJoinClub("already-member", {
      userId: user.id,
      clubId,
    });
    redirect(`/join?code=${encodeURIComponent(normalizedJoinCode)}&clubId=${clubId}&error=You+are+already+a+member+of+this+club.`);
  }

  const { error: profileError } = await upsertCurrentUserProfile(supabase, user);

  if (profileError) {
    logJoinClub("profile-error", {
      userId: user.id,
      clubId,
      code: profileError.code,
      message: profileError.message,
      details: profileError.details,
    });
    redirect(`/join?code=${encodeURIComponent(normalizedJoinCode)}&error=Missing+profile.+Please+sign+out+and+back+in,+then+retry.`);
  }

  logJoinClub("profile-ready", {
    userId: user.id,
    clubId,
  });

  const { error: joinError } = await supabase.from("club_members").insert({
    club_id: clubId,
    user_id: user.id,
    role: "member",
  });

  if (joinError) {
    if (joinError.code === "23505") {
      logJoinClub("duplicate-membership", {
        userId: user.id,
        clubId,
      });
      redirect(`/join?code=${encodeURIComponent(normalizedJoinCode)}&clubId=${clubId}&error=You+are+already+a+member+of+this+club.`);
    }

    logJoinClub("membership-insert-error", {
      userId: user.id,
      clubId,
      code: joinError.code,
      message: joinError.message,
      details: joinError.details,
    });
    redirect(`/join?code=${encodeURIComponent(normalizedJoinCode)}&error=Membership+insert+failed.+Please+retry.`);
  }

  logJoinClub("success", {
    userId: user.id,
    clubId,
  });

  revalidatePath("/dashboard");
  revalidatePath("/clubs");
  revalidatePath(`/clubs/${clubId}`);
  redirect(`/join?code=${encodeURIComponent(normalizedJoinCode)}&clubId=${clubId}&success=You+joined+the+club.`);
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

export async function toggleAttendanceAction(formData: FormData) {
  const parsed = attendanceToggleSchema.safeParse({
    clubId: formData.get("club_id"),
    eventId: formData.get("event_id"),
    userId: formData.get("user_id"),
    present: formData.get("present"),
  });

  if (!parsed.success) {
    const fallbackClubId = typeof formData.get("club_id") === "string" ? formData.get("club_id") : "";
    if (fallbackClubId) {
      redirect(`/clubs/${fallbackClubId}?attendanceError=${encodeURIComponent(getSafeValidationErrorMessage(parsed))}`);
    }
    redirect("/clubs?error=Invalid+attendance+request.");
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    redirect("/login");
  }

  logAttendance("start", {
    submittedClubId: parsed.data.clubId,
    submittedEventId: parsed.data.eventId,
    submittedUserId: parsed.data.userId,
    present: parsed.data.present,
    currentUserId: user.id,
  });

  const { error: currentProfileError } = await upsertCurrentUserProfile(supabase, user);
  if (currentProfileError) {
    logAttendance("current-profile-error", {
      currentUserId: user.id,
      code: currentProfileError.code,
      message: currentProfileError.message,
      details: currentProfileError.details,
    });
    redirect(`/clubs/${parsed.data.clubId}?attendanceError=Could+not+prepare+your+profile.+Please+retry.`);
  }

  const rateLimit = await enforceRateLimit({
    policy: "rsvpWrite",
    userId: user.id,
  });
  if (!rateLimit.success) {
    redirect(`/clubs/${parsed.data.clubId}?attendanceError=${encodeURIComponent(getRateLimitErrorMessage())}`);
  }

  const { data: membership, error: membershipError } = await supabase
    .from("club_members")
    .select("role")
    .eq("club_id", parsed.data.clubId)
    .eq("user_id", user.id)
    .maybeSingle();

  if (membershipError || !membership) {
    logAttendance("membership-check-failed", {
      currentUserId: user.id,
      clubId: parsed.data.clubId,
      code: membershipError?.code,
      message: membershipError?.message,
      details: membershipError?.details,
      foundMembership: Boolean(membership),
    });
    redirect(`/clubs/${parsed.data.clubId}?attendanceError=You+do+not+have+access+to+this+club.`);
  }

  if (membership.role !== "officer") {
    logAttendance("not-officer", {
      currentUserId: user.id,
      clubId: parsed.data.clubId,
      role: membership.role,
    });
    redirect(`/clubs/${parsed.data.clubId}?attendanceError=Only+officers+can+track+attendance.`);
  }

  logAttendance("membership-check-passed", {
    currentUserId: user.id,
    clubId: parsed.data.clubId,
    role: membership.role,
  });

  const { data: eventRow, error: eventError } = await supabase
    .from("events")
    .select("id, club_id")
    .eq("id", parsed.data.eventId)
    .maybeSingle();

  if (eventError || !eventRow || eventRow.club_id !== parsed.data.clubId) {
    logAttendance("event-check-failed", {
      currentUserId: user.id,
      clubId: parsed.data.clubId,
      eventId: parsed.data.eventId,
      code: eventError?.code,
      message: eventError?.message,
      details: eventError?.details,
      foundEvent: Boolean(eventRow),
      eventClubId: eventRow?.club_id,
    });
    redirect(`/clubs/${parsed.data.clubId}?attendanceError=Event+not+found+for+this+club.`);
  }

  logAttendance("event-check-passed", {
    currentUserId: user.id,
    clubId: parsed.data.clubId,
    eventId: parsed.data.eventId,
  });

  const { data: targetMember, error: targetMemberError } = await supabase
    .from("club_members")
    .select("id")
    .eq("club_id", parsed.data.clubId)
    .eq("user_id", parsed.data.userId)
    .maybeSingle();

  if (targetMemberError || !targetMember) {
    logAttendance("target-member-check-failed", {
      currentUserId: user.id,
      clubId: parsed.data.clubId,
      targetUserId: parsed.data.userId,
      code: targetMemberError?.code,
      message: targetMemberError?.message,
      details: targetMemberError?.details,
      foundTargetMember: Boolean(targetMember),
    });
    redirect(`/clubs/${parsed.data.clubId}?attendanceError=Member+not+found+in+this+club.`);
  }

  logAttendance("target-member-check-passed", {
    currentUserId: user.id,
    clubId: parsed.data.clubId,
    targetUserId: parsed.data.userId,
  });

  if (parsed.data.present) {
    const admin = createAdminClient();

    const { data: targetProfile } = await admin
      .from("profiles")
      .select("id")
      .eq("id", parsed.data.userId)
      .maybeSingle();

    if (!targetProfile) {
      const { data: authUser, error: authUserError } = await admin.auth.admin.getUserById(parsed.data.userId);

      logAttendance("target-profile-missing", {
        currentUserId: user.id,
        clubId: parsed.data.clubId,
        eventId: parsed.data.eventId,
        targetUserId: parsed.data.userId,
        authLookupError: authUserError?.message ?? null,
        authUserFound: Boolean(authUser?.user),
      });

      if (authUser?.user) {
        const { error: targetProfileError } = await admin.from("profiles").upsert(
          {
            id: authUser.user.id,
            email: authUser.user.email ?? "",
            full_name:
              typeof authUser.user.user_metadata?.full_name === "string"
                ? sanitizeInlineText(authUser.user.user_metadata.full_name).slice(0, 80)
                : "",
          },
          { onConflict: "id" },
        );

        if (targetProfileError) {
          logAttendance("target-profile-upsert-error", {
            currentUserId: user.id,
            targetUserId: parsed.data.userId,
            code: targetProfileError.code,
            message: targetProfileError.message,
            details: targetProfileError.details,
          });
          redirect(`/clubs/${parsed.data.clubId}?attendanceError=This+member+profile+is+missing.+Have+them+sign+in+again,+then+retry.`);
        }
      } else {
        redirect(`/clubs/${parsed.data.clubId}?attendanceError=This+member+profile+is+missing.+Have+them+sign+in+again,+then+retry.`);
      }
    }

    const { data: existingAttendance, error: existingAttendanceError } = await supabase
      .from("event_attendance")
      .select("id")
      .eq("event_id", parsed.data.eventId)
      .eq("user_id", parsed.data.userId)
      .maybeSingle();

    if (existingAttendanceError) {
      logAttendance("existing-attendance-check-error", {
        currentUserId: user.id,
        eventId: parsed.data.eventId,
        targetUserId: parsed.data.userId,
        code: existingAttendanceError.code,
        message: existingAttendanceError.message,
        details: existingAttendanceError.details,
      });
      redirect(`/clubs/${parsed.data.clubId}?attendanceError=${encodeURIComponent(getAttendanceErrorMessage(existingAttendanceError.code, existingAttendanceError.message))}`);
    }

    if (existingAttendance) {
      logAttendance("already-present", {
        currentUserId: user.id,
        eventId: parsed.data.eventId,
        targetUserId: parsed.data.userId,
      });
    } else {
      const { error: attendanceError } = await supabase.from("event_attendance").insert({
        event_id: parsed.data.eventId,
        user_id: parsed.data.userId,
        marked_by: user.id,
      });

      if (attendanceError) {
        logAttendance("insert-error", {
          currentUserId: user.id,
          clubId: parsed.data.clubId,
          eventId: parsed.data.eventId,
          targetUserId: parsed.data.userId,
          code: attendanceError.code,
          message: attendanceError.message,
          details: attendanceError.details,
        });
        redirect(`/clubs/${parsed.data.clubId}?attendanceError=${encodeURIComponent(getAttendanceErrorMessage(attendanceError.code, attendanceError.message))}`);
      }

      logAttendance("insert-success", {
        currentUserId: user.id,
        clubId: parsed.data.clubId,
        eventId: parsed.data.eventId,
        targetUserId: parsed.data.userId,
      });
    }
  } else {
    const { error: attendanceError } = await supabase
      .from("event_attendance")
      .delete()
      .eq("event_id", parsed.data.eventId)
      .eq("user_id", parsed.data.userId);

    if (attendanceError) {
      logAttendance("delete-error", {
        currentUserId: user.id,
        clubId: parsed.data.clubId,
        eventId: parsed.data.eventId,
        targetUserId: parsed.data.userId,
        code: attendanceError.code,
        message: attendanceError.message,
        details: attendanceError.details,
      });
      redirect(`/clubs/${parsed.data.clubId}?attendanceError=${encodeURIComponent(getAttendanceErrorMessage(attendanceError.code, attendanceError.message))}`);
    }

    logAttendance("delete-success", {
      currentUserId: user.id,
      clubId: parsed.data.clubId,
      eventId: parsed.data.eventId,
      targetUserId: parsed.data.userId,
    });
  }

  revalidatePath(`/clubs/${parsed.data.clubId}`);
  redirect(`/clubs/${parsed.data.clubId}?attendanceSuccess=Attendance+updated.`);
}
