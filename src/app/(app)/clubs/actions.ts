"use server";

import { randomBytes, randomUUID } from "crypto";
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { createAdminClient } from "@/lib/supabase/admin";
import { createClient } from "@/lib/supabase/server";

function getStringValue(formData: FormData, key: string) {
  const value = formData.get(key);
  return typeof value === "string" ? value.trim() : "";
}

function generateJoinCode() {
  return randomBytes(4).toString("hex").toUpperCase();
}

export async function createClubAction(formData: FormData) {
  const name = getStringValue(formData, "name");
  const description = getStringValue(formData, "description");

  if (!name || !description) {
    redirect("/clubs/create?error=Please+enter+name+and+description.");
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
      full_name: typeof user.user_metadata?.full_name === "string" ? user.user_metadata.full_name : "",
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
      name,
      description,
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

  const { error: memberError } = await admin.from("club_members").insert({
    club_id: clubId,
    user_id: user.id,
    role: "officer",
  });

  if (memberError) {
    redirect("/clubs/create?error=Club+created+but+membership+failed.+Contact+support.");
  }

  revalidatePath("/dashboard");
  revalidatePath("/clubs");
  redirect("/clubs?success=Club+created+successfully.");
}

export async function joinClubAction(formData: FormData) {
  const inputCode = getStringValue(formData, "join_code").toUpperCase();

  if (!inputCode) {
    redirect("/clubs/join?error=Please+enter+a+join+code.");
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
    .eq("join_code", inputCode)
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

  const { error: joinError } = await supabase.from("club_members").insert({
    club_id: club.id,
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
  const clubId = getStringValue(formData, "club_id");
  const title = getStringValue(formData, "title");
  const content = getStringValue(formData, "content");

  if (!clubId) {
    redirect("/clubs?error=Invalid+club.");
  }

  if (!title || !content) {
    redirect(`/clubs/${clubId}?annError=Please+enter+title+and+content.`);
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
    .eq("club_id", clubId)
    .eq("user_id", user.id)
    .maybeSingle();

  if (membershipError || !membership) {
    redirect(`/clubs/${clubId}?annError=You+do+not+have+access+to+this+club.`);
  }

  if (membership.role !== "officer") {
    redirect(`/clubs/${clubId}?annError=Only+officers+can+create+announcements.`);
  }

  const { error: insertError } = await supabase.from("announcements").insert({
    club_id: clubId,
    title,
    content,
    created_by: user.id,
  });

  if (insertError) {
    redirect(`/clubs/${clubId}?annError=Unable+to+create+announcement.+Please+retry.`);
  }

  revalidatePath(`/clubs/${clubId}`);
  redirect(`/clubs/${clubId}?annSuccess=Announcement+posted.`);
}

export async function createEventAction(formData: FormData) {
  const clubId = getStringValue(formData, "club_id");
  const title = getStringValue(formData, "title");
  const description = getStringValue(formData, "description");
  const location = getStringValue(formData, "location");
  const eventDateRaw = getStringValue(formData, "event_date");

  if (!clubId) {
    redirect("/clubs?error=Invalid+club.");
  }

  if (!title || !description || !location || !eventDateRaw) {
    redirect(`/clubs/${clubId}?eventError=Please+fill+all+event+fields.`);
  }

  const eventDate = new Date(eventDateRaw);
  if (Number.isNaN(eventDate.getTime())) {
    redirect(`/clubs/${clubId}?eventError=Please+enter+a+valid+event+date.`);
  }

  if (eventDate.getTime() < Date.now()) {
    redirect(`/clubs/${clubId}?eventError=Event+date+must+be+in+the+future.`);
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
    .eq("club_id", clubId)
    .eq("user_id", user.id)
    .maybeSingle();

  if (membershipError || !membership) {
    redirect(`/clubs/${clubId}?eventError=You+do+not+have+access+to+this+club.`);
  }

  if (membership.role !== "officer") {
    redirect(`/clubs/${clubId}?eventError=Only+officers+can+create+events.`);
  }

  const { error: insertError } = await supabase.from("events").insert({
    club_id: clubId,
    title,
    description,
    location,
    event_date: eventDate.toISOString(),
    created_by: user.id,
  });

  if (insertError) {
    redirect(`/clubs/${clubId}?eventError=Unable+to+create+event.+Please+retry.`);
  }

  revalidatePath(`/clubs/${clubId}`);
  redirect(`/clubs/${clubId}?eventSuccess=Event+created.`);
}

export async function upsertRsvpAction(formData: FormData) {
  const clubId = getStringValue(formData, "club_id");
  const eventId = getStringValue(formData, "event_id");
  const status = getStringValue(formData, "status") as "yes" | "no" | "maybe";

  if (!clubId || !eventId) {
    redirect("/clubs?error=Invalid+event+request.");
  }

  if (!["yes", "no", "maybe"].includes(status)) {
    redirect(`/clubs/${clubId}?rsvpError=Invalid+RSVP+status.`);
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
    .eq("club_id", clubId)
    .eq("user_id", user.id)
    .maybeSingle();

  if (membershipError || !membership) {
    redirect(`/clubs/${clubId}?rsvpError=You+do+not+have+access+to+this+club+event.`);
  }

  const { data: eventRow, error: eventError } = await supabase
    .from("events")
    .select("id, club_id")
    .eq("id", eventId)
    .maybeSingle();

  if (eventError || !eventRow || eventRow.club_id !== clubId) {
    redirect(`/clubs/${clubId}?rsvpError=Event+not+found+for+this+club.`);
  }

  const { error: upsertError } = await supabase.from("rsvps").upsert(
    {
      event_id: eventId,
      user_id: user.id,
      status,
    },
    { onConflict: "event_id,user_id" },
  );

  if (upsertError) {
    redirect(`/clubs/${clubId}?rsvpError=Unable+to+save+RSVP.+Please+retry.`);
  }

  revalidatePath(`/clubs/${clubId}`);
  redirect(`/clubs/${clubId}?rsvpSuccess=RSVP+saved.`);
}
