"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { createActivityEvent } from "@/lib/activity/create-activity-event";
import { sendAnnouncementMemberBroadcast } from "@/lib/announcements/member-broadcast-notifications";
import { assertClubActiveForMutations } from "@/lib/clubs/club-status";
import { notifyClubMembersOfPublishedEvent } from "@/lib/clubs/event-created-notify";
import { notifyOrganizerApprovalDecision } from "@/lib/clubs/advisor-notify";
import { hasPermission } from "@/lib/rbac/permissions";
import { createAdminClient } from "@/lib/supabase/admin";
import { createClient } from "@/lib/supabase/server";
import { advisorDecisionSchema } from "@/lib/validation/clubs";

function advisorPageUrl(clubId: string, params?: Record<string, string>) {
  const base = `/clubs/${clubId}/advisor`;
  if (!params) return base;
  return `${base}?${new URLSearchParams(params).toString()}`;
}

export async function approveEventAdvisorAction(formData: FormData) {
  const parsed = advisorDecisionSchema.safeParse({
    clubId: formData.get("club_id"),
    entityId: formData.get("event_id"),
    reason: formData.get("reason"),
  });

  if (!parsed.success) {
    const clubId = typeof formData.get("club_id") === "string" ? formData.get("club_id") : "";
    redirect(advisorPageUrl(String(clubId ?? ""), { error: "Invalid+request." }));
  }

  const { clubId, entityId: eventId } = parsed.data;
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const active = await assertClubActiveForMutations(clubId);
  if (!active.ok) {
    redirect(advisorPageUrl(clubId, { error: encodeURIComponent(active.message) }));
  }

  if (!(await hasPermission(user.id, clubId, "events.approve"))) {
    redirect(advisorPageUrl(clubId, { error: encodeURIComponent("You do not have permission to approve events.") }));
  }

  const admin = createAdminClient();
  const { data: row, error: fetchErr } = await admin
    .from("events")
    .select("id, club_id, approval_status, title, location, event_date, created_by, series_id")
    .eq("id", eventId)
    .maybeSingle();

  if (fetchErr || !row || row.club_id !== clubId) {
    redirect(advisorPageUrl(clubId, { error: "Event+not+found." }));
  }

  if (row.approval_status === "approved") {
    revalidatePath(`/clubs/${clubId}`);
    revalidatePath(`/clubs/${clubId}/events`);
    redirect(advisorPageUrl(clubId, { success: encodeURIComponent("Event is already approved.") }));
  }

  if (row.approval_status !== "pending") {
    redirect(advisorPageUrl(clubId, { error: "Only+pending+events+can+be+approved." }));
  }

  let targetIds = [eventId];
  if (row.series_id) {
    const { data: pendingSiblings } = await admin
      .from("events")
      .select("id")
      .eq("club_id", clubId)
      .eq("series_id", row.series_id)
      .eq("approval_status", "pending");
    const ids = (pendingSiblings ?? []).map((r) => r.id);
    if (ids.length > 0) targetIds = ids;
  }

  const nowIso = new Date().toISOString();
  await admin
    .from("events")
    .update({
      approval_status: "approved",
      approved_at: nowIso,
      approved_by: user.id,
      rejection_reason: null,
    })
    .in("id", targetIds);

  const { data: ordered } = await admin
    .from("events")
    .select("id, title, event_date, location, created_by")
    .in("id", targetIds)
    .order("event_date", { ascending: true });

  const primary = ordered?.[0];
  if (!primary) {
    redirect(advisorPageUrl(clubId, { error: "Event+update+failed." }));
  }

  await notifyClubMembersOfPublishedEvent({
    supabase,
    clubId,
    excludeNotifyUserId: primary.created_by,
    eventId: primary.id,
    title: primary.title,
    eventDate: new Date(primary.event_date),
    location: primary.location ?? row.location ?? "",
    occurrenceCount: targetIds.length,
    actorId: user.id,
  });

  await notifyOrganizerApprovalDecision({
    clubId,
    organizerId: row.created_by,
    kind: "event",
    title: row.title,
    approved: true,
    reason: null,
    entityHref: `/clubs/${clubId}/events#event-${primary.id}`,
  });

  revalidatePath(`/clubs/${clubId}`);
  revalidatePath(`/clubs/${clubId}/events`);
  revalidatePath("/dashboard");
  redirect(advisorPageUrl(clubId, { success: encodeURIComponent("Event approved.") }));
}

export async function rejectEventAdvisorAction(formData: FormData) {
  const parsed = advisorDecisionSchema.safeParse({
    clubId: formData.get("club_id"),
    entityId: formData.get("event_id"),
    reason: formData.get("reason"),
  });

  if (!parsed.success) {
    const clubId = typeof formData.get("club_id") === "string" ? formData.get("club_id") : "";
    redirect(advisorPageUrl(String(clubId ?? ""), { error: "Invalid+request." }));
  }

  const { clubId, entityId: eventId, reason } = parsed.data;
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const active = await assertClubActiveForMutations(clubId);
  if (!active.ok) {
    redirect(advisorPageUrl(clubId, { error: encodeURIComponent(active.message) }));
  }

  if (!(await hasPermission(user.id, clubId, "events.approve"))) {
    redirect(advisorPageUrl(clubId, { error: encodeURIComponent("You do not have permission to reject events.") }));
  }

  const admin = createAdminClient();
  const { data: row, error: fetchErr } = await admin
    .from("events")
    .select("id, club_id, approval_status, title, created_by, series_id")
    .eq("id", eventId)
    .maybeSingle();

  if (fetchErr || !row || row.club_id !== clubId) {
    redirect(advisorPageUrl(clubId, { error: "Event+not+found." }));
  }

  if (row.approval_status === "rejected") {
    revalidatePath(`/clubs/${clubId}/events`);
    redirect(advisorPageUrl(clubId, { success: encodeURIComponent("Event is already marked not approved.") }));
  }

  if (row.approval_status !== "pending") {
    redirect(advisorPageUrl(clubId, { error: "Only+pending+events+can+be+rejected." }));
  }

  let targetIds = [eventId];
  if (row.series_id) {
    const { data: pendingSiblings } = await admin
      .from("events")
      .select("id")
      .eq("club_id", clubId)
      .eq("series_id", row.series_id)
      .eq("approval_status", "pending");
    const ids = (pendingSiblings ?? []).map((r) => r.id);
    if (ids.length > 0) targetIds = ids;
  }

  await admin
    .from("events")
    .update({
      approval_status: "rejected",
      rejection_reason: reason,
      approved_at: null,
      approved_by: null,
    })
    .in("id", targetIds);

  await notifyOrganizerApprovalDecision({
    clubId,
    organizerId: row.created_by,
    kind: "event",
    title: row.title,
    approved: false,
    reason,
    entityHref: `/clubs/${clubId}/events#event-${eventId}`,
  });

  revalidatePath(`/clubs/${clubId}`);
  revalidatePath(`/clubs/${clubId}/events`);
  revalidatePath("/dashboard");
  redirect(advisorPageUrl(clubId, { success: encodeURIComponent("Event not approved.") }));
}

export async function approveAnnouncementAdvisorAction(formData: FormData) {
  const parsed = advisorDecisionSchema.safeParse({
    clubId: formData.get("club_id"),
    entityId: formData.get("announcement_id"),
    reason: formData.get("reason"),
  });

  if (!parsed.success) {
    const clubId = typeof formData.get("club_id") === "string" ? formData.get("club_id") : "";
    redirect(advisorPageUrl(String(clubId ?? ""), { error: "Invalid+request." }));
  }

  const { clubId, entityId: announcementId } = parsed.data;
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const active = await assertClubActiveForMutations(clubId);
  if (!active.ok) {
    redirect(advisorPageUrl(clubId, { error: encodeURIComponent(active.message) }));
  }

  if (!(await hasPermission(user.id, clubId, "announcements.approve"))) {
    redirect(
      advisorPageUrl(clubId, { error: encodeURIComponent("You do not have permission to approve announcements.") }),
    );
  }

  const admin = createAdminClient();
  const { data: row, error: fetchErr } = await admin
    .from("announcements")
    .select(
      "id, club_id, approval_status, title, created_by, is_published, scheduled_for, poll_question, is_urgent, member_broadcast_sent_at",
    )
    .eq("id", announcementId)
    .maybeSingle();

  if (fetchErr || !row || row.club_id !== clubId) {
    redirect(advisorPageUrl(clubId, { error: "Announcement+not+found." }));
  }

  if (row.approval_status === "approved") {
    revalidatePath(`/clubs/${clubId}/announcements`);
    redirect(advisorPageUrl(clubId, { success: encodeURIComponent("Announcement is already approved.") }));
  }

  if (row.approval_status !== "pending") {
    redirect(advisorPageUrl(clubId, { error: "Only+pending+announcements+can+be+approved." }));
  }

  const scheduleMs = row.scheduled_for ? new Date(row.scheduled_for).getTime() : null;
  const shouldPublishNow = !scheduleMs || scheduleMs <= Date.now();

  const nowIso = new Date().toISOString();
  await admin
    .from("announcements")
    .update({
      approval_status: "approved",
      approved_at: nowIso,
      approved_by: user.id,
      rejection_reason: null,
      is_published: shouldPublishNow ? true : row.is_published,
    })
    .eq("id", announcementId)
    .eq("club_id", clubId);

  await notifyOrganizerApprovalDecision({
    clubId,
    organizerId: row.created_by,
    kind: "announcement",
    title: row.title,
    approved: true,
    reason: null,
    entityHref: `/clubs/${clubId}/announcements#announcement-${announcementId}`,
  });

  if (shouldPublishNow) {
    const activityEventId = await createActivityEvent({
      type: "announcement.created",
      actorId: user.id,
      clubId,
      entityId: announcementId,
      targetLabel: row.title,
      href: `/clubs/${clubId}/announcements#announcement-${announcementId}`,
      metadata: {
        published_from_pending: true,
        has_poll: Boolean(row.poll_question?.trim()),
        urgent: Boolean(row.is_urgent),
      },
    });

    await sendAnnouncementMemberBroadcast({
      supabase,
      clubId,
      actorId: row.created_by,
      announcementId,
      title: row.title,
      hasPoll: Boolean(row.poll_question?.trim()),
      activityEventId,
      isUrgent: Boolean(row.is_urgent),
    });
  }

  revalidatePath(`/clubs/${clubId}`);
  revalidatePath(`/clubs/${clubId}/announcements`);
  revalidatePath("/dashboard");
  redirect(advisorPageUrl(clubId, { success: encodeURIComponent("Announcement approved.") }));
}

export async function rejectAnnouncementAdvisorAction(formData: FormData) {
  const parsed = advisorDecisionSchema.safeParse({
    clubId: formData.get("club_id"),
    entityId: formData.get("announcement_id"),
    reason: formData.get("reason"),
  });

  if (!parsed.success) {
    const clubId = typeof formData.get("club_id") === "string" ? formData.get("club_id") : "";
    redirect(advisorPageUrl(String(clubId ?? ""), { error: "Invalid+request." }));
  }

  const { clubId, entityId: announcementId, reason } = parsed.data;
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const active = await assertClubActiveForMutations(clubId);
  if (!active.ok) {
    redirect(advisorPageUrl(clubId, { error: encodeURIComponent(active.message) }));
  }

  if (!(await hasPermission(user.id, clubId, "announcements.approve"))) {
    redirect(
      advisorPageUrl(clubId, { error: encodeURIComponent("You do not have permission to reject announcements.") }),
    );
  }

  const admin = createAdminClient();
  const { data: row, error: fetchErr } = await admin
    .from("announcements")
    .select("id, club_id, approval_status, title, created_by")
    .eq("id", announcementId)
    .maybeSingle();

  if (fetchErr || !row || row.club_id !== clubId) {
    redirect(advisorPageUrl(clubId, { error: "Announcement+not+found." }));
  }

  if (row.approval_status === "rejected") {
    redirect(advisorPageUrl(clubId, { success: encodeURIComponent("Announcement is already marked not approved.") }));
  }

  if (row.approval_status !== "pending") {
    redirect(advisorPageUrl(clubId, { error: "Only+pending+announcements+can+be+rejected." }));
  }

  await admin
    .from("announcements")
    .update({
      approval_status: "rejected",
      rejection_reason: reason,
      is_published: false,
      approved_at: null,
      approved_by: null,
    })
    .eq("id", announcementId)
    .eq("club_id", clubId);

  await notifyOrganizerApprovalDecision({
    clubId,
    organizerId: row.created_by,
    kind: "announcement",
    title: row.title,
    approved: false,
    reason,
    entityHref: `/clubs/${clubId}/announcements#announcement-${announcementId}`,
  });

  revalidatePath(`/clubs/${clubId}`);
  revalidatePath(`/clubs/${clubId}/announcements`);
  revalidatePath("/dashboard");
  redirect(advisorPageUrl(clubId, { success: encodeURIComponent("Announcement not approved.") }));
}
