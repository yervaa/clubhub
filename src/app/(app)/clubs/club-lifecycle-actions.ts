"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import { hasPermission } from "@/lib/rbac/permissions";
import { logAuditEvent } from "@/lib/rbac/audit";
import { assertClubActiveForMutations } from "@/lib/clubs/club-status";
import {
  archiveClubSchema,
  clubAdvisorApprovalPolicySchema,
  clubJoinPolicySchema,
  deleteClubSchema,
  leaveClubSchema,
} from "@/lib/validation/clubs";

function clubSettingsUrl(clubId: string, params?: Record<string, string>) {
  const base = `/clubs/${clubId}/settings/club`;
  if (!params) return base;
  return `${base}?${new URLSearchParams(params).toString()}`;
}

function firstIssue(result: { error: { issues: Array<{ message: string }> } }) {
  return result.error.issues[0]?.message ?? "Invalid request.";
}

export async function leaveClubAction(formData: FormData) {
  const parsed = leaveClubSchema.safeParse({
    clubId: formData.get("club_id"),
  });

  if (!parsed.success) {
    const clubId = String(formData.get("club_id") ?? "");
    redirect(clubSettingsUrl(clubId, { error: firstIssue(parsed) }));
  }

  const { clubId } = parsed.data;

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const { data: status, error: rpcError } = await supabase.rpc("leave_club_self", {
    p_club_id: clubId,
  });

  if (rpcError) {
    redirect(clubSettingsUrl(clubId, { error: encodeURIComponent(rpcError.message) }));
  }

  if (status === "last_president_active") {
    redirect(
      clubSettingsUrl(clubId, {
        error: encodeURIComponent(
          "An active club must keep at least one President. Add another President, transfer the role, archive the club, or delete it.",
        ),
      }),
    );
  }

  if (status !== "ok") {
    const message =
      status === "not_member"
        ? "You are not a member of this club."
        : status === "not_authenticated"
          ? "You must be signed in."
          : status === "not_found"
            ? "Club not found."
            : "Unable to leave this club.";
    redirect(clubSettingsUrl(clubId, { error: encodeURIComponent(message) }));
  }

  revalidatePath("/dashboard");
  revalidatePath("/clubs");
  revalidatePath(`/clubs/${clubId}`);
  redirect("/dashboard?success=" + encodeURIComponent("You left the club."));
}

export async function archiveClubAction(formData: FormData) {
  const parsed = archiveClubSchema.safeParse({
    clubId: formData.get("club_id"),
  });

  if (!parsed.success) {
    const clubId = String(formData.get("club_id") ?? "");
    redirect(clubSettingsUrl(clubId, { error: firstIssue(parsed) }));
  }

  const { clubId } = parsed.data;

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const canArchive = await hasPermission(user.id, clubId, "club.archive");
  if (!canArchive) {
    redirect(clubSettingsUrl(clubId, { error: encodeURIComponent("Only Presidents can archive a club.") }));
  }

  const { data: status, error: rpcError } = await supabase.rpc("archive_club", {
    p_club_id: clubId,
  });

  if (rpcError) {
    redirect(clubSettingsUrl(clubId, { error: encodeURIComponent(rpcError.message) }));
  }

  if (status === "permission_denied") {
    redirect(clubSettingsUrl(clubId, { error: encodeURIComponent("You do not have permission to archive this club.") }));
  }

  if (status === "not_active") {
    redirect(clubSettingsUrl(clubId, { error: encodeURIComponent("This club is already archived.") }));
  }

  if (status !== "ok") {
    redirect(clubSettingsUrl(clubId, { error: encodeURIComponent("Unable to archive this club.") }));
  }

  await logAuditEvent({
    clubId,
    actorId: user.id,
    action: "club.archived",
  });

  revalidatePath("/dashboard");
  revalidatePath("/clubs");
  revalidatePath(`/clubs/${clubId}`);

  redirect(clubSettingsUrl(clubId, { success: encodeURIComponent("Club archived. It no longer appears in active lists.") }));
}

export async function deleteClubAction(formData: FormData) {
  const parsed = deleteClubSchema.safeParse({
    clubId: formData.get("club_id"),
    confirmName: formData.get("confirm_name"),
  });

  if (!parsed.success) {
    const clubId = String(formData.get("club_id") ?? "");
    redirect(clubSettingsUrl(clubId, { error: firstIssue(parsed) }));
  }

  const { clubId, confirmName } = parsed.data;

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const canDelete = await hasPermission(user.id, clubId, "club.delete");
  if (!canDelete) {
    redirect(clubSettingsUrl(clubId, { error: encodeURIComponent("Only Presidents can delete a club.") }));
  }

  const { data: clubRow, error: clubErr } = await supabase.from("clubs").select("name").eq("id", clubId).maybeSingle();

  if (clubErr || !clubRow) {
    redirect(clubSettingsUrl(clubId, { error: encodeURIComponent("Club not found.") }));
  }

  if (confirmName.trim() !== clubRow.name.trim()) {
    redirect(clubSettingsUrl(clubId, { error: encodeURIComponent("The name you typed does not match this club.") }));
  }

  const { data: status, error: rpcError } = await supabase.rpc("delete_club_cascade", {
    p_club_id: clubId,
  });

  if (rpcError) {
    redirect(clubSettingsUrl(clubId, { error: encodeURIComponent(rpcError.message) }));
  }

  if (status === "permission_denied") {
    redirect(clubSettingsUrl(clubId, { error: encodeURIComponent("You do not have permission to delete this club.") }));
  }

  if (status !== "ok") {
    redirect(clubSettingsUrl(clubId, { error: encodeURIComponent("Unable to delete this club.") }));
  }

  revalidatePath("/dashboard");
  revalidatePath("/clubs");

  redirect("/dashboard?success=" + encodeURIComponent("The club was permanently deleted."));
}

export async function updateClubJoinPolicyAction(formData: FormData) {
  const parsed = clubJoinPolicySchema.safeParse({
    clubId: formData.get("club_id"),
    requireJoinApproval: formData.get("require_join_approval"),
  });

  if (!parsed.success) {
    const clubId = String(formData.get("club_id") ?? "");
    redirect(clubSettingsUrl(clubId, { error: firstIssue(parsed) }));
  }

  const { clubId, requireJoinApproval } = parsed.data;
  const enabled = requireJoinApproval === "true";

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const canManageSettings = await hasPermission(user.id, clubId, "club.manage_settings");
  const { data: policyMembership } = await supabase
    .from("club_members")
    .select("role")
    .eq("club_id", clubId)
    .eq("user_id", user.id)
    .maybeSingle();
  const isLegacyOfficer = policyMembership?.role === "officer";
  if (!canManageSettings && !isLegacyOfficer) {
    redirect(
      clubSettingsUrl(clubId, {
        error: encodeURIComponent("You do not have permission to change club settings."),
      }),
    );
  }

  const active = await assertClubActiveForMutations(clubId);
  if (!active.ok) {
    redirect(clubSettingsUrl(clubId, { error: encodeURIComponent(active.message) }));
  }

  const { error } = await supabase
    .from("clubs")
    .update({ require_join_approval: enabled })
    .eq("id", clubId);

  if (error) {
    redirect(clubSettingsUrl(clubId, { error: encodeURIComponent("Could not update join policy. Please retry.") }));
  }

  revalidatePath(`/clubs/${clubId}`);
  revalidatePath(`/clubs/${clubId}/members`);
  revalidatePath("/join");
  revalidatePath("/clubs/join");
  redirect(
    clubSettingsUrl(clubId, {
      success: encodeURIComponent(
        enabled
          ? "New members will need approval before they can join."
          : "Join codes now add members immediately again.",
      ),
    }),
  );
}

export async function updateClubAdvisorApprovalPolicyAction(formData: FormData) {
  const parsed = clubAdvisorApprovalPolicySchema.safeParse({
    clubId: formData.get("club_id"),
    requireEventApproval: formData.get("require_event_approval"),
    requireAnnouncementApproval: formData.get("require_announcement_approval"),
  });

  if (!parsed.success) {
    const clubId = String(formData.get("club_id") ?? "");
    redirect(clubSettingsUrl(clubId, { error: firstIssue(parsed) }));
  }

  const { clubId, requireEventApproval, requireAnnouncementApproval } = parsed.data;
  const requireEvents = requireEventApproval === "true";
  const requireAnnouncements = requireAnnouncementApproval === "true";

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const canManageSettings = await hasPermission(user.id, clubId, "club.manage_settings");
  const { data: policyMembership } = await supabase
    .from("club_members")
    .select("role")
    .eq("club_id", clubId)
    .eq("user_id", user.id)
    .maybeSingle();
  const isLegacyOfficer = policyMembership?.role === "officer";
  if (!canManageSettings && !isLegacyOfficer) {
    redirect(
      clubSettingsUrl(clubId, {
        error: encodeURIComponent("You do not have permission to change these settings."),
      }),
    );
  }

  const active = await assertClubActiveForMutations(clubId);
  if (!active.ok) {
    redirect(clubSettingsUrl(clubId, { error: encodeURIComponent(active.message) }));
  }

  const { error } = await supabase
    .from("clubs")
    .update({
      require_event_approval: requireEvents,
      require_announcement_approval: requireAnnouncements,
    })
    .eq("id", clubId);

  if (error) {
    redirect(clubSettingsUrl(clubId, { error: encodeURIComponent("Could not update approval settings. Please retry.") }));
  }

  revalidatePath(`/clubs/${clubId}`);
  revalidatePath(`/clubs/${clubId}/advisor`);
  revalidatePath(`/clubs/${clubId}/events`);
  revalidatePath(`/clubs/${clubId}/announcements`);
  redirect(
    clubSettingsUrl(clubId, {
      success: encodeURIComponent("Advisor approval settings saved."),
    }),
  );
}
