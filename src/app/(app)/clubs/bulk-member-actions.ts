"use server";

import { revalidatePath } from "next/cache";
import { assertClubActiveForMutations } from "@/lib/clubs/club-status";
import { isViewerActiveLegacyOfficer } from "@/lib/clubs/member-management-access";
import { getMemberManagementErrorMessage } from "@/lib/clubs/member-management-messages";
import { hasPermission } from "@/lib/rbac/permissions";
import { createClient } from "@/lib/supabase/server";
import {
  bulkMarkAlumniSchema,
  bulkMemberCommitteeMutationSchema,
  bulkMemberTagMutationSchema,
  bulkMemberTeamMutationSchema,
  bulkRemoveMembersSchema,
} from "@/lib/validation/clubs";

export type BulkMutationResult =
  | { ok: true; applied: number; skipped: number; notes: string[] }
  | { ok: false; error: string };

const MAX_NOTES = 5;

function pushNote(notes: string[], msg: string) {
  if (notes.length >= MAX_NOTES) return;
  if (!notes.includes(msg)) notes.push(msg);
}

function dedupeIds(ids: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const id of ids) {
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(id);
  }
  return out;
}

/** Unique selected IDs excluding the actor (matches server-side filtering). */
function selectionRelevantCount(userIds: string[], actorId: string): number {
  return dedupeIds(userIds).filter((id) => id !== actorId).length;
}

async function assertCanManageTags(userId: string, clubId: string): Promise<BulkMutationResult | null> {
  const supabase = await createClient();
  if (await hasPermission(userId, clubId, "members.manage_tags")) return null;

  const { data: row } = await supabase
    .from("club_members")
    .select("role, membership_status")
    .eq("club_id", clubId)
    .eq("user_id", userId)
    .maybeSingle();

  if (isViewerActiveLegacyOfficer(row ?? null)) return null;
  return { ok: false, error: "You do not have permission to manage member tags." };
}

async function assertCanManageCommittees(userId: string, clubId: string): Promise<BulkMutationResult | null> {
  const supabase = await createClient();
  if (await hasPermission(userId, clubId, "members.manage_committees")) return null;

  const { data: row } = await supabase
    .from("club_members")
    .select("role, membership_status")
    .eq("club_id", clubId)
    .eq("user_id", userId)
    .maybeSingle();

  if (isViewerActiveLegacyOfficer(row ?? null)) return null;
  return { ok: false, error: "You do not have permission to manage committees." };
}

async function assertCanManageTeams(userId: string, clubId: string): Promise<BulkMutationResult | null> {
  const supabase = await createClient();
  if (await hasPermission(userId, clubId, "members.manage_teams")) return null;

  const { data: row } = await supabase
    .from("club_members")
    .select("role, membership_status")
    .eq("club_id", clubId)
    .eq("user_id", userId)
    .maybeSingle();

  if (isViewerActiveLegacyOfficer(row ?? null)) return null;
  return { ok: false, error: "You do not have permission to manage teams." };
}

async function loadActiveMemberTargets(
  supabase: Awaited<ReturnType<typeof createClient>>,
  clubId: string,
  requested: string[],
  actorId: string,
): Promise<string[]> {
  const filtered = dedupeIds(requested).filter((id) => id !== actorId);
  if (filtered.length === 0) return [];

  const { data } = await supabase
    .from("club_members")
    .select("user_id")
    .eq("club_id", clubId)
    .eq("membership_status", "active")
    .in("user_id", filtered);

  const eligible = new Set((data ?? []).map((r) => r.user_id as string));
  return filtered.filter((id) => eligible.has(id));
}

async function loadAnyMemberTargets(
  supabase: Awaited<ReturnType<typeof createClient>>,
  clubId: string,
  requested: string[],
  actorId: string,
): Promise<string[]> {
  const filtered = dedupeIds(requested).filter((id) => id !== actorId);
  if (filtered.length === 0) return [];

  const { data } = await supabase
    .from("club_members")
    .select("user_id")
    .eq("club_id", clubId)
    .in("user_id", filtered);

  const eligible = new Set((data ?? []).map((r) => r.user_id as string));
  return filtered.filter((id) => eligible.has(id));
}

function revalidateMemberSurfaces(clubId: string) {
  revalidatePath(`/clubs/${clubId}/members`);
  revalidatePath(`/clubs/${clubId}`);
  revalidatePath("/clubs");
  revalidatePath("/dashboard");
}

export async function bulkAssignMemberTagAction(input: unknown): Promise<BulkMutationResult> {
  const parsed = bulkMemberTagMutationSchema.safeParse(input);
  if (!parsed.success) {
    return { ok: false, error: parsed.error.issues[0]?.message ?? "Invalid request." };
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return { ok: false, error: "You must be signed in." };

  const active = await assertClubActiveForMutations(parsed.data.clubId);
  if (!active.ok) return { ok: false, error: active.message };

  const gate = await assertCanManageTags(user.id, parsed.data.clubId);
  if (gate) return gate;

  const { data: tag } = await supabase
    .from("club_member_tags")
    .select("id")
    .eq("id", parsed.data.tagId)
    .eq("club_id", parsed.data.clubId)
    .maybeSingle();

  if (!tag) return { ok: false, error: "Tag not found." };

  const requested = parsed.data.userIds;
  const targets = await loadActiveMemberTargets(supabase, parsed.data.clubId, requested, user.id);
  const notes: string[] = [];
  const requestedRelevantCount = selectionRelevantCount(parsed.data.userIds, user.id);

  let applied = 0;
  for (const userId of targets) {
    const { error } = await supabase.from("club_member_tag_assignments").insert({
      tag_id: parsed.data.tagId,
      user_id: userId,
      assigned_by: user.id,
    });
    if (error) {
      if (error.code === "23505") {
        /* already assigned */
      } else if (error.message?.includes("User must be a member")) {
        pushNote(notes, "Some members could not receive tags (membership check).");
      } else {
        pushNote(notes, "Some tag assignments could not be saved.");
      }
    } else {
      applied++;
    }
  }

  if (applied > 0) revalidateMemberSurfaces(parsed.data.clubId);
  return {
    ok: true,
    applied,
    skipped: Math.max(0, requestedRelevantCount - applied),
    notes,
  };
}

export async function bulkRemoveMemberTagAction(input: unknown): Promise<BulkMutationResult> {
  const parsed = bulkMemberTagMutationSchema.safeParse(input);
  if (!parsed.success) {
    return { ok: false, error: parsed.error.issues[0]?.message ?? "Invalid request." };
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return { ok: false, error: "You must be signed in." };

  const active = await assertClubActiveForMutations(parsed.data.clubId);
  if (!active.ok) return { ok: false, error: active.message };

  const gate = await assertCanManageTags(user.id, parsed.data.clubId);
  if (gate) return gate;

  const { data: tag } = await supabase
    .from("club_member_tags")
    .select("id")
    .eq("id", parsed.data.tagId)
    .eq("club_id", parsed.data.clubId)
    .maybeSingle();

  if (!tag) return { ok: false, error: "Tag not found." };

  const requested = parsed.data.userIds;
  const targets = await loadAnyMemberTargets(supabase, parsed.data.clubId, requested, user.id);
  const notes: string[] = [];
  const requestedRelevantCount = selectionRelevantCount(parsed.data.userIds, user.id);

  let applied = 0;
  for (const userId of targets) {
    const { data: removed, error } = await supabase
      .from("club_member_tag_assignments")
      .delete()
      .eq("tag_id", parsed.data.tagId)
      .eq("user_id", userId)
      .select("user_id");

    if (error) {
      pushNote(notes, "Some tags could not be removed.");
    } else if (removed && removed.length > 0) {
      applied++;
    }
  }

  if (applied > 0) revalidateMemberSurfaces(parsed.data.clubId);
  return {
    ok: true,
    applied,
    skipped: Math.max(0, requestedRelevantCount - applied),
    notes,
  };
}

export async function bulkAssignCommitteeMembersAction(input: unknown): Promise<BulkMutationResult> {
  const parsed = bulkMemberCommitteeMutationSchema.safeParse(input);
  if (!parsed.success) {
    return { ok: false, error: parsed.error.issues[0]?.message ?? "Invalid request." };
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return { ok: false, error: "You must be signed in." };

  const active = await assertClubActiveForMutations(parsed.data.clubId);
  if (!active.ok) return { ok: false, error: active.message };

  const gate = await assertCanManageCommittees(user.id, parsed.data.clubId);
  if (gate) return gate;

  const { data: committee } = await supabase
    .from("club_committees")
    .select("id")
    .eq("id", parsed.data.committeeId)
    .eq("club_id", parsed.data.clubId)
    .maybeSingle();

  if (!committee) return { ok: false, error: "Committee not found." };

  const requested = parsed.data.userIds;
  const targets = await loadActiveMemberTargets(supabase, parsed.data.clubId, requested, user.id);
  const notes: string[] = [];
  const requestedRelevantCount = selectionRelevantCount(parsed.data.userIds, user.id);

  let applied = 0;
  for (const userId of targets) {
    const { error } = await supabase.from("club_committee_members").insert({
      committee_id: parsed.data.committeeId,
      user_id: userId,
      added_by: user.id,
    });
    if (error) {
      if (error.code === "23505") {
        /* already on committee */
      } else if (error.message?.includes("User must be a member")) {
        pushNote(notes, "Some members could not be assigned (membership check).");
      } else {
        pushNote(notes, "Some committee assignments could not be saved.");
      }
    } else {
      applied++;
    }
  }

  if (applied > 0) revalidateMemberSurfaces(parsed.data.clubId);
  return {
    ok: true,
    applied,
    skipped: Math.max(0, requestedRelevantCount - applied),
    notes,
  };
}

export async function bulkRemoveCommitteeMembersAction(input: unknown): Promise<BulkMutationResult> {
  const parsed = bulkMemberCommitteeMutationSchema.safeParse(input);
  if (!parsed.success) {
    return { ok: false, error: parsed.error.issues[0]?.message ?? "Invalid request." };
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return { ok: false, error: "You must be signed in." };

  const active = await assertClubActiveForMutations(parsed.data.clubId);
  if (!active.ok) return { ok: false, error: active.message };

  const gate = await assertCanManageCommittees(user.id, parsed.data.clubId);
  if (gate) return gate;

  const { data: committee } = await supabase
    .from("club_committees")
    .select("id")
    .eq("id", parsed.data.committeeId)
    .eq("club_id", parsed.data.clubId)
    .maybeSingle();

  if (!committee) return { ok: false, error: "Committee not found." };

  const requested = parsed.data.userIds;
  const targets = await loadAnyMemberTargets(supabase, parsed.data.clubId, requested, user.id);
  const notes: string[] = [];
  const requestedRelevantCount = selectionRelevantCount(parsed.data.userIds, user.id);

  let applied = 0;
  for (const userId of targets) {
    const { data: removed, error } = await supabase
      .from("club_committee_members")
      .delete()
      .eq("committee_id", parsed.data.committeeId)
      .eq("user_id", userId)
      .select("user_id");

    if (error) {
      pushNote(notes, "Some committee removals could not be saved.");
    } else if (removed && removed.length > 0) {
      applied++;
    }
  }

  if (applied > 0) revalidateMemberSurfaces(parsed.data.clubId);
  return {
    ok: true,
    applied,
    skipped: Math.max(0, requestedRelevantCount - applied),
    notes,
  };
}

export async function bulkAssignTeamMembersAction(input: unknown): Promise<BulkMutationResult> {
  const parsed = bulkMemberTeamMutationSchema.safeParse(input);
  if (!parsed.success) {
    return { ok: false, error: parsed.error.issues[0]?.message ?? "Invalid request." };
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return { ok: false, error: "You must be signed in." };

  const active = await assertClubActiveForMutations(parsed.data.clubId);
  if (!active.ok) return { ok: false, error: active.message };

  const gate = await assertCanManageTeams(user.id, parsed.data.clubId);
  if (gate) return gate;

  const { data: team } = await supabase
    .from("club_teams")
    .select("id")
    .eq("id", parsed.data.teamId)
    .eq("club_id", parsed.data.clubId)
    .maybeSingle();

  if (!team) return { ok: false, error: "Team not found." };

  const requested = parsed.data.userIds;
  const targets = await loadActiveMemberTargets(supabase, parsed.data.clubId, requested, user.id);
  const notes: string[] = [];
  const requestedRelevantCount = selectionRelevantCount(parsed.data.userIds, user.id);

  let applied = 0;
  for (const userId of targets) {
    const { error } = await supabase.from("club_team_members").insert({
      team_id: parsed.data.teamId,
      user_id: userId,
      added_by: user.id,
    });
    if (error) {
      if (error.code === "23505") {
        /* already on team */
      } else if (error.message?.includes("User must be a member")) {
        pushNote(notes, "Some members could not be assigned (membership check).");
      } else {
        pushNote(notes, "Some team assignments could not be saved.");
      }
    } else {
      applied++;
    }
  }

  if (applied > 0) revalidateMemberSurfaces(parsed.data.clubId);
  return {
    ok: true,
    applied,
    skipped: Math.max(0, requestedRelevantCount - applied),
    notes,
  };
}

export async function bulkRemoveTeamMembersAction(input: unknown): Promise<BulkMutationResult> {
  const parsed = bulkMemberTeamMutationSchema.safeParse(input);
  if (!parsed.success) {
    return { ok: false, error: parsed.error.issues[0]?.message ?? "Invalid request." };
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return { ok: false, error: "You must be signed in." };

  const active = await assertClubActiveForMutations(parsed.data.clubId);
  if (!active.ok) return { ok: false, error: active.message };

  const gate = await assertCanManageTeams(user.id, parsed.data.clubId);
  if (gate) return gate;

  const { data: team } = await supabase
    .from("club_teams")
    .select("id")
    .eq("id", parsed.data.teamId)
    .eq("club_id", parsed.data.clubId)
    .maybeSingle();

  if (!team) return { ok: false, error: "Team not found." };

  const requested = parsed.data.userIds;
  const targets = await loadAnyMemberTargets(supabase, parsed.data.clubId, requested, user.id);
  const notes: string[] = [];
  const requestedRelevantCount = selectionRelevantCount(parsed.data.userIds, user.id);

  let applied = 0;
  for (const userId of targets) {
    const { data: removed, error } = await supabase
      .from("club_team_members")
      .delete()
      .eq("team_id", parsed.data.teamId)
      .eq("user_id", userId)
      .select("user_id");

    if (error) {
      pushNote(notes, "Some team removals could not be saved.");
    } else if (removed && removed.length > 0) {
      applied++;
    }
  }

  if (applied > 0) revalidateMemberSurfaces(parsed.data.clubId);
  return {
    ok: true,
    applied,
    skipped: Math.max(0, requestedRelevantCount - applied),
    notes,
  };
}

export async function bulkMarkMembersAlumniAction(input: unknown): Promise<BulkMutationResult> {
  const parsed = bulkMarkAlumniSchema.safeParse(input);
  if (!parsed.success) {
    return { ok: false, error: parsed.error.issues[0]?.message ?? "Invalid request." };
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return { ok: false, error: "You must be signed in." };

  const active = await assertClubActiveForMutations(parsed.data.clubId);
  if (!active.ok) return { ok: false, error: active.message };

  const canMark = await hasPermission(user.id, parsed.data.clubId, "members.remove");
  if (!canMark) {
    return { ok: false, error: "You do not have permission to update membership status." };
  }

  const requested = parsed.data.userIds;
  const targets = await loadActiveMemberTargets(supabase, parsed.data.clubId, requested, user.id);
  const notes: string[] = [];
  const requestedRelevantCount = selectionRelevantCount(parsed.data.userIds, user.id);

  let applied = 0;
  for (const userId of targets) {
    const { data: status, error } = await supabase.rpc("set_club_membership_alumni", {
      p_club_id: parsed.data.clubId,
      p_target_user_id: userId,
    });

    if (error || status !== "ok") {
      const code = typeof status === "string" ? status : "unknown";
      pushNote(notes, getMemberManagementErrorMessage(code));
    } else {
      applied++;
    }
  }

  if (applied > 0) {
    revalidateMemberSurfaces(parsed.data.clubId);
    revalidatePath(`/clubs/${parsed.data.clubId}/settings`);
  }
  return {
    ok: true,
    applied,
    skipped: Math.max(0, requestedRelevantCount - applied),
    notes,
  };
}

export async function bulkRemoveMembersAction(input: unknown): Promise<BulkMutationResult> {
  const parsed = bulkRemoveMembersSchema.safeParse(input);
  if (!parsed.success) {
    return { ok: false, error: parsed.error.issues[0]?.message ?? "Invalid request." };
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return { ok: false, error: "You must be signed in." };

  const active = await assertClubActiveForMutations(parsed.data.clubId);
  if (!active.ok) return { ok: false, error: active.message };

  const canRemove = await hasPermission(user.id, parsed.data.clubId, "members.remove");
  if (!canRemove) {
    return { ok: false, error: "You do not have permission to remove members." };
  }

  const { data: clubRow } = await supabase.from("clubs").select("name").eq("id", parsed.data.clubId).maybeSingle();
  if (!clubRow?.name) return { ok: false, error: "Club not found." };

  const expected = clubRow.name.trim().toLowerCase();
  const got = parsed.data.confirmationClubName.trim().toLowerCase();
  if (expected !== got) {
    return { ok: false, error: "Club name does not match — type the exact club name to confirm removal." };
  }

  const requested = parsed.data.userIds;
  const targets = await loadAnyMemberTargets(supabase, parsed.data.clubId, requested, user.id);
  const notes: string[] = [];
  const requestedRelevantCount = selectionRelevantCount(parsed.data.userIds, user.id);

  let applied = 0;
  for (const userId of targets) {
    const { data: status, error } = await supabase.rpc("remove_club_member", {
      target_club_id: parsed.data.clubId,
      target_user_id: userId,
    });

    if (error || status !== "ok") {
      const code = typeof status === "string" ? status : "unknown";
      pushNote(notes, getMemberManagementErrorMessage(code));
    } else {
      applied++;
    }
  }

  if (applied > 0) revalidateMemberSurfaces(parsed.data.clubId);
  return {
    ok: true,
    applied,
    skipped: Math.max(0, requestedRelevantCount - applied),
    notes,
  };
}
