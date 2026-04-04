"use server";

import { redirect } from "next/navigation";
import { assertClubActiveForMutations } from "@/lib/clubs/club-status";
import { createClient } from "@/lib/supabase/server";
import { hasPermission } from "@/lib/rbac/permissions";
import { assignMemberRole, removeMemberRole } from "@/lib/rbac/role-actions";
import { logAuditEvent } from "@/lib/rbac/audit";
import {
  governanceAddSchema,
  governanceRemoveSchema,
  governanceTransferSchema,
} from "@/lib/validation/clubs";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function governanceUrl(clubId: string, params?: Record<string, string>) {
  const base = `/clubs/${clubId}/settings/governance`;
  if (!params) return base;
  return `${base}?${new URLSearchParams(params).toString()}`;
}

function firstIssue(result: { error: { issues: Array<{ message: string }> } }) {
  return result.error.issues[0]?.message ?? "Invalid request.";
}

/**
 * Looks up the President system role ID for a club.
 * Returns null if RBAC migrations have not been applied.
 */
async function getPresidentRoleId(
  supabase: Awaited<ReturnType<typeof createClient>>,
  clubId: string,
): Promise<string | null> {
  const { data } = await supabase
    .from("club_roles")
    .select("id")
    .eq("club_id", clubId)
    .eq("name", "President")
    .eq("is_system", true)
    .maybeSingle();
  return data?.id ?? null;
}

// ─── Add Co-President ─────────────────────────────────────────────────────────
/**
 * Grants the President role to another club member.
 * Requires: club.transfer_presidency permission (Presidents only).
 * Does NOT remove the acting user from the President role.
 */
export async function addPresidentAction(formData: FormData) {
  const parsed = governanceAddSchema.safeParse({
    clubId: formData.get("club_id"),
    targetUserId: formData.get("target_user_id"),
  });

  if (!parsed.success) {
    const clubId = String(formData.get("club_id") ?? "");
    redirect(governanceUrl(clubId, { error: firstIssue(parsed) }));
  }

  const { clubId, targetUserId } = parsed.data;

  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const active = await assertClubActiveForMutations(clubId);
  if (!active.ok) {
    redirect(governanceUrl(clubId, { error: encodeURIComponent(active.message) }));
  }

  // Gate: only users with club.transfer_presidency (i.e. Presidents) may grant Presidency.
  const canTransfer = await hasPermission(user.id, clubId, "club.transfer_presidency");
  if (!canTransfer) {
    redirect(governanceUrl(clubId, { error: "Only+Presidents+can+grant+the+President+role." }));
  }

  // Prevent promoting self (already a President).
  if (targetUserId === user.id) {
    redirect(governanceUrl(clubId, { error: "You+are+already+a+President+of+this+club." }));
  }

  const presidentRoleId = await getPresidentRoleId(supabase, clubId);
  if (!presidentRoleId) {
    redirect(governanceUrl(clubId, { error: "President+role+not+found.+Apply+the+RBAC+database+migrations." }));
  }

  // assignMemberRole enforces: members.assign_roles + President escalation guard
  // + target must be a club member + idempotent on duplicate.
  const result = await assignMemberRole(user.id, targetUserId, clubId, presidentRoleId);
  if (!result.ok) {
    redirect(governanceUrl(clubId, { error: encodeURIComponent(result.error) }));
  }

  await logAuditEvent({
    clubId,
    actorId: user.id,
    action: "president.added",
    targetUserId,
    targetRoleId: presidentRoleId,
  });

  redirect(governanceUrl(clubId, { success: "Co-President+added+successfully." }));
}

// ─── Remove President ─────────────────────────────────────────────────────────
/**
 * Removes the President role from a club member.
 * Requires: club.transfer_presidency permission (Presidents only).
 * The DB trigger prevents removing the last President — this surfaces cleanly.
 */
export async function removePresidentAction(formData: FormData) {
  const parsed = governanceRemoveSchema.safeParse({
    clubId: formData.get("club_id"),
    targetUserId: formData.get("target_user_id"),
  });

  if (!parsed.success) {
    const clubId = String(formData.get("club_id") ?? "");
    redirect(governanceUrl(clubId, { error: firstIssue(parsed) }));
  }

  const { clubId, targetUserId } = parsed.data;

  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const active = await assertClubActiveForMutations(clubId);
  if (!active.ok) {
    redirect(governanceUrl(clubId, { error: encodeURIComponent(active.message) }));
  }

  const canTransfer = await hasPermission(user.id, clubId, "club.transfer_presidency");
  if (!canTransfer) {
    redirect(governanceUrl(clubId, { error: "Only+Presidents+can+remove+the+President+role." }));
  }

  const presidentRoleId = await getPresidentRoleId(supabase, clubId);
  if (!presidentRoleId) {
    redirect(governanceUrl(clubId, { error: "President+role+not+found.+Apply+the+RBAC+database+migrations." }));
  }

  // removeMemberRole enforces: members.assign_roles + last-President DB trigger.
  const result = await removeMemberRole(user.id, targetUserId, clubId, presidentRoleId);
  if (!result.ok) {
    redirect(governanceUrl(clubId, { error: encodeURIComponent(result.error) }));
  }

  await logAuditEvent({
    clubId,
    actorId: user.id,
    action: "president.removed",
    targetUserId,
    targetRoleId: presidentRoleId,
  });

  redirect(governanceUrl(clubId, { success: "President+removed+successfully." }));
}

// ─── Transfer Presidency ──────────────────────────────────────────────────────
/**
 * Transfers full Presidency to another member and removes the acting user
 * from the President role.
 *
 * Order of operations (safe):
 *   1. Grant target the President role  → guarantees ≥1 President exists
 *   2. Remove self from President role  → DB trigger fires; succeeds because
 *      the target was just added
 *
 * If step 2 fails after step 1, the club will have two Presidents rather than
 * zero — the safe failure mode. The acting user can remove themselves manually.
 */
export async function transferPresidencyAction(formData: FormData) {
  const parsed = governanceTransferSchema.safeParse({
    clubId: formData.get("club_id"),
    targetUserId: formData.get("target_user_id"),
  });

  if (!parsed.success) {
    const clubId = String(formData.get("club_id") ?? "");
    redirect(governanceUrl(clubId, { error: firstIssue(parsed) }));
  }

  const { clubId, targetUserId } = parsed.data;

  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  if (targetUserId === user.id) {
    redirect(governanceUrl(clubId, { error: "You+cannot+transfer+Presidency+to+yourself." }));
  }

  const active = await assertClubActiveForMutations(clubId);
  if (!active.ok) {
    redirect(governanceUrl(clubId, { error: encodeURIComponent(active.message) }));
  }

  const canTransfer = await hasPermission(user.id, clubId, "club.transfer_presidency");
  if (!canTransfer) {
    redirect(governanceUrl(clubId, { error: "Only+Presidents+can+transfer+Presidency." }));
  }

  const presidentRoleId = await getPresidentRoleId(supabase, clubId);
  if (!presidentRoleId) {
    redirect(governanceUrl(clubId, { error: "President+role+not+found.+Apply+the+RBAC+database+migrations." }));
  }

  // Step 1: Grant target the President role.
  const addResult = await assignMemberRole(user.id, targetUserId, clubId, presidentRoleId);
  if (!addResult.ok) {
    redirect(governanceUrl(clubId, { error: encodeURIComponent(addResult.error) }));
  }

  // Step 2: Remove self from President role.
  // At this point the target is already a President, so the last-President
  // guardrail will not trigger.
  const removeResult = await removeMemberRole(user.id, user.id, clubId, presidentRoleId);
  if (!removeResult.ok) {
    // Step 1 succeeded — the target is now a President. Advise the user to
    // manually remove themselves if they still want to step down.
    redirect(
      governanceUrl(clubId, {
        error: encodeURIComponent(
          `${targetUserId} is now a President, but we could not remove you automatically: ${removeResult.error}. Remove yourself manually from the list below.`,
        ),
      }),
    );
  }

  await logAuditEvent({
    clubId,
    actorId: user.id,
    action: "presidency.transferred",
    targetUserId,
    targetRoleId: presidentRoleId,
    metadata: { from_user_id: user.id },
  });

  redirect(governanceUrl(clubId, { success: "Presidency+transferred+successfully.+You+are+no+longer+a+President." }));
}
