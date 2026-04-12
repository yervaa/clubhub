"use server";

import { revalidatePath } from "next/cache";
import { assertClubActiveForMutations } from "@/lib/clubs/club-status";
import { isViewerActiveLegacyOfficer } from "@/lib/clubs/member-management-access";
import { hasPermission } from "@/lib/rbac/permissions";
import { enforceRateLimit, getRateLimitErrorMessage } from "@/lib/rate-limit";
import { createClient } from "@/lib/supabase/server";
import { joinRequestDecisionSchema } from "@/lib/validation/clubs";

export type JoinRequestReviewState = { ok: true } | { ok: false; error: string };

async function assertCanReviewJoinRequests(userId: string, clubId: string): Promise<boolean> {
  if (await hasPermission(userId, clubId, "members.review_join_requests")) {
    return true;
  }
  const supabase = await createClient();
  const { data: row } = await supabase
    .from("club_members")
    .select("role, membership_status")
    .eq("club_id", clubId)
    .eq("user_id", userId)
    .maybeSingle();
  return isViewerActiveLegacyOfficer(row ?? null);
}

export async function reviewJoinRequestAction(
  _prev: JoinRequestReviewState,
  formData: FormData,
): Promise<JoinRequestReviewState> {
  const intent = formData.get("intent");
  if (intent === "approve") {
    return approveJoinRequestAction(formData);
  }
  if (intent === "deny") {
    return denyJoinRequestAction(formData);
  }
  return { ok: false, error: "Invalid action." };
}

export async function approveJoinRequestAction(formData: FormData): Promise<JoinRequestReviewState> {
  const parsed = joinRequestDecisionSchema.safeParse({
    clubId: formData.get("club_id"),
    requestId: formData.get("request_id"),
  });

  if (!parsed.success) {
    return { ok: false as const, error: parsed.error.issues[0]?.message ?? "Invalid request." };
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    return { ok: false as const, error: "You must be signed in." };
  }

  const active = await assertClubActiveForMutations(parsed.data.clubId);
  if (!active.ok) {
    return { ok: false as const, error: active.message };
  }

  const canReview = await assertCanReviewJoinRequests(user.id, parsed.data.clubId);
  if (!canReview) {
    return { ok: false as const, error: "You do not have permission to approve join requests." };
  }

  const rateLimit = await enforceRateLimit({
    policy: "joinRequestReview",
    userId: user.id,
    hint: parsed.data.clubId,
  });
  if (!rateLimit.success) {
    return { ok: false as const, error: getRateLimitErrorMessage() };
  }

  const { data: status, error } = await supabase.rpc("approve_club_join_request", {
    p_club_id: parsed.data.clubId,
    p_request_id: parsed.data.requestId,
  });

  if (error) {
    return { ok: false as const, error: "Could not approve request. Please retry." };
  }

  if (status === "not_allowed" || status === "not_authenticated") {
    return { ok: false as const, error: "You do not have permission to approve join requests." };
  }
  if (status === "not_found" || status === "not_pending") {
    return { ok: false as const, error: "This request is no longer pending." };
  }

  revalidatePath(`/clubs/${parsed.data.clubId}/members`);
  revalidatePath(`/clubs/${parsed.data.clubId}`);
  revalidatePath("/dashboard");
  revalidatePath("/clubs");
  return { ok: true };
}

export async function denyJoinRequestAction(formData: FormData): Promise<JoinRequestReviewState> {
  const parsed = joinRequestDecisionSchema.safeParse({
    clubId: formData.get("club_id"),
    requestId: formData.get("request_id"),
  });

  if (!parsed.success) {
    return { ok: false as const, error: parsed.error.issues[0]?.message ?? "Invalid request." };
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    return { ok: false as const, error: "You must be signed in." };
  }

  const active = await assertClubActiveForMutations(parsed.data.clubId);
  if (!active.ok) {
    return { ok: false as const, error: active.message };
  }

  const canReview = await assertCanReviewJoinRequests(user.id, parsed.data.clubId);
  if (!canReview) {
    return { ok: false as const, error: "You do not have permission to deny join requests." };
  }

  const rateLimit = await enforceRateLimit({
    policy: "joinRequestReview",
    userId: user.id,
    hint: parsed.data.clubId,
  });
  if (!rateLimit.success) {
    return { ok: false as const, error: getRateLimitErrorMessage() };
  }

  const { data: status, error } = await supabase.rpc("deny_club_join_request", {
    p_club_id: parsed.data.clubId,
    p_request_id: parsed.data.requestId,
  });

  if (error) {
    return { ok: false as const, error: "Could not deny request. Please retry." };
  }

  if (status === "not_allowed" || status === "not_authenticated") {
    return { ok: false as const, error: "You do not have permission to deny join requests." };
  }
  if (status === "not_found") {
    return { ok: false as const, error: "This request is no longer pending." };
  }

  revalidatePath(`/clubs/${parsed.data.clubId}/members`);
  revalidatePath(`/clubs/${parsed.data.clubId}`);
  return { ok: true };
}
