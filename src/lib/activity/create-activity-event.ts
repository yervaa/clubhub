import "server-only";
import { createAdminClient } from "@/lib/supabase/admin";
import type { ActivityEventInput } from "@/lib/activity/types";

export async function createActivityEvent(input: ActivityEventInput): Promise<string | null> {
  const admin = createAdminClient();
  const { data, error } = await admin
    .from("activity_events")
    .insert({
      type: input.type,
      actor_id: input.actorId,
      club_id: input.clubId,
      entity_id: input.entityId ?? null,
      target_label: input.targetLabel,
      href: input.href ?? null,
      metadata: input.metadata ?? {},
    })
    .select("id")
    .maybeSingle();

  if (error) {
    console.error("[activity] Failed to create activity event:", input.type, error.message);
    return null;
  }

  return data?.id ?? null;
}
