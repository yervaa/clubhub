import type { User } from "@supabase/supabase-js";
import { sanitizeInlineText } from "@/lib/sanitize";
import { createClient } from "@/lib/supabase/server";

export async function upsertCurrentUserProfile(
  supabase: Awaited<ReturnType<typeof createClient>>,
  user: User,
) {
  return supabase.from("profiles").upsert(
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
}
