import "server-only";
import { createClient } from "@supabase/supabase-js";
import { getSupabaseEnv, getSupabaseServiceRoleKey } from "@/lib/supabase/env";

export function createAdminClient() {
  const { url } = getSupabaseEnv();
  const serviceRoleKey = getSupabaseServiceRoleKey();

  return createClient(url, serviceRoleKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });
}
