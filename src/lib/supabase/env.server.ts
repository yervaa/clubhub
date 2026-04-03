import "server-only";

import { cleanEnvValue } from "@/lib/supabase/env.shared";

/**
 * Service role key — **server-only**. Never import this module from client components.
 */
export function getSupabaseServiceRoleKey(): string {
  const serviceRoleKey = cleanEnvValue(process.env.SUPABASE_SERVICE_ROLE_KEY);

  if (!serviceRoleKey) {
    throw new Error("Missing SUPABASE_SERVICE_ROLE_KEY in server environment.");
  }

  return serviceRoleKey;
}
