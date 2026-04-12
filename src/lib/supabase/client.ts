import { createBrowserClient } from "@supabase/ssr";
import { getSupabaseEnv } from "@/lib/supabase/env";

/** Browser client — uses only `NEXT_PUBLIC_SUPABASE_*` (see `getSupabaseEnv`). */
export function createClient() {
  const { url, anonKey } = getSupabaseEnv();
  return createBrowserClient(url, anonKey);
}
