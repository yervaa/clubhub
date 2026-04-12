/**
 * Public Supabase settings only (`NEXT_PUBLIC_*`). Safe for the browser bundle via
 * `lib/supabase/client.ts`. Do **not** read `SUPABASE_SERVICE_ROLE_KEY` or other
 * server secrets here — use `env.server.ts` / `admin.ts` on the server only.
 */
import { cleanEnvValue } from "@/lib/supabase/env.shared";

function ensureValidUrl(value: string, envName: string) {
  try {
    const parsed = new URL(value);
    if (!parsed.protocol.startsWith("http")) {
      throw new Error("Invalid protocol");
    }
  } catch {
    throw new Error(`Invalid ${envName}. Expected a full https URL.`);
  }
}

/** URL + anon key — safe to use from browser client (`createBrowserClient`). */
export function getSupabaseEnv() {
  const url = cleanEnvValue(process.env.NEXT_PUBLIC_SUPABASE_URL);
  const anonKey = cleanEnvValue(process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY);

  if (!url || !anonKey) {
    throw new Error(
      "Missing Supabase environment variables. Set NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_ANON_KEY.",
    );
  }

  ensureValidUrl(url, "NEXT_PUBLIC_SUPABASE_URL");

  return { url, anonKey };
}
