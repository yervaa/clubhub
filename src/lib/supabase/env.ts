function cleanEnvValue(value: string | undefined) {
  if (!value) return "";
  return value.trim().replace(/^['"]|['"]$/g, "");
}

export function getSupabaseEnv() {
  const url = cleanEnvValue(process.env.NEXT_PUBLIC_SUPABASE_URL);
  const anonKey = cleanEnvValue(process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY);

  if (!url || !anonKey) {
    throw new Error(
      "Missing Supabase environment variables. Set NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_ANON_KEY.",
    );
  }

  return { url, anonKey };
}

export function getSupabaseServiceRoleKey() {
  const serviceRoleKey = cleanEnvValue(process.env.SUPABASE_SERVICE_ROLE_KEY);

  if (!serviceRoleKey) {
    throw new Error("Missing SUPABASE_SERVICE_ROLE_KEY in server environment.");
  }

  return serviceRoleKey;
}
