/**
 * Runs once when the Node.js server starts (not during `next build`).
 * Surfaces misconfigured deploy env early in host logs (Vercel preview/production).
 */
export function register() {
  if (process.env.NEXT_RUNTIME !== "nodejs") {
    return;
  }

  const vercelEnv = process.env.VERCEL_ENV;
  const onVercelHosted = vercelEnv === "production" || vercelEnv === "preview";
  if (!onVercelHosted) {
    return;
  }

  const trim = (v: string | undefined) => v?.trim().replace(/^['"]|['"]$/g, "") ?? "";

  const pubUrl = trim(process.env.NEXT_PUBLIC_SUPABASE_URL);
  const pubAnon = trim(process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY);
  if (!pubUrl || !pubAnon) {
    console.error(
      "[clubhub] Missing NEXT_PUBLIC_SUPABASE_URL or NEXT_PUBLIC_SUPABASE_ANON_KEY in this Vercel environment — sessions and data access will fail.",
    );
  }

  if (!trim(process.env.SUPABASE_SERVICE_ROLE_KEY)) {
    console.error(
      "[clubhub] Missing SUPABASE_SERVICE_ROLE_KEY in this Vercel environment — admin server paths (tasks, notifications, audit, some joins) will error when used.",
    );
  }

  const upstashOk =
    Boolean(trim(process.env.UPSTASH_REDIS_REST_URL)) && Boolean(trim(process.env.UPSTASH_REDIS_REST_TOKEN));
  if (!upstashOk) {
    console.warn(
      "[clubhub] Upstash Redis env vars missing on Vercel — rate limits use in-memory fallback per instance (weak under serverless concurrency). Set UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN for preview and production.",
    );
  }
}
