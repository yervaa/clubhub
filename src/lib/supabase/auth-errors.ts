import type { AuthError } from "@supabase/supabase-js";

/** Supabase Auth errors where stored cookies should be discarded (stale / revoked session). */
export function isInvalidRefreshSessionError(error: AuthError | null | undefined): boolean {
  if (!error) return false;
  const code = error.code ?? "";
  if (code === "refresh_token_not_found") return true;
  if (code === "invalid_grant") return true;
  const msg = (error.message ?? "").toLowerCase();
  return msg.includes("refresh token") && (msg.includes("not found") || msg.includes("invalid"));
}

/** Remove Supabase browser cookie pairs from a raw `Cookie` header value. */
export function filterSupabaseCookiesFromHeader(cookieHeader: string | null): string | null {
  if (!cookieHeader?.trim()) return null;
  const pairs = cookieHeader
    .split(";")
    .map((s) => s.trim())
    .filter(Boolean);
  const kept = pairs.filter((pair) => {
    const name = pair.split("=")[0]?.trim() ?? "";
    return name.length > 0 && !name.startsWith("sb-");
  });
  return kept.length > 0 ? kept.join("; ") : null;
}
