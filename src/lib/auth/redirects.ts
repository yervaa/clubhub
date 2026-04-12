const MAX_NEXT_LEN = 2048;

/** Post-auth redirects must not target auth surfaces (avoid redirect loops). */
const DISALLOWED_PATH_PREFIXES = ["/login", "/signup"];

/**
 * Returns a same-origin relative path safe to pass to `redirect()`.
 * Rejects scheme-relative URLs (`//`), traversal, backslashes, and auth-only routes.
 */
export function getSafeNextPath(
  value: string | null | undefined | string[],
  fallback = "/dashboard",
): string {
  let raw: string | null | undefined;
  if (Array.isArray(value)) {
    raw = value[0];
  } else {
    raw = value;
  }

  if (!raw || typeof raw !== "string") {
    return fallback;
  }

  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > MAX_NEXT_LEN) {
    return fallback;
  }

  if (!trimmed.startsWith("/") || trimmed.startsWith("//")) {
    return fallback;
  }

  if (trimmed.includes("\\") || /[\u0000-\u001f\u007f]/.test(trimmed)) {
    return fallback;
  }

  const q = trimmed.indexOf("?");
  const h = trimmed.indexOf("#");
  let end = trimmed.length;
  if (q >= 0) end = Math.min(end, q);
  if (h >= 0) end = Math.min(end, h);
  const pathname = trimmed.slice(0, end);

  if (pathname.includes("..") || pathname.includes("//")) {
    return fallback;
  }

  const pathLower = pathname.toLowerCase();
  for (const prefix of DISALLOWED_PATH_PREFIXES) {
    if (pathLower === prefix || pathLower.startsWith(`${prefix}/`)) {
      return fallback;
    }
  }

  return trimmed;
}
