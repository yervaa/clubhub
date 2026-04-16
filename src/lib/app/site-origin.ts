/**
 * Public site origin for absolute links in emails (digest, transactional).
 * Prefer `NEXT_PUBLIC_SITE_URL`; fallback to `VERCEL_URL` in production.
 */
export function getPublicSiteOrigin(): string | null {
  const raw = process.env.NEXT_PUBLIC_SITE_URL?.trim() || process.env.VERCEL_URL?.trim();
  if (!raw) {
    return null;
  }
  const withProto = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  try {
    return new URL(withProto).origin;
  } catch {
    return null;
  }
}
