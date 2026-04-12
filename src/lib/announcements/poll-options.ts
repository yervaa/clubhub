/** Normalizes poll_options JSONB from the database into a string array or null. */
export function parsePollOptionsFromDb(raw: unknown): string[] | null {
  if (raw == null) return null;
  if (!Array.isArray(raw)) return null;
  const out: string[] = [];
  for (const item of raw) {
    if (typeof item !== "string") return null;
    const t = item.trim();
    if (t.length === 0) return null;
    out.push(t);
  }
  return out.length > 0 ? out : null;
}
