import "server-only";
import { createAdminClient } from "@/lib/supabase/admin";

const BUCKET = "announcement-attachments";
const TTL_SECONDS = 3600;

export type AttachmentRow = {
  id: string;
  announcement_id: string;
  file_url: string;
  file_name: string;
  file_type: string;
};

/**
 * SECURITY: callers MUST pass rows fetched via a user-scoped (RLS-filtered)
 * Supabase client so that `announcement_attachments_select_member` has already
 * authorized access. Never pass rows fetched with the admin/service-role client
 * (which bypasses RLS) — this helper performs no authorization of its own and
 * will mint a signed URL for any path it is handed.
 */
export async function signAnnouncementAttachmentRows(
  rows: AttachmentRow[],
): Promise<Map<string, string>> {
  if (rows.length === 0) return new Map();

  const admin = createAdminClient();
  const out = new Map<string, string>();

  for (const row of rows) {
    // Non-image types (PDF) download instead of rendering inline, to avoid
    // serving attacker-influenced bytes inline under an attacker-chosen type.
    const isImage = (row.file_type || "").toLowerCase().startsWith("image/");
    const options = isImage ? undefined : { download: row.file_name || true };
    const { data, error } = await admin.storage
      .from(BUCKET)
      .createSignedUrl(row.file_url, TTL_SECONDS, options);
    if (!error && data?.signedUrl) {
      out.set(row.id, data.signedUrl);
    }
  }

  return out;
}
