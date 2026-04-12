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

export async function signAnnouncementAttachmentRows(
  rows: AttachmentRow[],
): Promise<Map<string, string>> {
  if (rows.length === 0) return new Map();

  const admin = createAdminClient();
  const out = new Map<string, string>();

  for (const row of rows) {
    const { data, error } = await admin.storage.from(BUCKET).createSignedUrl(row.file_url, TTL_SECONDS);
    if (!error && data?.signedUrl) {
      out.set(row.id, data.signedUrl);
    }
  }

  return out;
}
