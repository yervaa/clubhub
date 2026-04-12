"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";
import { createClient } from "@/lib/supabase/server";

const uuidSchema = z.uuid("Invalid announcement.");

export async function markAnnouncementReadAction(announcementId: string): Promise<{ ok: boolean }> {
  const idParsed = uuidSchema.safeParse(announcementId);
  if (!idParsed.success) {
    return { ok: false };
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    return { ok: false };
  }

  const { error } = await supabase.from("announcement_reads").upsert(
    {
      announcement_id: idParsed.data,
      user_id: user.id,
      read_at: new Date().toISOString(),
    },
    { onConflict: "announcement_id,user_id", ignoreDuplicates: true },
  );

  if (error) {
    return { ok: false };
  }

  return { ok: true };
}

export type AnnouncementReaderRow = {
  userId: string;
  fullName: string;
  email: string;
  readAt: string;
};

export async function getAnnouncementReadersAction(
  announcementId: string,
): Promise<{ ok: true; readers: AnnouncementReaderRow[] } | { ok: false; error: string }> {
  const idParsed = uuidSchema.safeParse(announcementId);
  if (!idParsed.success) {
    return { ok: false, error: "Invalid announcement." };
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    return { ok: false, error: "You must be logged in." };
  }

  const { data, error } = await supabase.rpc("list_announcement_readers", {
    p_announcement_id: idParsed.data,
  });

  if (error) {
    return { ok: false, error: "Unable to load readers." };
  }

  const rows = (data ?? []) as {
    user_id: string;
    full_name: string;
    email: string;
    read_at: string;
  }[];

  return {
    ok: true,
    readers: rows.map((r) => ({
      userId: r.user_id,
      fullName: r.full_name,
      email: r.email,
      readAt: r.read_at,
    })),
  };
}

export async function votePollAnnouncementAction(
  announcementId: string,
  optionIndex: number,
): Promise<{ ok: true } | { ok: false; error: string }> {
  const idParsed = uuidSchema.safeParse(announcementId);
  if (!idParsed.success) {
    return { ok: false, error: "Invalid announcement." };
  }

  if (!Number.isInteger(optionIndex) || optionIndex < 0 || optionIndex > 32) {
    return { ok: false, error: "Invalid option." };
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    return { ok: false, error: "You must be logged in." };
  }

  const { data: ann, error: annErr } = await supabase
    .from("announcements")
    .select("id, club_id, poll_question, poll_options")
    .eq("id", idParsed.data)
    .maybeSingle();

  if (annErr || !ann?.poll_question) {
    return { ok: false, error: "This poll is not available." };
  }

  const rawOpts = ann.poll_options;
  const len = Array.isArray(rawOpts) ? rawOpts.length : 0;
  if (optionIndex >= len) {
    return { ok: false, error: "Invalid option." };
  }

  const { error } = await supabase.from("poll_votes").upsert(
    {
      announcement_id: idParsed.data,
      user_id: user.id,
      option_index: optionIndex,
    },
    { onConflict: "announcement_id,user_id" },
  );

  if (error) {
    return { ok: false, error: "Unable to save your vote." };
  }

  revalidatePath(`/clubs/${ann.club_id}/announcements`);
  return { ok: true };
}
