"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";
import { assertClubActiveForMutations } from "@/lib/clubs/club-status";
import { canImportMemberList } from "@/lib/clubs/member-import-auth";
import { parseCsvRows, stripUtf8Bom } from "@/lib/csv-parse";
import { enforceRateLimit, getRateLimitErrorMessage } from "@/lib/rate-limit";
import { createClient } from "@/lib/supabase/server";
import { memberImportCommitSchema } from "@/lib/validation/clubs";

const MAX_CSV_BYTES = 256 * 1024;
const MAX_DATA_ROWS = 300;

const clubIdFormSchema = z.object({
  clubId: z.uuid("Invalid club."),
});

export type MemberImportRowStatus =
  | "invalid_email"
  | "missing_email"
  | "duplicate_in_file"
  | "no_profile"
  | "already_member"
  | "ready";

export type MemberImportPreviewRow = {
  rowNumber: number;
  emailRaw: string;
  emailNormalized: string | null;
  /** Optional column from CSV — preview only; not written to profiles. */
  labelFromCsv: string | null;
  status: MemberImportRowStatus;
  /** Profile full name when resolved; for already_member / ready. */
  resolvedFullName: string | null;
};

export type MemberImportPreviewSummary = {
  ready: number;
  invalidEmail: number;
  missingEmail: number;
  duplicateInFile: number;
  noProfile: number;
  alreadyMember: number;
  /** Completely empty lines after the header row. */
  skippedBlankRows: number;
};

export type MemberImportPreviewResult =
  | { ok: true; rows: MemberImportPreviewRow[]; summary: MemberImportPreviewSummary; readyEmails: string[] }
  | { ok: false; error: string };

export type MemberImportCommitResult =
  | {
      ok: true;
      added: number;
      skippedDuplicateInFile: number;
      skippedNoProfile: number;
      skippedAlreadyMember: number;
    }
  | { ok: false; error: string };

type LookupRow = { norm_email: string; user_id: string; full_name: string };

function normalizeHeaderKey(h: string): string {
  return h.trim().toLowerCase().replace(/\s+/g, " ");
}

function findHeaderIndex(headers: string[], candidates: string[]): number | null {
  const mapped = headers.map((h) => normalizeHeaderKey(h));
  for (const c of candidates) {
    const idx = mapped.indexOf(c);
    if (idx >= 0) return idx;
  }
  return null;
}

const emailFormatSchema = z.string().trim().email();

function summarizePreview(rows: MemberImportPreviewRow[]): MemberImportPreviewSummary {
  const s: MemberImportPreviewSummary = {
    ready: 0,
    invalidEmail: 0,
    missingEmail: 0,
    duplicateInFile: 0,
    noProfile: 0,
    alreadyMember: 0,
    skippedBlankRows: 0,
  };
  for (const r of rows) {
    if (r.status === "ready") s.ready++;
    else if (r.status === "invalid_email") s.invalidEmail++;
    else if (r.status === "missing_email") s.missingEmail++;
    else if (r.status === "duplicate_in_file") s.duplicateInFile++;
    else if (r.status === "no_profile") s.noProfile++;
    else if (r.status === "already_member") s.alreadyMember++;
  }
  return s;
}

function friendlyRpcMessage(message: string): string {
  const m = message.toLowerCase();
  if (m.includes("permission denied") || m.includes("permission_denied")) {
    return "You do not have permission to import members.";
  }
  if (m.includes("club archived") || m.includes("club_archived")) {
    return "This club is archived and can no longer be edited.";
  }
  if (m.includes("too many")) {
    return "Too many rows in this request.";
  }
  if (m.includes("not authenticated")) {
    return "You must be signed in.";
  }
  return "Import could not be completed. Please try again.";
}

export async function previewMemberImportAction(formData: FormData): Promise<MemberImportPreviewResult> {
  const parsedId = clubIdFormSchema.safeParse({ clubId: formData.get("clubId") });
  if (!parsedId.success) {
    return { ok: false, error: parsedId.error.issues[0]?.message ?? "Invalid club." };
  }

  const { clubId } = parsedId.data;
  const file = formData.get("file");

  if (!(file instanceof File)) {
    return { ok: false, error: "Choose a CSV file to upload." };
  }

  if (file.size > MAX_CSV_BYTES) {
    return { ok: false, error: `File is too large (max ${Math.round(MAX_CSV_BYTES / 1024)} KB).` };
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    return { ok: false, error: "You must be signed in." };
  }

  if (!(await canImportMemberList(user.id, clubId))) {
    return { ok: false, error: "You do not have permission to import members." };
  }

  const active = await assertClubActiveForMutations(clubId);
  if (!active.ok) {
    return { ok: false, error: active.message };
  }

  const rateLimit = await enforceRateLimit({
    policy: "memberImport",
    userId: user.id,
    hint: clubId,
  });
  if (!rateLimit.success) {
    return { ok: false, error: getRateLimitErrorMessage() };
  }

  let text: string;
  try {
    text = stripUtf8Bom(await file.text());
  } catch {
    return { ok: false, error: "Could not read the file. Try saving as UTF-8 CSV." };
  }

  const grid = parseCsvRows(text);
  if (grid.length === 0) {
    return { ok: false, error: "The CSV is empty." };
  }

  const headerRow = grid[0]!.map((c) => c.trim());
  const emailIdx = findHeaderIndex(headerRow, ["email", "e-mail"]);
  if (emailIdx === null) {
    return {
      ok: false,
      error: 'Missing required column header "email" (first row). Optional: "full_name" or "name".',
    };
  }

  const labelIdx = findHeaderIndex(headerRow, ["full_name", "name", "display name", "displayname"]);

  const dataRows = grid.slice(1);
  if (dataRows.length > MAX_DATA_ROWS) {
    return { ok: false, error: `Too many data rows (max ${MAX_DATA_ROWS} per upload).` };
  }

  const previewRows: MemberImportPreviewRow[] = [];
  const seenNormalized = new Set<string>();
  const toLookup: string[] = [];
  let skippedBlankRows = 0;

  let rowNumber = 1;
  for (const cells of dataRows) {
    rowNumber++;
    const isBlankRow = cells.every((c) => c.trim() === "");
    if (isBlankRow) {
      skippedBlankRows++;
      continue;
    }

    const emailRaw = (cells[emailIdx] ?? "").trim();
    const labelFromCsv =
      labelIdx !== null ? (cells[labelIdx] ?? "").trim() || null : null;

    if (emailRaw === "") {
      previewRows.push({
        rowNumber,
        emailRaw: "",
        emailNormalized: null,
        labelFromCsv,
        status: "missing_email",
        resolvedFullName: null,
      });
      continue;
    }

    const formatResult = emailFormatSchema.safeParse(emailRaw);
    if (!formatResult.success) {
      previewRows.push({
        rowNumber,
        emailRaw,
        emailNormalized: null,
        labelFromCsv,
        status: "invalid_email",
        resolvedFullName: null,
      });
      continue;
    }

    const normalized = formatResult.data.toLowerCase();
    if (seenNormalized.has(normalized)) {
      previewRows.push({
        rowNumber,
        emailRaw,
        emailNormalized: normalized,
        labelFromCsv,
        status: "duplicate_in_file",
        resolvedFullName: null,
      });
      continue;
    }

    seenNormalized.add(normalized);
    toLookup.push(normalized);
    previewRows.push({
      rowNumber,
      emailRaw,
      emailNormalized: normalized,
      labelFromCsv,
      status: "ready",
      resolvedFullName: null,
    });
  }

  if (toLookup.length === 0) {
    return {
      ok: true,
      rows: previewRows,
      summary: { ...summarizePreview(previewRows), skippedBlankRows },
      readyEmails: [],
    };
  }

  const { data: lookupData, error: lookupError } = await supabase.rpc("lookup_profiles_for_member_import", {
    p_club_id: clubId,
    p_emails: toLookup,
  });

  if (lookupError) {
    return { ok: false, error: friendlyRpcMessage(lookupError.message) };
  }

  const lookupMap = new Map<string, LookupRow>();
  for (const row of (lookupData ?? []) as LookupRow[]) {
    lookupMap.set(row.norm_email, row);
  }

  const { data: memberRows, error: memberErr } = await supabase
    .from("club_members")
    .select("user_id")
    .eq("club_id", clubId);

  if (memberErr) {
    return { ok: false, error: "Could not load current roster for comparison." };
  }

  const memberIds = new Set((memberRows ?? []).map((r) => r.user_id as string));

  const readyEmails: string[] = [];

  for (const pr of previewRows) {
    if (pr.status !== "ready" || !pr.emailNormalized) continue;

    const hit = lookupMap.get(pr.emailNormalized);
    if (!hit) {
      pr.status = "no_profile";
      pr.resolvedFullName = null;
      continue;
    }

    pr.resolvedFullName = hit.full_name || null;
    if (memberIds.has(hit.user_id)) {
      pr.status = "already_member";
      continue;
    }

    readyEmails.push(pr.emailNormalized);
  }

  return {
    ok: true,
    rows: previewRows,
    summary: { ...summarizePreview(previewRows), skippedBlankRows },
    readyEmails,
  };
}

export async function commitMemberImportAction(payload: unknown): Promise<MemberImportCommitResult> {
  const parsed = memberImportCommitSchema.safeParse(payload);
  if (!parsed.success) {
    return { ok: false, error: parsed.error.issues[0]?.message ?? "Invalid import request." };
  }

  const { clubId, emails } = parsed.data;

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    return { ok: false, error: "You must be signed in." };
  }

  if (!(await canImportMemberList(user.id, clubId))) {
    return { ok: false, error: "You do not have permission to import members." };
  }

  const active = await assertClubActiveForMutations(clubId);
  if (!active.ok) {
    return { ok: false, error: active.message };
  }

  const rateLimit = await enforceRateLimit({
    policy: "memberImport",
    userId: user.id,
    hint: clubId,
  });
  if (!rateLimit.success) {
    return { ok: false, error: getRateLimitErrorMessage() };
  }

  const { data, error } = await supabase.rpc("commit_club_member_import", {
    p_club_id: clubId,
    p_emails: emails,
  });

  if (error) {
    return { ok: false, error: friendlyRpcMessage(error.message) };
  }

  const body = data as {
    ok?: boolean;
    error?: string;
    added?: number;
    skipped_duplicate_in_file?: number;
    skipped_no_profile?: number;
    skipped_already_member?: number;
  };

  if (!body?.ok) {
    return { ok: false, error: friendlyRpcMessage(body?.error ?? "permission_denied") };
  }

  revalidatePath(`/clubs/${clubId}/members`);

  return {
    ok: true,
    added: body.added ?? 0,
    skippedDuplicateInFile: body.skipped_duplicate_in_file ?? 0,
    skippedNoProfile: body.skipped_no_profile ?? 0,
    skippedAlreadyMember: body.skipped_already_member ?? 0,
  };
}
