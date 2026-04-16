import { z } from "zod";
import { EVENT_TYPE_OPTIONS } from "@/lib/events";
import { sanitizeCode, sanitizeInlineText, sanitizeMultilineText } from "@/lib/sanitize";

const uuidSchema = z.uuid("Invalid record identifier.");

/** JSON `assignee_ids` field from task forms — cap size before `JSON.parse`. */
const MAX_TASK_ASSIGNEE_JSON_CHARS = 4096;
/** Matches practical UI limits and keeps notification / insert batches bounded. */
export const MAX_TASK_ASSIGNEES_PER_TASK = 30;

/**
 * Parses the JSON array of user ids from task create/update forms.
 * Rejects malformed JSON, non-arrays, non-UUID strings, and oversized lists.
 */
export function parseTaskAssigneeIdsJson(raw: unknown): { ok: true; ids: string[] } | { ok: false; error: string } {
  const s = typeof raw === "string" ? raw : "";
  if (s.length > MAX_TASK_ASSIGNEE_JSON_CHARS) {
    return { ok: false, error: "Assignee list is too large." };
  }
  const t = s.trim();
  if (t === "") return { ok: true, ids: [] };
  let parsed: unknown;
  try {
    parsed = JSON.parse(t);
  } catch {
    return { ok: false, error: "Invalid assignee data." };
  }
  if (!Array.isArray(parsed)) {
    return { ok: false, error: "Assignee list must be a JSON array." };
  }
  if (parsed.length > MAX_TASK_ASSIGNEES_PER_TASK) {
    return { ok: false, error: `You can assign at most ${MAX_TASK_ASSIGNEES_PER_TASK} members per task.` };
  }
  const ids: string[] = [];
  for (const item of parsed) {
    if (typeof item !== "string" || !uuidSchema.safeParse(item).success) {
      return { ok: false, error: "Invalid assignee identifier." };
    }
    ids.push(item);
  }
  return { ok: true, ids };
}

/** Parses optional due datetime; rejects invalid dates instead of silently dropping them. */
export function parseTaskDueAtFormValue(raw: unknown): { ok: true; iso: string | null } | { ok: false; error: string } {
  const s = typeof raw === "string" ? raw.trim().slice(0, 48) : "";
  if (s === "") return { ok: true, iso: null };
  const ms = Date.parse(s);
  if (Number.isNaN(ms)) {
    return { ok: false, error: "Enter a valid due date." };
  }
  return { ok: true, iso: new Date(ms).toISOString() };
}
const shortTitleSchema = z.string().transform(sanitizeInlineText).pipe(z.string().min(1).max(160));
const plainTextSchema = z.string().transform(sanitizeMultilineText).pipe(z.string().min(1).max(2000));
const shortInlineSchema = z.string().transform(sanitizeInlineText).pipe(z.string().min(1).max(160));
const eventTypeSchema = z.enum(EVENT_TYPE_OPTIONS);
const optionalEventCapacitySchema = z
  .union([z.string(), z.null(), z.undefined()])
  .transform((value) => (typeof value === "string" ? value.trim() : ""))
  .superRefine((value, ctx) => {
    if (value === "") return;
    if (!/^\d+$/.test(value)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Capacity must be a whole number.",
      });
      return;
    }
    const n = Number.parseInt(value, 10);
    if (n < 1 || n > 5000) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Capacity must be between 1 and 5000.",
      });
    }
  })
  .transform((value) => (value === "" ? null : Number.parseInt(value, 10)));

export const clubCreateSchema = z.object({
  name: shortTitleSchema,
  description: z.string().transform(sanitizeMultilineText).pipe(z.string().min(1).max(500)),
});

export const joinCodeSchema = z.object({
  joinCode: z
    .string()
    .transform(sanitizeCode)
    .refine((value) => /^[A-Z0-9]{8}$/.test(value), "Enter a valid join code."),
});

export const announcementCreateSchema = z.object({
  clubId: uuidSchema,
  title: shortTitleSchema,
  content: plainTextSchema,
});

export const announcementUpdateSchema = z.object({
  clubId: uuidSchema,
  announcementId: uuidSchema,
  title: shortTitleSchema,
  content: plainTextSchema,
});

export const announcementDeleteSchema = z.object({
  clubId: uuidSchema,
  announcementId: uuidSchema,
});

export const MAX_ANNOUNCEMENT_ATTACHMENTS = 5;
export const MAX_ANNOUNCEMENT_ATTACHMENT_BYTES = 5 * 1024 * 1024;
export const ANNOUNCEMENT_ATTACHMENT_MIMES = new Set([
  "image/jpeg",
  "image/png",
  "image/gif",
  "image/webp",
  "application/pdf",
]);

const pollOptionSchema = z
  .string()
  .transform(sanitizeInlineText)
  .pipe(z.string().min(1).max(200));

const optionalPollQuestionSchema = z
  .union([z.string(), z.null(), z.undefined()])
  .transform((v) => (v == null ? "" : String(v)))
  .transform(sanitizeInlineText)
  .pipe(z.string().max(500));

/** Optional schedule: datetime string from `<input type="datetime-local" />` or empty. */
const optionalScheduleSchema = z
  .union([z.string(), z.null(), z.undefined()])
  .transform((v) => (v == null ? "" : String(v).trim().slice(0, 48)));

export type AnnouncementCreateExtras = {
  pollQuestion: string | null;
  pollOptions: string[] | null;
  scheduledForIso: string | null;
  isPublished: boolean;
  isUrgent: boolean;
  isPinned: boolean;
};

/**
 * Parses poll + schedule fields from the announcement form.
 * When poll question is non-empty, requires 2–10 options (already sanitized strings).
 */
export function parseAnnouncementCreateExtras(formData: FormData): {
  ok: true;
  data: AnnouncementCreateExtras;
} | { ok: false; error: string } {
  const pollQuestionRaw = optionalPollQuestionSchema.safeParse(formData.get("poll_question"));
  if (!pollQuestionRaw.success) {
    return { ok: false, error: pollQuestionRaw.error.issues[0]?.message ?? "Invalid poll question." };
  }

  const pollOptionInputs = formData
    .getAll("poll_option")
    .filter((x): x is string => typeof x === "string")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

  const pollQuestion = pollQuestionRaw.data.trim();
  let pollOptions: string[] | null = null;

  if (pollQuestion.length > 0) {
    if (pollOptionInputs.length < 2) {
      return { ok: false, error: "Add at least two poll options." };
    }
    if (pollOptionInputs.length > 10) {
      return { ok: false, error: "You can add at most 10 poll options." };
    }
    const parsed: string[] = [];
    for (const opt of pollOptionInputs) {
      const r = pollOptionSchema.safeParse(opt);
      if (!r.success) {
        return { ok: false, error: r.error.issues[0]?.message ?? "Invalid poll option." };
      }
      parsed.push(r.data);
    }
    pollOptions = parsed;
  } else if (pollOptionInputs.length > 0) {
    return { ok: false, error: "Remove poll options or enter a poll question." };
  }

  const scheduleRaw = optionalScheduleSchema.safeParse(formData.get("scheduled_for"));
  if (!scheduleRaw.success) {
    return { ok: false, error: "Invalid schedule value." };
  }

  const scheduleStr = scheduleRaw.data;
  const intentRaw = formData.get("announcement_intent");
  const intent = typeof intentRaw === "string" ? intentRaw.trim() : "publish_now";
  if (intent !== "publish_now" && intent !== "save_draft") {
    return { ok: false, error: "Invalid publish intent." };
  }
  const isUrgent = formData.get("is_urgent") === "on";
  const requestedPinned = formData.get("is_pinned") === "on";
  let scheduledForIso: string | null = null;
  let isPublished = intent !== "save_draft";

  if (scheduleStr.length > 0 && intent !== "save_draft") {
    const ms = Date.parse(scheduleStr);
    if (Number.isNaN(ms)) {
      return { ok: false, error: "Enter a valid publish date and time." };
    }
    const minAhead = Date.now() + 60_000;
    if (ms < minAhead) {
      return { ok: false, error: "Schedule at least one minute in the future, or leave empty to post now." };
    }
    scheduledForIso = new Date(ms).toISOString();
    isPublished = false;
  }

  return {
    ok: true,
    data: {
      pollQuestion: pollQuestion.length > 0 ? pollQuestion : null,
      pollOptions,
      scheduledForIso,
      isPublished,
      isUrgent,
      isPinned: isPublished && requestedPinned,
    },
  };
}

export type AnnouncementUpdateIntent = "save_draft" | "publish_now" | "save_changes";

export function parseAnnouncementUpdateIntent(formData: FormData): AnnouncementUpdateIntent {
  const raw = formData.get("announcement_intent");
  if (typeof raw !== "string") return "save_changes";
  const trimmed = raw.trim();
  if (trimmed === "save_draft" || trimmed === "publish_now" || trimmed === "save_changes") {
    return trimmed;
  }
  return "save_changes";
}

/** Reflection / optional note blocks — FormData may omit or send null. */
const optionalNotesSchema = z
  .union([z.string(), z.null(), z.undefined()])
  .transform((v) => (v == null ? "" : v))
  .transform(sanitizeMultilineText)
  .pipe(z.string().max(2000));

export const eventCreateSchema = z
  .object({
    clubId: uuidSchema,
    title: shortTitleSchema,
    description: plainTextSchema,
    location: shortInlineSchema,
    eventType: eventTypeSchema,
    capacity: optionalEventCapacitySchema,
    eventDate: z.string().min(1).max(40, "Event date value is too long."),
  })
  .superRefine((value, ctx) => {
    const parsedDate = new Date(value.eventDate);
    if (Number.isNaN(parsedDate.getTime())) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["eventDate"],
        message: "Please enter a valid event date.",
      });
      return;
    }

    if (parsedDate.getTime() < Date.now()) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["eventDate"],
        message: "Event date must be in the future.",
      });
    }
  });

export const eventUpdateSchema = z.object({
  clubId: uuidSchema,
  eventId: uuidSchema,
  title: shortTitleSchema,
  description: plainTextSchema,
  location: shortInlineSchema,
  eventType: eventTypeSchema,
  capacity: optionalEventCapacitySchema,
  eventDate: z.string().min(1).max(40, "Event date value is too long."),
}).superRefine((value, ctx) => {
  const parsedDate = new Date(value.eventDate);
  if (Number.isNaN(parsedDate.getTime())) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["eventDate"],
      message: "Please enter a valid event date.",
    });
  }
});

export const eventDeleteSchema = z.object({
  clubId: uuidSchema,
  eventId: uuidSchema,
});

export const MAX_RECURRING_OCCURRENCES = 52;

const recurrenceFrequencySchema = z.enum(["weekly", "biweekly", "monthly"]);
const recurrenceEndTypeSchema = z.enum(["after_count", "until_date"]);
const optionalTimeHmSchema = z
  .union([z.string(), z.null(), z.undefined()])
  .transform((v) => (typeof v === "string" ? v.trim() : ""));
const optionalDateOnlySchema = z
  .union([z.string(), z.null(), z.undefined()])
  .transform((v) => (typeof v === "string" ? v.trim() : ""));

export type EventRecurrenceSettings = {
  frequency: "weekly" | "biweekly" | "monthly";
  endType: "after_count" | "until_date";
  occurrenceCount: number | null;
  untilDate: string | null;
  durationMinutes: number;
  endTimeHm: string;
};

/**
 * Parses optional recurrence controls from event create form.
 * Returns `null` when recurring mode is not selected.
 */
export function parseEventRecurrenceSettings(
  formData: FormData,
  eventDateInput: string,
): { ok: true; data: EventRecurrenceSettings | null } | { ok: false; error: string } {
  const modeRaw = formData.get("recurrence_mode");
  const mode = typeof modeRaw === "string" ? modeRaw.trim() : "";
  if (mode !== "recurring") {
    return { ok: true, data: null };
  }

  const frequencyParsed = recurrenceFrequencySchema.safeParse(formData.get("recurrence_frequency"));
  if (!frequencyParsed.success) {
    return { ok: false, error: "Choose a valid recurrence frequency." };
  }

  const endTypeParsed = recurrenceEndTypeSchema.safeParse(formData.get("recurrence_end_type"));
  if (!endTypeParsed.success) {
    return { ok: false, error: "Choose a valid recurrence end condition." };
  }

  const endTimeParsed = optionalTimeHmSchema.safeParse(formData.get("recurrence_end_time"));
  if (!endTimeParsed.success) {
    return { ok: false, error: "Enter a valid end time." };
  }
  const endTimeHm = endTimeParsed.data;
  if (!/^\d{2}:\d{2}$/.test(endTimeHm)) {
    return { ok: false, error: "End time must use HH:MM format." };
  }

  const timePart = eventDateInput.includes("T") ? eventDateInput.split("T")[1] ?? "" : "";
  if (!/^\d{2}:\d{2}/.test(timePart)) {
    return { ok: false, error: "Event start time is invalid." };
  }
  const startHm = timePart.slice(0, 5);
  const [startH, startM] = startHm.split(":").map((x) => Number.parseInt(x, 10));
  const [endH, endM] = endTimeHm.split(":").map((x) => Number.parseInt(x, 10));
  const startTotal = startH * 60 + startM;
  const endTotal = endH * 60 + endM;
  if (endTotal <= startTotal) {
    return { ok: false, error: "End time must be after start time." };
  }
  const durationMinutes = endTotal - startTotal;

  let occurrenceCount: number | null = null;
  let untilDate: string | null = null;

  if (endTypeParsed.data === "after_count") {
    const rawCount = formData.get("recurrence_count");
    const count = typeof rawCount === "string" ? Number.parseInt(rawCount.trim(), 10) : Number.NaN;
    if (!Number.isInteger(count) || count < 1) {
      return { ok: false, error: "Occurrence count must be a whole number greater than zero." };
    }
    if (count > MAX_RECURRING_OCCURRENCES) {
      return { ok: false, error: `You can generate at most ${MAX_RECURRING_OCCURRENCES} occurrences at once.` };
    }
    occurrenceCount = count;
  } else {
    const untilParsed = optionalDateOnlySchema.safeParse(formData.get("recurrence_until_date"));
    if (!untilParsed.success) {
      return { ok: false, error: "Enter a valid recurrence end date." };
    }
    const value = untilParsed.data;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) {
      return { ok: false, error: "Recurrence end date must use YYYY-MM-DD." };
    }
    const untilMs = Date.parse(`${value}T23:59:59`);
    const startMs = Date.parse(eventDateInput);
    if (Number.isNaN(untilMs) || Number.isNaN(startMs)) {
      return { ok: false, error: "Recurrence dates are invalid." };
    }
    if (untilMs < startMs) {
      return { ok: false, error: "Recurrence end date must be on or after the first occurrence." };
    }
    untilDate = value;
  }

  return {
    ok: true,
    data: {
      frequency: frequencyParsed.data,
      endType: endTypeParsed.data,
      occurrenceCount,
      untilDate,
      durationMinutes,
      endTimeHm,
    },
  };
}

export const rsvpSchema = z.object({
  clubId: uuidSchema,
  eventId: uuidSchema,
  status: z.enum(["yes", "no", "maybe"]),
});

export const attendanceToggleSchema = z.object({
  clubId: uuidSchema,
  eventId: uuidSchema,
  userId: uuidSchema,
  present: z.enum(["true", "false"]).transform((value) => value === "true"),
});

export const eventReflectionSchema = z.object({
  clubId: uuidSchema,
  eventId: uuidSchema,
  whatWorked: plainTextSchema,
  whatDidnt: plainTextSchema,
  notes: optionalNotesSchema,
});

export const memberRoleUpdateSchema = z.object({
  clubId: uuidSchema,
  userId: uuidSchema,
  role: z.enum(["member", "officer"]),
});

export const memberRemovalSchema = z.object({
  clubId: uuidSchema,
  userId: uuidSchema,
});

export const memberMarkAlumniSchema = z.object({
  clubId: uuidSchema,
  userId: uuidSchema,
});

/** Bulk roster actions: cap selection size for predictable server work. */
export const bulkMemberUserIdsSchema = z
  .array(uuidSchema)
  .min(1, "Select at least one member.")
  .max(60, "You can select at most 60 members at a time.");

export const bulkMemberTagMutationSchema = z.object({
  clubId: uuidSchema,
  tagId: uuidSchema,
  userIds: bulkMemberUserIdsSchema,
});

export const bulkMemberCommitteeMutationSchema = z.object({
  clubId: uuidSchema,
  committeeId: uuidSchema,
  userIds: bulkMemberUserIdsSchema,
});

export const bulkMemberTeamMutationSchema = z.object({
  clubId: uuidSchema,
  teamId: uuidSchema,
  userIds: bulkMemberUserIdsSchema,
});

export const bulkMarkAlumniSchema = z.object({
  clubId: uuidSchema,
  userIds: bulkMemberUserIdsSchema,
  confirmation: z
    .string()
    .refine((s) => s.trim().toUpperCase() === "MARK ALUMNI", 'Type MARK ALUMNI to confirm.'),
});

export const bulkRemoveMembersSchema = z.object({
  clubId: uuidSchema,
  userIds: bulkMemberUserIdsSchema,
  /** Compared case-insensitively to the club name after trim (no aggressive sanitization). */
  confirmationClubName: z.string().trim().min(1, "Enter the club name to confirm.").max(200),
});

const clubContactPhoneSchema = z
  .string()
  .max(40, "Phone must be 40 characters or fewer.")
  .optional()
  .transform((s) => {
    const t = (s ?? "").trim();
    return t === "" ? null : t;
  })
  .superRefine((val, ctx) => {
    if (val === null) return;
    if (!/^[\d\s\-+().]{3,40}$/.test(val)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Use digits and common phone symbols only (spaces, +, -, parentheses).",
      });
    }
  });

export const clubMemberContactUpsertSchema = z.object({
  clubId: uuidSchema,
  phoneNumber: clubContactPhoneSchema,
  preferredContactMethod: z.enum(["email", "phone", "either"]).nullable().optional(),
});

const memberTagNameSchema = z
  .string()
  .transform((s) => sanitizeInlineText(s).trim().replace(/\s+/g, " "))
  .pipe(z.string().min(1, "Tag name is required.").max(40, "Tag name must be 40 characters or fewer."));

export const clubMemberTagCreateSchema = z.object({
  clubId: uuidSchema,
  name: memberTagNameSchema,
});

export const clubMemberTagAssignSchema = z.object({
  clubId: uuidSchema,
  tagId: uuidSchema,
  userId: uuidSchema,
});

export const clubMemberTagRemoveSchema = z.object({
  clubId: uuidSchema,
  tagId: uuidSchema,
  userId: uuidSchema,
});

export const clubMemberTagDeleteSchema = z.object({
  clubId: uuidSchema,
  tagId: uuidSchema,
});

const committeeNameSchema = z
  .string()
  .transform((s) => sanitizeInlineText(s).trim().replace(/\s+/g, " "))
  .pipe(z.string().min(1, "Committee name is required.").max(80, "Name must be 80 characters or fewer."));

export const clubCommitteeCreateSchema = z.object({
  clubId: uuidSchema,
  name: committeeNameSchema,
});

export const clubCommitteeRenameSchema = z.object({
  clubId: uuidSchema,
  committeeId: uuidSchema,
  name: committeeNameSchema,
});

export const clubCommitteeDeleteSchema = z.object({
  clubId: uuidSchema,
  committeeId: uuidSchema,
});

export const clubCommitteeAssignSchema = z.object({
  clubId: uuidSchema,
  committeeId: uuidSchema,
  userId: uuidSchema,
});

export const clubCommitteeRemoveMemberSchema = z.object({
  clubId: uuidSchema,
  committeeId: uuidSchema,
  userId: uuidSchema,
});

const teamNameSchema = z
  .string()
  .transform((s) => sanitizeInlineText(s).trim().replace(/\s+/g, " "))
  .pipe(z.string().min(1, "Team name is required.").max(80, "Name must be 80 characters or fewer."));

export const clubTeamCreateSchema = z.object({
  clubId: uuidSchema,
  name: teamNameSchema,
});

export const clubTeamRenameSchema = z.object({
  clubId: uuidSchema,
  teamId: uuidSchema,
  name: teamNameSchema,
});

export const clubTeamDeleteSchema = z.object({
  clubId: uuidSchema,
  teamId: uuidSchema,
});

export const clubTeamAssignSchema = z.object({
  clubId: uuidSchema,
  teamId: uuidSchema,
  userId: uuidSchema,
});

export const clubTeamRemoveMemberSchema = z.object({
  clubId: uuidSchema,
  teamId: uuidSchema,
  userId: uuidSchema,
});

const volunteerHoursStringSchema = z
  .string()
  .trim()
  .min(1, "Enter hours.")
  .refine((s) => /^\d+(\.\d{1,2})?$/.test(s), "Use a number with up to two decimal places (e.g. 2 or 2.5).")
  .transform((s) => Number.parseFloat(s))
  .pipe(z.number().positive("Hours must be greater than zero.").max(500, "Maximum 500 hours per entry."));

const volunteerHoursNoteOptionalSchema = z
  .string()
  .optional()
  .transform((raw) => {
    if (raw == null || raw.trim() === "") return undefined;
    const t = sanitizeMultilineText(raw).trim();
    if (t === "") return undefined;
    return t.length > 500 ? t.slice(0, 500) : t;
  });

const volunteerServiceDateSchema = z
  .string()
  .trim()
  .min(1, "Service date is required.")
  .regex(/^\d{4}-\d{2}-\d{2}$/, "Use a valid date.")
  .refine((s) => !Number.isNaN(Date.parse(`${s}T12:00:00Z`)), "Invalid calendar date.");

export const volunteerHoursAddSchema = z.object({
  clubId: uuidSchema,
  userId: uuidSchema,
  hours: volunteerHoursStringSchema,
  note: volunteerHoursNoteOptionalSchema,
  serviceDate: volunteerServiceDateSchema,
});

export const volunteerHoursUpdateSchema = z.object({
  clubId: uuidSchema,
  entryId: uuidSchema,
  hours: volunteerHoursStringSchema,
  note: volunteerHoursNoteOptionalSchema,
  serviceDate: volunteerServiceDateSchema,
});

export const volunteerHoursDeleteSchema = z.object({
  clubId: uuidSchema,
  entryId: uuidSchema,
});

const memberSkillInterestLabelSchema = z
  .string()
  .transform((s) => sanitizeInlineText(s).trim().replace(/\s+/g, " "))
  .pipe(
    z
      .string()
      .min(1, "Enter a skill or interest.")
      .max(80, "Keep it to 80 characters or fewer."),
  );

export const clubMemberSkillInterestAddSchema = z.object({
  clubId: uuidSchema,
  userId: uuidSchema,
  kind: z.enum(["skill", "interest"]),
  label: memberSkillInterestLabelSchema,
});

export const clubMemberSkillInterestDeleteSchema = z.object({
  clubId: uuidSchema,
  entryId: uuidSchema,
});

const availabilityTimeHmSchema = z
  .string()
  .trim()
  .regex(/^\d{2}:\d{2}$/, "Use a valid time.");

export const clubMemberAvailabilityAddSchema = z
  .object({
    clubId: uuidSchema,
    userId: uuidSchema,
    dayOfWeek: z.coerce.number().int().min(1).max(7),
    window: z.enum(["allday", "range"]),
    timeStart: z.string().optional(),
    timeEnd: z.string().optional(),
  })
  .superRefine((data, ctx) => {
    if (data.window !== "range") return;
    const ts = data.timeStart?.trim() ?? "";
    const te = data.timeEnd?.trim() ?? "";
    const tss = availabilityTimeHmSchema.safeParse(ts);
    const tes = availabilityTimeHmSchema.safeParse(te);
    if (!tss.success) {
      ctx.addIssue({ code: "custom", message: "Choose a valid start time.", path: ["timeStart"] });
      return;
    }
    if (!tes.success) {
      ctx.addIssue({ code: "custom", message: "Choose a valid end time.", path: ["timeEnd"] });
      return;
    }
    const [sh, sm] = ts.split(":").map((x) => Number.parseInt(x, 10));
    const [eh, em] = te.split(":").map((x) => Number.parseInt(x, 10));
    const startMin = sh * 60 + sm;
    const endMin = eh * 60 + em;
    if (endMin <= startMin) {
      ctx.addIssue({
        code: "custom",
        message: "End time must be after start time.",
        path: ["timeEnd"],
      });
    }
  })
  .transform((data) => ({
    clubId: data.clubId,
    userId: data.userId,
    dayOfWeek: data.dayOfWeek,
    timeStart: data.window === "allday" ? null : (data.timeStart?.trim() ?? null),
    timeEnd: data.window === "allday" ? null : (data.timeEnd?.trim() ?? null),
  }));

export const clubMemberAvailabilityDeleteSchema = z.object({
  clubId: uuidSchema,
  entryId: uuidSchema,
});

export const clubMemberOfficerNoteSetSchema = z.object({
  clubId: uuidSchema,
  targetUserId: uuidSchema,
  body: z
    .string()
    .transform((s) => sanitizeMultilineText(s))
    .pipe(z.string().max(4000, "Note must be 4000 characters or fewer.")),
});

const clubMemberDuesFormStatusSchema = z.enum([
  "unset",
  "unpaid",
  "paid",
  "partial",
  "exempt",
  "waived",
]);

export const clubMemberDuesSetSchema = z.object({
  clubId: uuidSchema,
  targetUserId: uuidSchema,
  status: clubMemberDuesFormStatusSchema,
  notes: z
    .string()
    .optional()
    .transform((s) => sanitizeMultilineText(s ?? ""))
    .pipe(z.string().max(500, "Notes must be 500 characters or fewer.")),
});

const duesCurrencyNormalized = z
  .union([z.string(), z.null(), z.undefined()])
  .transform((v) => {
    if (typeof v !== "string") return "USD";
    const t = sanitizeInlineText(v).trim().toUpperCase();
    return /^[A-Z]{3}$/.test(t) ? t : "USD";
  });

export const clubDuesSettingsUpsertSchema = z
  .object({
    clubId: uuidSchema,
    label: z
      .union([z.string(), z.null(), z.undefined()])
      .transform((v) => sanitizeInlineText(typeof v === "string" ? v : ""))
      .pipe(z.string().min(1, "Label is required.").max(200, "Label must be 200 characters or fewer.")),
    dueDate: z
      .union([z.string(), z.null(), z.undefined()])
      .transform((v) => (typeof v === "string" ? v.trim() : ""))
      .pipe(z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "Pick a valid due date.")),
    amount: z
      .union([z.string(), z.number(), z.null(), z.undefined()])
      .transform((v) => {
        if (v == null) return "";
        const raw = typeof v === "number" && Number.isFinite(v) ? String(v) : String(v);
        return sanitizeInlineText(raw).replace(/[$,\s]/g, "");
      })
      .pipe(
        z
          .string()
          .min(1, "Enter an amount.")
          .regex(/^\d+(\.\d{1,2})?$/, "Use a number with up to two decimal places (e.g. 20 or 20.50)."),
      )
      .transform((s) => Math.round(parseFloat(s) * 100))
      .pipe(
        z
          .number()
          .int("Amount must be a whole number of cents.")
          .min(0, "Amount cannot be negative.")
          .max(99_999_999, "Amount is too large."),
      ),
    currency: duesCurrencyNormalized,
  })
  .transform((d) => ({
    clubId: d.clubId,
    label: d.label,
    dueDate: d.dueDate,
    amountCents: d.amount,
    currency: d.currency,
  }));

const roleNameSchema = z
  .string()
  .transform(sanitizeInlineText)
  .pipe(z.string().min(1, "Role name is required.").max(50, "Name must be 50 characters or fewer."));

const roleDescriptionSchema = z
  .string()
  .transform(sanitizeInlineText)
  .pipe(z.string().max(200, "Description must be 200 characters or fewer."));

export const roleCreateSchema = z.object({
  clubId: uuidSchema,
  name: roleNameSchema,
  description: roleDescriptionSchema,
  /** Optional — if a valid template key is submitted, initial permissions are seeded from it. */
  templateKey: z
    .union([z.string(), z.null(), z.undefined()])
    .transform((v) => {
      if (typeof v !== "string") return undefined;
      const t = sanitizeInlineText(v).trim().slice(0, 64);
      return t === "" ? undefined : t;
    }),
});

export const roleUpdateSchema = z.object({
  clubId: uuidSchema,
  roleId: uuidSchema,
  name: roleNameSchema,
  description: roleDescriptionSchema,
});

export const roleDeleteSchema = z.object({
  clubId: uuidSchema,
  roleId: uuidSchema,
});

export const assignRoleSchema = z.object({
  clubId: uuidSchema,
  roleId: uuidSchema,
  targetUserId: uuidSchema,
});

export const removeRoleSchema = z.object({
  clubId: uuidSchema,
  roleId: uuidSchema,
  targetUserId: uuidSchema,
});

// ─── Governance (Presidency management) ──────────────────────────────────────

export const governanceAddSchema = z.object({
  clubId: uuidSchema,
  targetUserId: uuidSchema,
});

export const governanceRemoveSchema = z.object({
  clubId: uuidSchema,
  targetUserId: uuidSchema,
});

export const governanceTransferSchema = z.object({
  clubId: uuidSchema,
  targetUserId: uuidSchema,
});

// ─── Club lifecycle (leave / archive / delete) ───────────────────────────────

export const leaveClubSchema = z.object({
  clubId: uuidSchema,
});

export const clubJoinPolicySchema = z.object({
  clubId: uuidSchema,
  requireJoinApproval: z.enum(["true", "false"]),
});

export const joinRequestDecisionSchema = z.object({
  clubId: uuidSchema,
  requestId: uuidSchema,
});

const advisorReasonSchema = z
  .union([z.string(), z.null(), z.undefined()])
  .transform((v) => {
    if (v == null || typeof v !== "string") return null;
    const t = v.trim();
    if (!t) return null;
    return sanitizeInlineText(t).slice(0, 500);
  });

/** Approve/reject advisor flows (`entityId` is `event_id` or `announcement_id` depending on action). */
export const advisorDecisionSchema = z.object({
  clubId: uuidSchema,
  entityId: uuidSchema,
  reason: advisorReasonSchema,
});

export const clubAdvisorApprovalPolicySchema = z.object({
  clubId: uuidSchema,
  requireEventApproval: z.enum(["true", "false"]),
  requireAnnouncementApproval: z.enum(["true", "false"]),
});

export const archiveClubSchema = z.object({
  clubId: uuidSchema,
});

export const deleteClubSchema = z.object({
  clubId: uuidSchema,
  /** Must match the club name exactly (trimmed). */
  confirmName: z
    .string()
    .transform(sanitizeInlineText)
    .pipe(z.string().min(1, "Type the club name to confirm.")),
});

// ─── Tasks ────────────────────────────────────────────────────────────────────

const taskTitleSchema = z
  .string()
  .transform(sanitizeInlineText)
  .pipe(z.string().min(1, "Title is required.").max(200, "Title must be 200 characters or fewer."));

const taskDescriptionSchema = z
  .string()
  .transform(sanitizeMultilineText)
  .pipe(z.string().max(2000, "Description must be 2000 characters or fewer."));

const taskStatusSchema = z.enum(["todo", "in_progress", "blocked", "completed"]);
const taskPrioritySchema = z.enum(["low", "medium", "high", "urgent"]);

const taskDueAtFormFieldSchema = z
  .union([z.string(), z.null(), z.undefined()])
  .transform((v) => (typeof v === "string" ? v : ""))
  .pipe(z.string().max(48));

const taskAssigneeIdsFormFieldSchema = z
  .union([z.string(), z.null(), z.undefined()])
  .transform((v) => (typeof v === "string" ? v : ""))
  .pipe(z.string().max(MAX_TASK_ASSIGNEE_JSON_CHARS));

export const taskCreateSchema = z.object({
  clubId: uuidSchema,
  title: taskTitleSchema,
  description: taskDescriptionSchema.optional(),
  status: taskStatusSchema.default("todo"),
  priority: taskPrioritySchema.default("medium"),
  /** Raw due field from the form — validated with `parseTaskDueAtFormValue` in the action. */
  dueAt: taskDueAtFormFieldSchema,
  /** Raw JSON array string — validated with `parseTaskAssigneeIdsJson` in the action. */
  assigneeIds: taskAssigneeIdsFormFieldSchema,
});

export const taskUpdateSchema = z.object({
  clubId: uuidSchema,
  taskId: uuidSchema,
  title: taskTitleSchema,
  description: taskDescriptionSchema.optional(),
  status: taskStatusSchema,
  priority: taskPrioritySchema,
  dueAt: taskDueAtFormFieldSchema,
  assigneeIds: taskAssigneeIdsFormFieldSchema,
});

export const taskStatusUpdateSchema = z.object({
  clubId: uuidSchema,
  taskId: uuidSchema,
  status: taskStatusSchema,
});

export const taskDeleteSchema = z.object({
  clubId: uuidSchema,
  taskId: uuidSchema,
});

const memberImportEmailSchema = z
  .string()
  .trim()
  .min(1, "Email is required.")
  .email("Enter a valid email address.")
  .transform((s) => s.toLowerCase());

/** Body for confirming a CSV import — only emails that were "ready" in preview. */
export const memberImportCommitSchema = z.object({
  clubId: uuidSchema,
  /** Aligned with `MAX_DATA_ROWS` in member-import preview (single batch). */
  emails: z
    .array(memberImportEmailSchema)
    .max(300, "Too many rows in one import (max 300)."),
});
