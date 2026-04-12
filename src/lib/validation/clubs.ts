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
