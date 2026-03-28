import { z } from "zod";
import { EVENT_TYPE_OPTIONS } from "@/lib/events";
import { sanitizeCode, sanitizeInlineText, sanitizeMultilineText } from "@/lib/sanitize";

const uuidSchema = z.uuid("Invalid record identifier.");
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

const optionalNotesSchema = z.string().transform(sanitizeMultilineText).pipe(z.string().max(2000));

export const eventCreateSchema = z
  .object({
    clubId: uuidSchema,
    title: shortTitleSchema,
    description: plainTextSchema,
    location: shortInlineSchema,
    eventType: eventTypeSchema,
    eventDate: z.string().min(1),
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
  templateKey: z.string().optional(),
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

export const taskCreateSchema = z.object({
  clubId: uuidSchema,
  title: taskTitleSchema,
  description: taskDescriptionSchema.optional(),
  status: taskStatusSchema.default("todo"),
  priority: taskPrioritySchema.default("medium"),
  /** ISO-8601 date-time string or empty string (no due date). */
  dueAt: z.string().optional(),
  /** JSON-encoded array of user UUIDs. */
  assigneeIds: z.string().optional(),
});

export const taskUpdateSchema = z.object({
  clubId: uuidSchema,
  taskId: uuidSchema,
  title: taskTitleSchema,
  description: taskDescriptionSchema.optional(),
  status: taskStatusSchema,
  priority: taskPrioritySchema,
  dueAt: z.string().optional(),
  assigneeIds: z.string().optional(),
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
