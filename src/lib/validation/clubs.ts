import { z } from "zod";
import { sanitizeCode, sanitizeInlineText, sanitizeMultilineText } from "@/lib/sanitize";

const uuidSchema = z.uuid("Invalid record identifier.");
const roleSchema = z.enum(["member", "officer"]);

export const clubCreateSchema = z.object({
  name: z.string().min(2).max(80).transform(sanitizeInlineText),
  description: z.string().min(10).max(500).transform(sanitizeMultilineText),
});

export const joinCodeSchema = z.object({
  joinCode: z
    .string()
    .transform(sanitizeCode)
    .refine((value) => /^[A-Z0-9]{8}$/.test(value), "Enter a valid join code."),
});

export const announcementCreateSchema = z.object({
  clubId: uuidSchema,
  title: z.string().min(2).max(120).transform(sanitizeInlineText),
  content: z.string().min(2).max(2000).transform(sanitizeMultilineText),
});

export const eventCreateSchema = z
  .object({
    clubId: uuidSchema,
    title: z.string().min(2).max(120).transform(sanitizeInlineText),
    description: z.string().min(2).max(2000).transform(sanitizeMultilineText),
    location: z.string().min(2).max(160).transform(sanitizeInlineText),
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

export const clubMembershipSchema = z.object({
  clubId: uuidSchema,
  userId: uuidSchema,
  role: roleSchema,
});
