import { z } from "zod";

const hhmmRegex = /^([01]\d|2[0-3]):([0-5]\d)$/;

export const notificationPreferencesFormSchema = z
  .object({
    in_app_announcements: z.boolean(),
    email_announcements: z.boolean(),
    in_app_events: z.boolean(),
    email_events: z.boolean(),
    in_app_reminders: z.boolean(),
    email_reminders: z.boolean(),
    in_app_role_membership: z.boolean(),
    email_role_membership: z.boolean(),
    in_app_activity: z.boolean(),
    email_activity: z.boolean(),
    quiet_hours_enabled: z.boolean(),
    quiet_hours_start: z.string().optional(),
    quiet_hours_end: z.string().optional(),
    timezone: z.string().trim().min(1).max(100),
    weekly_digest_enabled: z.boolean(),
  })
  .superRefine((data, ctx) => {
    if (!data.quiet_hours_enabled) return;
    const start = data.quiet_hours_start?.trim() ?? "";
    const end = data.quiet_hours_end?.trim() ?? "";
    if (!hhmmRegex.test(start)) {
      ctx.addIssue({
        code: "custom",
        message: "Quiet hours need a valid start time (HH:MM).",
        path: ["quiet_hours_start"],
      });
    }
    if (!hhmmRegex.test(end)) {
      ctx.addIssue({
        code: "custom",
        message: "Quiet hours need a valid end time (HH:MM).",
        path: ["quiet_hours_end"],
      });
    }
  });

export type NotificationPreferencesFormValues = z.infer<typeof notificationPreferencesFormSchema>;
