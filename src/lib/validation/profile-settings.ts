import { z } from "zod";
import { sanitizeInlineText } from "@/lib/sanitize";

export const updateDisplayNameSchema = z.object({
  fullName: z.string().min(2, "Display name must be at least 2 characters.").max(80).transform(sanitizeInlineText),
});

export const changePasswordSchema = z
  .object({
    currentPassword: z.string().trim().min(6, "Current password must be at least 6 characters.").max(128),
    newPassword: z.string().trim().min(6, "New password must be at least 6 characters.").max(128),
    confirmPassword: z.string().trim().min(6).max(128),
  })
  .refine((data) => data.newPassword === data.confirmPassword, {
    message: "New passwords do not match.",
    path: ["confirmPassword"],
  })
  .refine((data) => data.currentPassword !== data.newPassword, {
    message: "New password must be different from your current password.",
    path: ["newPassword"],
  });
