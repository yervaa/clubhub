import { z } from "zod";
import { sanitizeEmail, sanitizeInlineText } from "@/lib/sanitize";

export const loginSchema = z.object({
  email: z.email().transform(sanitizeEmail),
  password: z.string().trim().min(6).max(128),
});

export const signupSchema = z.object({
  fullName: z.string().min(2).max(80).transform(sanitizeInlineText),
  email: z.email().transform(sanitizeEmail),
  password: z.string().trim().min(6).max(128),
});

export const profileSchema = z.object({
  fullName: z.string().min(2).max(80).transform(sanitizeInlineText),
});
