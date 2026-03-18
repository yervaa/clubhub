"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { isRedirectError } from "next/dist/client/components/redirect-error";
import { enforceRateLimit, getRateLimitErrorMessage } from "@/lib/rate-limit";
import { createClient } from "@/lib/supabase/server";
import { loginSchema, profileSchema, signupSchema } from "@/lib/validation/auth";

function getAuthErrorMessage(error: unknown) {
  if (error instanceof Error && error.message.toLowerCase().includes("fetch failed")) {
    return "Network error reaching Supabase. Check your internet/DNS and try again.";
  }

  if (error instanceof Error) {
    return error.message;
  }

  return "Unexpected authentication error. Please try again.";
}

function normalizeSupabaseErrorMessage(message: string) {
  if (message.toLowerCase().includes("fetch failed")) {
    return "Network error reaching Supabase. Check your internet/DNS and try again.";
  }

  return message;
}

function getSafeValidationErrorMessage(result: { error: { issues: Array<{ message: string }> } }) {
  return result.error.issues[0]?.message ?? "Please review your input and try again.";
}

export async function loginAction(formData: FormData) {
  const parsed = loginSchema.safeParse({
    email: formData.get("email"),
    password: formData.get("password"),
  });

  if (!parsed.success) {
    redirect(`/login?error=${encodeURIComponent(getSafeValidationErrorMessage(parsed))}`);
  }

  const rateLimit = await enforceRateLimit({
    policy: "login",
    hint: parsed.data.email,
  });
  if (!rateLimit.success) {
    redirect(`/login?error=${encodeURIComponent(getRateLimitErrorMessage())}`);
  }

  try {
    const supabase = await createClient();
    const { error } = await supabase.auth.signInWithPassword(parsed.data);

    if (error) {
      redirect(`/login?error=${encodeURIComponent(normalizeSupabaseErrorMessage(error.message))}`);
    }
  } catch (error) {
    if (isRedirectError(error)) {
      throw error;
    }

    redirect(`/login?error=${encodeURIComponent(getAuthErrorMessage(error))}`);
  }

  redirect("/dashboard");
}

export async function signupAction(formData: FormData) {
  const parsed = signupSchema.safeParse({
    fullName: formData.get("full_name"),
    email: formData.get("email"),
    password: formData.get("password"),
  });

  if (!parsed.success) {
    redirect(`/signup?error=${encodeURIComponent(getSafeValidationErrorMessage(parsed))}`);
  }

  const rateLimit = await enforceRateLimit({
    policy: "signup",
    hint: parsed.data.email,
  });
  if (!rateLimit.success) {
    redirect(`/signup?error=${encodeURIComponent(getRateLimitErrorMessage())}`);
  }

  try {
    const supabase = await createClient();
    const safeProfile = profileSchema.parse({ fullName: parsed.data.fullName });
    const { data, error } = await supabase.auth.signUp({
      email: parsed.data.email,
      password: parsed.data.password,
      options: {
        data: { full_name: safeProfile.fullName },
      },
    });

    if (error) {
      redirect(`/signup?error=${encodeURIComponent(normalizeSupabaseErrorMessage(error.message))}`);
    }

    if (data.session) {
      redirect("/dashboard");
    }
  } catch (error) {
    if (isRedirectError(error)) {
      throw error;
    }

    redirect(`/signup?error=${encodeURIComponent(getAuthErrorMessage(error))}`);
  }

  redirect("/login?message=Check+your+email+to+confirm+your+account.");
}

export async function logoutAction() {
  const supabase = await createClient();
  await supabase.auth.signOut();
  revalidatePath("/", "layout");
  revalidatePath("/dashboard");
  revalidatePath("/clubs");
  redirect("/login?message=You+have+been+logged+out.");
}
