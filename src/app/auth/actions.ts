"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { isRedirectError } from "next/dist/client/components/redirect-error";
import { enforceRateLimit, getRateLimitErrorMessage } from "@/lib/rate-limit";
import { getSafeNextPath } from "@/lib/auth/redirects";
import { upsertCurrentUserProfile } from "@/lib/profiles";
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

/** Avoid leaking unusual Supabase/internal text; keep actionable messages short. */
function sanitizeAuthFlowError(message: string, flow: "login" | "signup"): string {
  const m = normalizeSupabaseErrorMessage(message);
  const ml = m.toLowerCase();

  if (flow === "login") {
    if (ml.includes("invalid login credentials") || ml.includes("invalid credentials")) {
      return "Invalid email or password.";
    }
  }

  if (m.length > 220) {
    return flow === "login"
      ? "Could not sign in. Please try again."
      : "Could not create your account. Please try again.";
  }

  return m;
}

function getSafeValidationErrorMessage(result: { error: { issues: Array<{ message: string }> } }) {
  return result.error.issues[0]?.message ?? "Please review your input and try again.";
}

export async function loginAction(formData: FormData) {
  const rawNext = formData.get("next");
  const nextPath = getSafeNextPath(
    typeof rawNext === "string" ? rawNext : null,
  );

  const parsed = loginSchema.safeParse({
    email: formData.get("email"),
    password: formData.get("password"),
  });

  if (!parsed.success) {
    redirect(`/login?error=${encodeURIComponent(getSafeValidationErrorMessage(parsed))}&next=${encodeURIComponent(nextPath)}`);
  }

  const rateLimit = await enforceRateLimit({
    policy: "login",
    hint: parsed.data.email,
  });
  if (!rateLimit.success) {
    redirect(`/login?error=${encodeURIComponent(getRateLimitErrorMessage())}&next=${encodeURIComponent(nextPath)}`);
  }

  try {
    const supabase = await createClient();
    const { data, error } = await supabase.auth.signInWithPassword(parsed.data);

    if (error) {
      redirect(
        `/login?error=${encodeURIComponent(sanitizeAuthFlowError(error.message, "login"))}&next=${encodeURIComponent(nextPath)}`,
      );
    }

    if (data.user) {
      const { error: profileError } = await upsertCurrentUserProfile(supabase, data.user);
      if (profileError) {
        redirect(`/login?error=Could+not+prepare+your+profile.+Please+retry.&next=${encodeURIComponent(nextPath)}`);
      }
    }
  } catch (error) {
    if (isRedirectError(error)) {
      throw error;
    }

    redirect(
      `/login?error=${encodeURIComponent(sanitizeAuthFlowError(getAuthErrorMessage(error), "login"))}&next=${encodeURIComponent(nextPath)}`,
    );
  }

  redirect(nextPath);
}

export async function signupAction(formData: FormData) {
  const rawNext = formData.get("next");
  const nextPath = getSafeNextPath(
    typeof rawNext === "string" ? rawNext : null,
  );

  const parsed = signupSchema.safeParse({
    fullName: formData.get("full_name"),
    email: formData.get("email"),
    password: formData.get("password"),
  });

  if (!parsed.success) {
    redirect(`/signup?error=${encodeURIComponent(getSafeValidationErrorMessage(parsed))}&next=${encodeURIComponent(nextPath)}`);
  }

  const rateLimit = await enforceRateLimit({
    policy: "signup",
    hint: parsed.data.email,
  });
  if (!rateLimit.success) {
    redirect(`/signup?error=${encodeURIComponent(getRateLimitErrorMessage())}&next=${encodeURIComponent(nextPath)}`);
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
      redirect(
        `/signup?error=${encodeURIComponent(sanitizeAuthFlowError(error.message, "signup"))}&next=${encodeURIComponent(nextPath)}`,
      );
    }

    if (data.session) {
      if (data.user) {
        const { error: profileError } = await upsertCurrentUserProfile(supabase, data.user);
        if (profileError) {
          redirect(`/signup?error=Could+not+prepare+your+profile.+Please+retry.&next=${encodeURIComponent(nextPath)}`);
        }
      }
      redirect(nextPath);
    }
  } catch (error) {
    if (isRedirectError(error)) {
      throw error;
    }

    redirect(
      `/signup?error=${encodeURIComponent(sanitizeAuthFlowError(getAuthErrorMessage(error), "signup"))}&next=${encodeURIComponent(nextPath)}`,
    );
  }

  redirect(`/login?message=Check+your+email+to+confirm+your+account.&next=${encodeURIComponent(nextPath)}`);
}

export async function logoutAction() {
  try {
    const supabase = await createClient();
    await supabase.auth.signOut();
  } catch {
    // Still send the user to login; session cookies may already be invalid.
  }
  revalidatePath("/", "layout");
  revalidatePath("/dashboard");
  revalidatePath("/clubs");
  redirect("/login?message=You+have+been+logged+out.");
}
