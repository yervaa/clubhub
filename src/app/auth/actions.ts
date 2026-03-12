"use server";

import { redirect } from "next/navigation";
import { isRedirectError } from "next/dist/client/components/redirect-error";
import { createClient } from "@/lib/supabase/server";

function getStringValue(formData: FormData, key: string) {
  const value = formData.get(key);
  return typeof value === "string" ? value.trim() : "";
}

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

export async function loginAction(formData: FormData) {
  const email = getStringValue(formData, "email");
  const password = getStringValue(formData, "password");

  if (!email || !password) {
    redirect("/login?error=Please+enter+email+and+password.");
  }

  try {
    const supabase = await createClient();
    const { error } = await supabase.auth.signInWithPassword({ email, password });

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
  const fullName = getStringValue(formData, "full_name");
  const email = getStringValue(formData, "email");
  const password = getStringValue(formData, "password");

  if (!fullName || !email || !password) {
    redirect("/signup?error=Please+fill+all+fields.");
  }

  try {
    const supabase = await createClient();
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: { full_name: fullName },
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
  redirect("/login?message=You+have+been+logged+out.");
}
