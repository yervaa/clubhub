import Link from "next/link";
import { redirect } from "next/navigation";
import { signupAction } from "@/app/auth/actions";
import { createClient } from "@/lib/supabase/server";
import { Navbar } from "@/components/layout/navbar";

type SignupPageProps = {
  searchParams: Promise<{ error?: string }>;
};

export default async function SignupPage({ searchParams }: SignupPageProps) {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (user) {
    redirect("/dashboard");
  }

  const params = await searchParams;

  return (
    <div className="min-h-screen bg-slate-50">
      <Navbar />
      <main className="page-shell">
        <div className="card-surface max-w-lg p-8 sm:p-9">
          <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">Get Started</p>
          <h1 className="section-title mt-2">Sign up</h1>
          <p className="section-subtitle">Create your ClubHub account.</p>

          {params.error ? <p className="alert-error mt-6">{params.error}</p> : null}

          <form action={signupAction} className="mt-7 space-y-4">
            <div>
              <label htmlFor="full_name" className="mb-1.5 block text-sm font-medium text-slate-700">
                Full name
              </label>
              <input id="full_name" name="full_name" type="text" required className="input-control" placeholder="Jane Student" />
            </div>
            <div>
              <label htmlFor="email" className="mb-1.5 block text-sm font-medium text-slate-700">
                Email
              </label>
              <input id="email" name="email" type="email" required className="input-control" placeholder="you@school.edu" />
            </div>
            <div>
              <label htmlFor="password" className="mb-1.5 block text-sm font-medium text-slate-700">
                Password
              </label>
              <input
                id="password"
                name="password"
                type="password"
                required
                minLength={6}
                className="input-control"
                placeholder="At least 6 characters"
              />
            </div>
            <button type="submit" className="btn-primary w-full">
              Create account
            </button>
          </form>

          <p className="mt-6 text-sm text-slate-600">
            Already have an account?{" "}
            <Link href="/login" className="font-semibold text-slate-900 hover:text-slate-700">
              Log in
            </Link>
          </p>
        </div>
      </main>
    </div>
  );
}
