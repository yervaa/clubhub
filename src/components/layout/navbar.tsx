import Link from "next/link";
import { unstable_noStore as noStore } from "next/cache";
import { logoutAction } from "@/app/auth/actions";
import { createClient } from "@/lib/supabase/server";

export async function Navbar() {
  noStore();

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  return (
    <header className="sticky top-0 z-30 border-b border-slate-200/80 bg-white/90 shadow-sm backdrop-blur">
      <nav className="mx-auto flex h-16 w-full max-w-7xl items-center justify-between px-4 sm:px-6">
        <Link href="/" className="flex items-center gap-3 text-slate-900">
          <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-slate-900 text-sm font-bold text-white">CH</span>
          <span className="text-lg font-bold tracking-tight">ClubHub</span>
        </Link>
        <ul className="flex items-center gap-2 sm:gap-3">
          <li>
            <Link
              href="/"
              className="rounded-md px-3 py-2 text-sm font-medium text-slate-600 transition hover:bg-slate-100 hover:text-slate-900"
            >
              Home
            </Link>
          </li>
          {user ? (
            <>
              <li>
                <Link
                  href="/dashboard"
                  className="rounded-md px-3 py-2 text-sm font-medium text-slate-600 transition hover:bg-slate-100 hover:text-slate-900"
                >
                  Dashboard
                </Link>
              </li>
              <li className="hidden rounded-full bg-slate-100 px-3 py-1.5 text-sm text-slate-600 sm:block">{user.email}</li>
              <li>
                <form action={logoutAction}>
                  <button
                    type="submit"
                    className="rounded-md px-3 py-2 text-sm font-medium text-slate-600 transition hover:bg-slate-100 hover:text-slate-900"
                  >
                    Logout
                  </button>
                </form>
              </li>
            </>
          ) : (
            <>
              <li>
                <Link
                  href="/login"
                  className="rounded-md px-3 py-2 text-sm font-medium text-slate-600 transition hover:bg-slate-100 hover:text-slate-900"
                >
                  Login
                </Link>
              </li>
              <li>
                <Link
                  href="/signup"
                  className="rounded-md px-3 py-2 text-sm font-medium text-slate-600 transition hover:bg-slate-100 hover:text-slate-900"
                >
                  Sign up
                </Link>
              </li>
            </>
          )}
        </ul>
      </nav>
    </header>
  );
}
