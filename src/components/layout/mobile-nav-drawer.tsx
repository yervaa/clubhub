"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import type { UserClub } from "@/lib/clubs/queries";

const TOP_LINKS = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/clubs/create", label: "Create Club" },
  { href: "/clubs/join", label: "Join Club" },
  { href: "/notifications", label: "Notifications" },
] as const;

type MobileNavDrawerProps = {
  clubs: UserClub[];
};

export function MobileNavDrawer({ clubs }: MobileNavDrawerProps) {
  const [open, setOpen] = useState(false);
  const pathname = usePathname();

  useEffect(() => {
    if (!open) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = prev;
    };
  }, [open]);

  useEffect(() => {
    // Close after in-app navigations (e.g. client-side transitions) so the sheet never stays open on a new page.
    const id = requestAnimationFrame(() => setOpen(false));
    return () => cancelAnimationFrame(id);
  }, [pathname]);

  useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  return (
    <>
      <button
        type="button"
        className="inline-flex h-11 w-11 flex-shrink-0 items-center justify-center rounded-xl border border-slate-200 bg-white text-slate-700 shadow-sm transition hover:border-slate-300 hover:bg-slate-50 lg:hidden"
        aria-expanded={open}
        aria-controls="mobile-app-nav-drawer"
        aria-label={open ? "Close menu" : "Open menu"}
        onClick={() => setOpen((v) => !v)}
      >
        {open ? (
          <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden>
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        ) : (
          <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden>
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
          </svg>
        )}
      </button>

      {open ? (
        <div
          className="fixed inset-x-0 bottom-0 top-16 z-[55] lg:hidden"
          role="dialog"
          aria-modal="true"
          aria-label="App navigation"
        >
          <button
            type="button"
            className="absolute inset-0 bg-slate-900/45 backdrop-blur-[2px]"
            aria-label="Close menu"
            onClick={() => setOpen(false)}
          />
          <nav
            id="mobile-app-nav-drawer"
            className="absolute left-0 top-0 flex h-full w-[min(20rem,92vw)] flex-col border-r border-slate-200 bg-white shadow-2xl"
          >
            <div className="flex h-16 flex-shrink-0 items-center justify-between border-b border-slate-100 px-4">
              <span className="text-sm font-bold text-slate-900">Menu</span>
              <button
                type="button"
                className="flex h-10 w-10 items-center justify-center rounded-lg text-slate-500 hover:bg-slate-100"
                aria-label="Close menu"
                onClick={() => setOpen(false)}
              >
                <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            <div className="flex-1 overflow-y-auto overscroll-contain px-3 py-4">
              <p className="px-3 pb-2 text-xs font-semibold uppercase tracking-wider text-slate-400">Navigate</p>
              <ul className="space-y-0.5">
                {TOP_LINKS.map((link) => {
                  const active = pathname === link.href || pathname.startsWith(`${link.href}/`);
                  return (
                    <li key={link.href}>
                      <Link
                        href={link.href}
                        onClick={() => setOpen(false)}
                        aria-current={active ? "page" : undefined}
                        className={`block rounded-xl px-3 py-3 text-sm font-semibold transition ${
                          active ? "bg-slate-900 text-white" : "text-slate-700 hover:bg-slate-100"
                        }`}
                      >
                        {link.label}
                      </Link>
                    </li>
                  );
                })}
              </ul>

              {clubs.length > 0 ? (
                <>
                  <p className="mt-6 px-3 pb-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
                    Your clubs
                  </p>
                  <ul className="space-y-0.5">
                    {clubs.map((club) => {
                      const base = `/clubs/${club.id}`;
                      const active = pathname === base || pathname.startsWith(`${base}/`);
                      return (
                        <li key={club.id}>
                          <Link
                            href={base}
                            onClick={() => setOpen(false)}
                            className={`flex items-center gap-2 rounded-xl px-3 py-3 text-sm font-semibold transition ${
                              active ? "bg-slate-900 text-white" : "text-slate-700 hover:bg-slate-100"
                            }`}
                          >
                            <span className="min-w-0 flex-1 truncate">{club.name}</span>
                            {club.role === "officer" ? (
                              <span
                                className={`flex-shrink-0 rounded-full px-2 py-0.5 text-[10px] font-bold uppercase ${
                                  active ? "bg-white/20 text-white" : "bg-slate-200 text-slate-600"
                                }`}
                              >
                                Officer
                              </span>
                            ) : null}
                          </Link>
                        </li>
                      );
                    })}
                  </ul>
                </>
              ) : null}
            </div>
          </nav>
        </div>
      ) : null}
    </>
  );
}
