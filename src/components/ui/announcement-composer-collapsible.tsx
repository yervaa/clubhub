"use client";

import { useEffect, useState, type ReactNode } from "react";

const COMPOSER_HASH = "#post-announcement";

type AnnouncementComposerCollapsibleProps = {
  /** When true, the full composer is visible on first paint (e.g. no announcements yet). */
  defaultOpen: boolean;
  children: ReactNode;
};

function hashTargetsComposer(): boolean {
  return typeof window !== "undefined" && window.location.hash === COMPOSER_HASH;
}

/**
 * Collapsed by default with a single entry CTA; expands to the server-rendered form as children.
 * Navigating to `#post-announcement` (e.g. sticky CTA) expands if currently collapsed.
 */
export function AnnouncementComposerCollapsible({ defaultOpen, children }: AnnouncementComposerCollapsibleProps) {
  const [open, setOpen] = useState(defaultOpen);

  useEffect(() => {
    function expandIfTargeted() {
      if (hashTargetsComposer()) {
        setOpen(true);
      }
    }

    expandIfTargeted();
    window.addEventListener("hashchange", expandIfTargeted);
    return () => window.removeEventListener("hashchange", expandIfTargeted);
  }, []);

  if (!open) {
    return (
      <div id="post-announcement" className="card-surface p-4 sm:p-5">
        <button
          type="button"
          onClick={() => setOpen(true)}
          className="flex w-full items-center justify-center gap-2 rounded-xl border border-dashed border-slate-300 bg-slate-50/80 px-4 py-4 text-sm font-semibold text-slate-800 transition hover:border-slate-400 hover:bg-slate-100/80"
        >
          <span className="text-lg leading-none text-slate-600" aria-hidden>
            +
          </span>
          New announcement
        </button>
      </div>
    );
  }

  return <div id="post-announcement">{children}</div>;
}
