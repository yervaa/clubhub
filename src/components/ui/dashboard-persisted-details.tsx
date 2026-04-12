"use client";

import { useEffect, useState, type ReactNode } from "react";

type DashboardPersistedDetailsProps = {
  storageKey: string;
  className: string;
  summary: ReactNode;
  children: ReactNode;
};

/**
 * Remembers open/closed state in localStorage. Renders closed until hydrated to avoid mismatch.
 */
export function DashboardPersistedDetails({ storageKey, className, summary, children }: DashboardPersistedDetailsProps) {
  const [open, setOpen] = useState(false);
  const [hydrated, setHydrated] = useState(false);

  useEffect(() => {
    try {
      const v = localStorage.getItem(storageKey);
      if (v === "1") setOpen(true);
      else if (v === "0") setOpen(false);
    } catch {
      /* ignore */
    }
    setHydrated(true);
  }, [storageKey]);

  useEffect(() => {
    if (!hydrated) return;
    try {
      localStorage.setItem(storageKey, open ? "1" : "0");
    } catch {
      /* ignore */
    }
  }, [open, hydrated, storageKey]);

  return (
    <details
      className={className}
      open={hydrated ? open : false}
      onToggle={(e) => {
        setOpen(e.currentTarget.open);
      }}
    >
      {summary}
      {children}
    </details>
  );
}
