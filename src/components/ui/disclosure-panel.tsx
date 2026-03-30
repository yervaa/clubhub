"use client";

import { useState, type ReactNode, type SyntheticEvent } from "react";

type DisclosurePanelProps = {
  /** Optional stable id for anchor links / a11y */
  id?: string;
  title: string;
  subtitle?: string;
  badge?: ReactNode;
  defaultOpen?: boolean;
  className?: string;
  summaryClassName?: string;
  children: ReactNode;
};

/**
 * Progressive disclosure panel — client component so open state toggles reliably after hydration.
 */
export function DisclosurePanel({
  id,
  title,
  subtitle,
  badge,
  defaultOpen = false,
  className = "",
  summaryClassName = "",
  children,
}: DisclosurePanelProps) {
  const [open, setOpen] = useState(defaultOpen);

  function handleToggle(e: SyntheticEvent<HTMLDetailsElement>) {
    setOpen(e.currentTarget.open);
  }

  return (
    <details
      id={id}
      className={`disclosure-panel group rounded-xl border border-slate-200/95 bg-slate-50/40 open:border-slate-300 open:bg-white ${className}`}
      open={open}
      onToggle={handleToggle}
    >
      <summary
        className={`disclosure-panel-summary flex cursor-pointer list-none items-start justify-between gap-3 p-4 pr-10 transition hover:bg-slate-100/60 [&::-webkit-details-marker]:hidden ${summaryClassName}`}
      >
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm font-semibold text-slate-900">{title}</span>
            {badge}
          </div>
          {subtitle ? <p className="mt-1 text-xs text-slate-600">{subtitle}</p> : null}
        </div>
        <span className="flex-shrink-0 pt-0.5 text-[10px] font-bold uppercase tracking-wider text-blue-600 group-open:hidden">
          Show
        </span>
        <span className="hidden flex-shrink-0 pt-0.5 text-[10px] font-bold uppercase tracking-wider text-slate-500 group-open:inline">
          Hide
        </span>
      </summary>
      <div className="disclosure-panel-body border-t border-slate-200/80 px-4 pb-4 pt-3">{children}</div>
    </details>
  );
}
