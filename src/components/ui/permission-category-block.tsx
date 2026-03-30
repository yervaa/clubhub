"use client";

import type { ReactNode } from "react";
import { useMediaLg } from "@/lib/hooks/use-media-lg";

type PermissionCategoryBlockProps = {
  category: string;
  headerRight?: ReactNode;
  children: ReactNode;
};

/** On mobile, collapses the permission category; on lg+ shows always-expanded section. */
export function PermissionCategoryBlock({ category, headerRight, children }: PermissionCategoryBlockProps) {
  const isLg = useMediaLg();

  if (isLg) {
    return (
      <div className="py-4 first:pt-0 last:pb-0">
        <div className="mb-3 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <p className="section-kicker text-slate-500">{category}</p>
          {headerRight}
        </div>
        {children}
      </div>
    );
  }

  return (
    <details className="group mb-3 rounded-xl border border-slate-100 bg-slate-50/50 open:border-slate-200 open:bg-white last:mb-0">
      <summary className="flex cursor-pointer list-none items-center justify-between gap-2 px-3 py-3 pr-4 [&::-webkit-details-marker]:hidden">
        <span className="section-kicker text-slate-600">{category}</span>
        <span className="flex-shrink-0 text-[10px] font-bold uppercase tracking-wider text-blue-600 group-open:hidden">
          Show
        </span>
        <span className="hidden flex-shrink-0 text-[10px] font-bold uppercase tracking-wider text-slate-500 group-open:inline">
          Hide
        </span>
      </summary>
      <div className="border-t border-slate-100 px-2 pb-3 pt-2">
        {headerRight ? <div className="mb-2 flex justify-end">{headerRight}</div> : null}
        {children}
      </div>
    </details>
  );
}
