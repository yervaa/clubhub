"use client";

import { useCallback, useState } from "react";

type ClubJoinCodeRowProps = {
  joinCode: string;
};

export function ClubJoinCodeRow({ joinCode }: ClubJoinCodeRowProps) {
  const [copied, setCopied] = useState(false);

  const copy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(joinCode);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      /* ignore */
    }
  }, [joinCode]);

  return (
    <div className="mt-2 flex min-w-0 items-center gap-2 text-[11px] text-slate-500 sm:text-xs">
      <span className="shrink-0">Code</span>
      <span
        className="min-w-0 truncate font-mono font-semibold tracking-wider text-slate-700"
        title={joinCode}
      >
        {joinCode}
      </span>
      <button
        type="button"
        onClick={copy}
        className="shrink-0 rounded-md border border-slate-200 bg-white px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-slate-600 transition hover:border-slate-300 hover:bg-slate-50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-blue-500"
      >
        {copied ? "Copied" : "Copy"}
      </button>
    </div>
  );
}
