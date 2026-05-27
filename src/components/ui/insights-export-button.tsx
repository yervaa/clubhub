"use client";

import { downloadInsightsCsv, type InsightsExportPayload } from "@/lib/clubs/insights-export";

type InsightsExportButtonProps = {
  payload: InsightsExportPayload;
  disabled?: boolean;
};

export function InsightsExportButton({ payload, disabled = false }: InsightsExportButtonProps) {
  return (
    <button
      type="button"
      disabled={disabled}
      className="btn-secondary inline-flex items-center justify-center gap-2 px-3 py-2 text-sm font-semibold disabled:cursor-not-allowed disabled:opacity-60"
      onClick={() => downloadInsightsCsv(payload)}
    >
      <svg className="h-4 w-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden>
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={2}
          d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
        />
      </svg>
      Export CSV
    </button>
  );
}
