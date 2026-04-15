import type { ClubDuesSettings, ClubMemberDuesStatus } from "@/lib/clubs/queries";

/** `YYYY-MM-DD` in the viewer's local calendar — for comparing to `due_date` from the DB. */
export function localCalendarDateYmd(): string {
  const t = new Date();
  const y = t.getFullYear();
  const m = String(t.getMonth() + 1).padStart(2, "0");
  const d = String(t.getDate()).padStart(2, "0");
  return `${y}-${m}-${d}`;
}

/** Unpaid status and calendar today strictly after the due date (due day is not overdue). */
export function isUnpaidDuesPastDue(status: ClubMemberDuesStatus, dueDateYmd: string | null | undefined): boolean {
  if (status !== "unpaid" || !dueDateYmd) return false;
  return localCalendarDateYmd() > dueDateYmd;
}

export function formatClubDuesMoney(amountCents: number, currency: string): string {
  const code = currency.trim().toUpperCase() || "USD";
  try {
    return new Intl.NumberFormat(undefined, {
      style: "currency",
      currency: code,
      minimumFractionDigits: amountCents % 100 === 0 ? 0 : 2,
      maximumFractionDigits: 2,
    }).format(amountCents / 100);
  } catch {
    return `${(amountCents / 100).toFixed(2)} ${code}`;
  }
}

export function formatClubDuesDueDateLabel(dueDateYmd: string): string {
  const [y, m, d] = dueDateYmd.split("-").map(Number);
  if (!y || !m || !d) return dueDateYmd;
  const dt = new Date(y, m - 1, d);
  if (Number.isNaN(dt.getTime())) return dueDateYmd;
  return dt.toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

/** One-line summary for profile: `Label · $20 · Due Sep 15, 2025` */
export function formatDuesTermSummaryLine(settings: ClubDuesSettings): string {
  const money = formatClubDuesMoney(settings.amountCents, settings.currency);
  const due = formatClubDuesDueDateLabel(settings.dueDate);
  return `${settings.label} · ${money} · Due ${due}`;
}
