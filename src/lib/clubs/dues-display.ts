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
  if (!Number.isFinite(amountCents)) {
    return "—";
  }
  const cents = Math.max(0, Math.round(amountCents));
  const code = currency.trim().toUpperCase() || "USD";
  try {
    return new Intl.NumberFormat(undefined, {
      style: "currency",
      currency: code,
      minimumFractionDigits: cents % 100 === 0 ? 0 : 2,
      maximumFractionDigits: 2,
    }).format(cents / 100);
  } catch {
    return `${(cents / 100).toFixed(2)} ${code}`;
  }
}

export function formatClubDuesDueDateLabel(dueDateYmd: string): string {
  const raw = typeof dueDateYmd === "string" ? dueDateYmd.trim() : "";
  if (!raw) return "—";
  const [y, m, d] = raw.split("-").map(Number);
  if (!y || !m || !d) return raw;
  const dt = new Date(y, m - 1, d);
  if (Number.isNaN(dt.getTime())) return dueDateYmd;
  return dt.toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

/** Money + due date only (for stacked layouts where the label is shown separately). */
export function formatDuesTermMoneyAndDue(settings: ClubDuesSettings): string {
  const money = formatClubDuesMoney(settings.amountCents, settings.currency);
  const due = formatClubDuesDueDateLabel(settings.dueDate);
  return `${money} · Due ${due}`;
}

/** One-line summary: `Label · $20 · Due Sep 15, 2025` — use `title` for truncation in tight UI. */
export function formatDuesTermSummaryLine(settings: ClubDuesSettings): string {
  return `${settings.label} · ${formatDuesTermMoneyAndDue(settings)}`;
}
