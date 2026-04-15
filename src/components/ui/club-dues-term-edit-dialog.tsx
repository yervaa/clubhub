"use client";

import { useRouter } from "next/navigation";
import { useEffect, useId, useRef, useState } from "react";
import { upsertClubDuesSettingsAction } from "@/app/(app)/clubs/club-dues-settings-actions";
import { formatDuesTermMoneyAndDue } from "@/lib/clubs/dues-display";
import type { ClubDuesSettings } from "@/lib/clubs/queries";

function centsToAmountFieldValue(cents: number): string {
  if (!Number.isFinite(cents) || cents < 0) return "";
  if (cents % 100 === 0) return String(Math.round(cents / 100));
  return (cents / 100).toFixed(2);
}

type ClubDuesTermEditDialogProps = {
  open: boolean;
  onClose: () => void;
  clubId: string;
  isArchived: boolean;
  initial: ClubDuesSettings | null;
};

export function ClubDuesTermEditDialog({ open, onClose, clubId, isArchived, initial }: ClubDuesTermEditDialogProps) {
  const router = useRouter();
  const titleId = useId();
  const descId = useId();
  const [label, setLabel] = useState(() => initial?.label ?? "");
  const [amount, setAmount] = useState(() => (initial ? centsToAmountFieldValue(initial.amountCents) : ""));
  const [dueDate, setDueDate] = useState(() => initial?.dueDate ?? "");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const labelInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!open) return;
    const t = window.setTimeout(() => {
      labelInputRef.current?.focus({ preventScroll: true });
    }, 0);
    return () => window.clearTimeout(t);
  }, [open]);

  useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (isArchived) return;
    setError(null);
    setPending(true);
    const fd = new FormData();
    fd.set("club_id", clubId);
    fd.set("label", label);
    fd.set("amount", amount);
    fd.set("due_date", dueDate);
    fd.set("currency", "USD");
    const r = await upsertClubDuesSettingsAction(fd);
    setPending(false);
    if (r.ok) {
      router.refresh();
      onClose();
    } else {
      setError(r.error);
    }
  }

  const preview =
    label.trim() && amount.trim() && /^\d{4}-\d{2}-\d{2}$/.test(dueDate.trim())
      ? (() => {
          const cents = Math.round(parseFloat(amount.replace(/[$,\s]/g, "")) * 100);
          if (!Number.isFinite(cents) || cents < 0) return null;
          const fake: ClubDuesSettings = {
            clubId,
            label: label.trim(),
            amountCents: cents,
            dueDate: dueDate.trim(),
            currency: "USD",
            updatedAt: null,
          };
          return fake;
        })()
      : null;

  return (
    <div className="fixed inset-0 z-[110] flex items-end justify-center p-0 sm:items-center sm:p-4" role="presentation">
      <button
        type="button"
        className="absolute inset-0 bg-slate-900/45 backdrop-blur-[2px] transition hover:bg-slate-900/55"
        aria-label="Close dues term editor"
        onClick={onClose}
      />
      <div
        className="relative z-10 flex max-h-[min(92vh,640px)] w-full max-w-lg flex-col overflow-hidden rounded-t-2xl border border-slate-200/95 bg-white shadow-2xl sm:max-h-[90vh] sm:rounded-2xl"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descId}
      >
        <div className="flex shrink-0 items-start justify-between gap-3 border-b border-slate-100 bg-gradient-to-br from-slate-50 to-indigo-50/50 px-5 py-4 sm:px-6 sm:py-5">
          <div className="min-w-0">
            <p className="section-kicker text-slate-600">Club dues</p>
            <h2 id={titleId} className="mt-1 text-lg font-semibold tracking-tight text-slate-900 sm:text-xl">
              {initial ? "Edit club dues term" : "Set club dues term"}
            </h2>
            <p id={descId} className="mt-2 text-sm leading-relaxed text-slate-600">
              One amount and due date for everyone. Member Paid / Unpaid / Partial still lives on each profile — this
              only defines what they are paying toward.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="flex h-10 min-w-10 shrink-0 items-center justify-center rounded-xl text-slate-500 transition hover:bg-white/80 hover:text-slate-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-400 focus-visible:ring-offset-2"
            aria-label="Close dues term dialog"
          >
            <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <form
          onSubmit={onSubmit}
          className="min-h-0 flex-1 space-y-4 overflow-y-auto px-5 py-4 sm:px-6 sm:py-5"
        >
          {error ? (
            <div
              className="rounded-xl border border-rose-200/90 bg-rose-50 px-3 py-2.5 text-sm text-rose-900"
              role="alert"
            >
              {error}
            </div>
          ) : null}
          {isArchived ? (
            <p className="rounded-lg border border-amber-200 bg-amber-50/90 px-3 py-2 text-sm font-medium text-amber-950">
              This club is archived — dues term cannot be changed.
            </p>
          ) : null}

          <div>
            <div className="flex items-end justify-between gap-2">
              <label htmlFor="dues-term-label" className="block text-xs font-semibold text-slate-700">
                Term label
              </label>
              <span className="text-[10px] font-medium tabular-nums text-slate-400">{label.length} / 200</span>
            </div>
            <input
              ref={labelInputRef}
              id="dues-term-label"
              name="label"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              maxLength={200}
              required
              disabled={isArchived}
              placeholder="e.g. 2025–26 membership"
              className="input-control mt-1.5 w-full min-h-11 text-sm"
            />
            <p className="mt-1 text-[11px] leading-relaxed text-slate-500">
              Shown on the Members summary card and on profiles (wraps automatically; very long names truncate on the
              roster card).
            </p>
          </div>

          <div>
            <label htmlFor="dues-term-amount" className="block text-xs font-semibold text-slate-700">
              Amount (USD)
            </label>
            <input
              id="dues-term-amount"
              name="amount"
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
              inputMode="decimal"
              autoComplete="off"
              required
              disabled={isArchived}
              placeholder="20 or 15.50"
              className="input-control mt-1.5 w-full min-h-11 text-sm tabular-nums"
            />
            <p className="mt-1 text-[11px] leading-relaxed text-slate-500">Whole dollars or cents, up to two decimal places.</p>
          </div>

          <div>
            <label htmlFor="dues-term-due" className="block text-xs font-semibold text-slate-700">
              Due date
            </label>
            <input
              id="dues-term-due"
              name="due_date"
              type="date"
              value={dueDate}
              onChange={(e) => setDueDate(e.target.value)}
              required
              disabled={isArchived}
              className="input-control mt-1.5 w-full min-h-11 text-sm"
            />
            <p className="mt-1 text-[11px] leading-relaxed text-slate-500">
              Used for the <span className="font-medium text-slate-700">Past due</span> roster chip when someone is still{" "}
              <span className="font-medium text-slate-700">Unpaid</span> after this day.
            </p>
          </div>

          {preview ? (
            <div className="rounded-xl border border-emerald-100/90 bg-gradient-to-br from-emerald-50/90 to-white px-3 py-3 sm:px-4">
              <p className="text-[10px] font-bold uppercase tracking-wider text-emerald-900/80">Preview on profiles</p>
              <p className="mt-1.5 break-words text-sm font-semibold leading-snug text-slate-900" title={preview.label}>
                {preview.label}
              </p>
              <p className="mt-1 text-sm text-slate-600">{formatDuesTermMoneyAndDue(preview)}</p>
              <p className="mt-2 text-[11px] leading-relaxed text-slate-500">
                Matches the Members page summary and the “Club dues term” block on each profile.
              </p>
            </div>
          ) : null}

          <div className="flex flex-wrap gap-2 border-t border-slate-100 pt-4">
            <button type="submit" className="btn-primary min-h-10 px-5 text-sm font-semibold" disabled={isArchived || pending}>
              {pending ? "Saving…" : "Save term"}
            </button>
            <button type="button" className="btn-secondary min-h-10 px-4 text-sm" onClick={onClose} disabled={pending}>
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
