"use client";

import { useRouter } from "next/navigation";
import { useEffect, useId, useState } from "react";
import { upsertClubDuesSettingsAction } from "@/app/(app)/clubs/club-dues-settings-actions";
import { formatClubDuesDueDateLabel, formatClubDuesMoney } from "@/lib/clubs/dues-display";
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
          return `${fake.label} · ${formatClubDuesMoney(fake.amountCents, fake.currency)} · Due ${formatClubDuesDueDateLabel(fake.dueDate)}`;
        })()
      : null;

  return (
    <div className="fixed inset-0 z-[110] flex items-end justify-center p-0 sm:items-center sm:p-4" role="presentation">
      <button
        type="button"
        className="absolute inset-0 bg-slate-900/50 backdrop-blur-[2px]"
        aria-label="Close dues term editor"
        onClick={onClose}
      />
      <div
        className="relative z-10 w-full max-w-lg rounded-t-2xl border border-slate-200 bg-white shadow-2xl sm:rounded-2xl"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descId}
      >
        <div className="flex items-start justify-between gap-3 border-b border-slate-100 px-5 py-4 sm:px-6">
          <div className="min-w-0">
            <h2 id={titleId} className="text-lg font-semibold tracking-tight text-slate-900">
              {initial ? "Edit dues term" : "Set dues term"}
            </h2>
            <p id={descId} className="mt-1 text-sm text-slate-600">
              One amount and due date for the whole club. Member paid/unpaid is still tracked separately on each profile.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="flex h-9 min-w-9 shrink-0 items-center justify-center rounded-lg text-slate-500 transition hover:bg-slate-100 hover:text-slate-800"
            aria-label="Close"
          >
            <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <form onSubmit={onSubmit} className="space-y-4 px-5 py-4 sm:px-6 sm:py-5">
          {error ? <p className="text-sm text-red-700">{error}</p> : null}
          {isArchived ? (
            <p className="text-sm font-medium text-amber-900">This club is archived — dues settings cannot be changed.</p>
          ) : null}

          <div>
            <label htmlFor="dues-term-label" className="block text-xs font-semibold text-slate-700">
              Label
            </label>
            <input
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
              placeholder="e.g. 20 or 15.50"
              className="input-control mt-1.5 w-full min-h-11 text-sm"
            />
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
          </div>

          {preview ? (
            <p className="rounded-lg border border-teal-100 bg-teal-50/80 px-3 py-2 text-xs leading-relaxed text-teal-950">
              <span className="font-semibold">Preview:</span> {preview}
            </p>
          ) : null}

          <div className="flex flex-wrap gap-2 border-t border-slate-100 pt-4">
            <button type="submit" className="btn-primary min-h-10 px-4 text-sm font-semibold" disabled={isArchived || pending}>
              {pending ? "Saving…" : "Save"}
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
