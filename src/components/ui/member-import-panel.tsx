"use client";

import { useCallback, useState } from "react";
import {
  commitMemberImportAction,
  previewMemberImportAction,
  type MemberImportCommitResult,
  type MemberImportPreviewResult,
  type MemberImportPreviewRow,
} from "@/app/(app)/clubs/member-import-actions";

type Step = "upload" | "preview" | "done";

function statusLabel(status: MemberImportPreviewRow["status"]): string {
  switch (status) {
    case "ready":
      return "Ready to add";
    case "invalid_email":
      return "Invalid email";
    case "missing_email":
      return "Missing email";
    case "duplicate_in_file":
      return "Duplicate in file";
    case "no_profile":
      return "No ClubHub account";
    case "already_member":
      return "Already in club";
    default:
      return status;
  }
}

function PreviewTable({
  title,
  rows,
  variant,
  rowKey,
}: {
  title: string;
  rows: MemberImportPreviewRow[];
  variant: "ok" | "warn" | "neutral";
  rowKey: (r: MemberImportPreviewRow) => string;
}) {
  if (rows.length === 0) return null;

  const border =
    variant === "ok"
      ? "border-emerald-200/90 bg-emerald-50/50"
      : variant === "warn"
        ? "border-amber-200/90 bg-amber-50/40"
        : "border-slate-200/90 bg-slate-50/60";

  return (
    <div className={`rounded-xl border p-4 ${border}`}>
      <p className="text-sm font-semibold text-slate-900">{title}</p>
      <p className="mt-1 text-xs text-slate-600">{rows.length} row{rows.length === 1 ? "" : "s"}</p>
      <div className="mt-3 max-h-52 overflow-auto rounded-lg border border-slate-200/80 bg-white">
        <table className="min-w-full text-left text-xs">
          <thead className="sticky top-0 bg-slate-100/95 text-[0.65rem] font-semibold uppercase tracking-wide text-slate-600">
            <tr>
              <th className="px-3 py-2">Line</th>
              <th className="px-3 py-2">Email</th>
              <th className="px-3 py-2">Label (CSV / profile)</th>
              <th className="px-3 py-2">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {rows.map((r) => (
              <tr key={rowKey(r)} className="text-slate-800">
                <td className="whitespace-nowrap px-3 py-2 font-mono text-[0.7rem] text-slate-500">{r.rowNumber}</td>
                <td className="px-3 py-2 font-mono text-[0.7rem]">{r.emailRaw || "—"}</td>
                <td className="px-3 py-2 text-slate-600">
                  {r.labelFromCsv || r.resolvedFullName || "—"}
                </td>
                <td className="px-3 py-2 text-slate-700">{statusLabel(r.status)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function MemberImportPanel({ clubId }: { clubId: string }) {
  const [step, setStep] = useState<Step>("upload");
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<MemberImportPreviewResult | null>(null);
  const [commitResult, setCommitResult] = useState<MemberImportCommitResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reset = useCallback(() => {
    setStep("upload");
    setFile(null);
    setPreview(null);
    setCommitResult(null);
    setError(null);
    setBusy(false);
  }, []);

  async function onParse() {
    setError(null);
    if (!file) {
      setError("Choose a CSV file first.");
      return;
    }
    setBusy(true);
    try {
      const fd = new FormData();
      fd.set("clubId", clubId);
      fd.set("file", file);
      const result = await previewMemberImportAction(fd);
      if (!result.ok) {
        setError(result.error);
        return;
      }
      setPreview(result);
      setStep("preview");
    } finally {
      setBusy(false);
    }
  }

  async function onConfirm() {
    if (!preview?.ok) return;
    setError(null);
    setBusy(true);
    try {
      const result = await commitMemberImportAction({
        clubId,
        emails: preview.readyEmails,
      });
      setCommitResult(result);
      if (!result.ok) {
        setError(result.error);
        return;
      }
      setStep("done");
    } finally {
      setBusy(false);
    }
  }

  const rows = preview?.ok ? preview.rows : [];
  const readyRows = rows.filter((r) => r.status === "ready");
  const problemRows = rows.filter((r) => r.status !== "ready");

  return (
    <div className="mt-4 w-full rounded-2xl border-2 border-indigo-200/80 bg-gradient-to-br from-white to-indigo-50/40 p-4 sm:p-5">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-indigo-800">Leadership</p>
          <h3 className="mt-1 text-base font-semibold text-slate-900">Import member list (CSV)</h3>
          <p className="mt-2 max-w-2xl text-sm text-slate-700">
            Add people who already have ClubHub accounts. Each row is checked before anything is written. Unknown emails
            and people already in this club are skipped. This does not create new user accounts or send invitations.
          </p>
        </div>
        {step !== "upload" ? (
          <button type="button" className="btn-secondary shrink-0 px-3 py-2 text-sm font-semibold" onClick={reset}>
            Start over
          </button>
        ) : null}
      </div>

      {error ? (
        <p className="mt-4 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-900" role="alert">
          {error}
        </p>
      ) : null}

      {step === "upload" ? (
        <div className="mt-5 space-y-4">
          <div>
            <label htmlFor={`member-import-file-${clubId}`} className="mb-2 block text-sm font-semibold text-slate-800">
              CSV file
            </label>
            <input
              id={`member-import-file-${clubId}`}
              type="file"
              accept=".csv,text/csv"
              className="block w-full max-w-md text-sm text-slate-700 file:mr-3 file:rounded-lg file:border-0 file:bg-indigo-600 file:px-4 file:py-2 file:text-sm file:font-semibold file:text-white hover:file:bg-indigo-700"
              disabled={busy}
              onChange={(e) => {
                setFile(e.target.files?.[0] ?? null);
              }}
            />
            <p className="mt-2 text-xs text-slate-600">
              Required header: <span className="font-mono">email</span>. Optional:{" "}
              <span className="font-mono">full_name</span>, <span className="font-mono">name</span>, or{" "}
              <span className="font-mono">display name</span> (preview only). Max 300 data rows, 256 KB.
            </p>
          </div>
          <button type="button" className="btn-primary px-5 py-2.5 text-sm font-semibold" disabled={busy} onClick={onParse}>
            {busy ? "Checking…" : "Upload & validate"}
          </button>
        </div>
      ) : null}

      {step === "preview" && preview?.ok ? (
        <div className="mt-5 space-y-4">
          <div className="rounded-xl border border-slate-200 bg-white/80 p-4 text-sm text-slate-800">
            <p className="font-semibold text-slate-900">Validation summary</p>
            <ul className="mt-2 list-inside list-disc space-y-1 text-slate-700">
              <li>
                <span className="font-semibold text-emerald-800">{preview.summary.ready}</span> will be added as members
              </li>
              <li>{preview.summary.alreadyMember} already in this club (skipped)</li>
              <li>{preview.summary.noProfile} no matching ClubHub account (skipped)</li>
              <li>{preview.summary.duplicateInFile} duplicate emails in the file (skipped)</li>
              <li>{preview.summary.invalidEmail} invalid email format</li>
              <li>{preview.summary.missingEmail} rows missing an email</li>
              {preview.summary.skippedBlankRows > 0 ? (
                <li>{preview.summary.skippedBlankRows} blank rows ignored</li>
              ) : null}
            </ul>
          </div>

          <PreviewTable
            title="Will be imported"
            rows={readyRows}
            variant="ok"
            rowKey={(r) => `${r.rowNumber}-${r.emailNormalized ?? "row"}`}
          />
          <PreviewTable
            title="Will not be imported"
            rows={problemRows}
            variant="warn"
            rowKey={(r) => `${r.rowNumber}-${r.status}-${r.emailRaw || "empty"}`}
          />

          <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
            <button
              type="button"
              className="btn-primary px-5 py-2.5 text-sm font-semibold disabled:cursor-not-allowed disabled:opacity-60"
              disabled={busy || preview.readyEmails.length === 0}
              onClick={onConfirm}
            >
              {busy ? "Importing…" : `Confirm import (${preview.readyEmails.length})`}
            </button>
            {preview.readyEmails.length === 0 ? (
              <p className="text-sm text-slate-600">No rows are eligible — fix the file or add accounts first.</p>
            ) : (
              <p className="text-sm text-slate-600">Only the &quot;Ready to add&quot; rows are written. You can still cancel by leaving this page.</p>
            )}
          </div>
        </div>
      ) : null}

      {step === "done" && commitResult?.ok ? (
        <div className="mt-5 rounded-xl border border-emerald-200 bg-emerald-50/70 p-4 text-sm text-emerald-950">
          <p className="font-semibold">Import finished</p>
          <ul className="mt-2 list-inside list-disc space-y-1">
            <li>
              <span className="font-semibold">{commitResult.added}</span> new members added
            </li>
            {commitResult.skippedAlreadyMember > 0 ? (
              <li>{commitResult.skippedAlreadyMember} skipped (already a member at commit time)</li>
            ) : null}
            {commitResult.skippedNoProfile > 0 ? (
              <li>{commitResult.skippedNoProfile} skipped (no profile at commit time)</li>
            ) : null}
            {commitResult.skippedDuplicateInFile > 0 ? (
              <li>{commitResult.skippedDuplicateInFile} duplicate lines skipped during commit</li>
            ) : null}
          </ul>
          <button type="button" className="btn-secondary mt-4 px-4 py-2 text-sm font-semibold" onClick={reset}>
            Import another file
          </button>
        </div>
      ) : null}
    </div>
  );
}
