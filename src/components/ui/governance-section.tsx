"use client";

import { useState, useTransition } from "react";
import {
  addPresidentAction,
  removePresidentAction,
  transferPresidencyAction,
} from "@/app/(app)/clubs/governance-actions";
import { DisclosurePanel } from "@/components/ui/disclosure-panel";

type GovernanceMember = {
  userId: string;
  name: string | null;
  email: string | null;
};

// Mirrors AuditLogEntry from src/lib/rbac/audit.ts.
// Defined here to avoid importing from a server-only module into a client component.
type AuditLogEntry = {
  id: string;
  action: string;
  actorName: string;
  targetUserName: string | null;
  targetRoleName: string | null;
  metadata: Record<string, unknown>;
  createdAt: string;
};

type GovernanceSectionProps = {
  clubId: string;
  clubName: string;
  currentUserId: string;
  isPresident: boolean;
  presidentRoleId: string | null;
  presidents: GovernanceMember[];
  nonPresidents: GovernanceMember[];
  query: {
    success?: string;
    error?: string;
  };
  auditLogs: AuditLogEntry[];
  canViewAudit: boolean;
};

function getMemberLabel(member: GovernanceMember): string {
  if (member.name) return member.name;
  if (member.email) return member.email;
  return "Unknown member";
}

function getMemberSubtext(member: GovernanceMember): string | null {
  if (member.name && member.email) return member.email;
  return null;
}

// ─── Inline confirmation panel ────────────────────────────────────────────────

type ConfirmState =
  | { kind: "remove"; targetUserId: string; targetLabel: string }
  | { kind: "transfer"; targetUserId: string; targetLabel: string }
  | null;

// ─── Audit timeline helpers ───────────────────────────────────────────────────

const AUDIT_ACTION_ICONS: Record<string, { icon: string; color: string }> = {
  "role.created":          { icon: "plus",     color: "emerald" },
  "role.updated":          { icon: "edit",     color: "blue"    },
  "role.deleted":          { icon: "trash",    color: "red"     },
  "role.assigned":         { icon: "user-add", color: "emerald" },
  "role.removed":          { icon: "user-del", color: "amber"   },
  "president.added":       { icon: "crown",    color: "violet"  },
  "president.removed":     { icon: "crown-x",  color: "amber"   },
  "presidency.transferred":{ icon: "transfer", color: "violet"  },
};

function formatAuditAction(entry: AuditLogEntry): string {
  const role = entry.targetRoleName;
  const user = entry.targetUserName;
  switch (entry.action) {
    case "role.created":          return `Created role "${role ?? "Unknown"}"`;
    case "role.updated":          return `Updated permissions for "${role ?? "Unknown"}"`;
    case "role.deleted":          return `Deleted role "${role ?? "Unknown"}"`;
    case "role.assigned":         return `Assigned "${role ?? "Unknown"}" to ${user ?? "a member"}`;
    case "role.removed":          return `Removed "${role ?? "Unknown"}" from ${user ?? "a member"}`;
    case "president.added":       return `Added ${user ?? "a member"} as President`;
    case "president.removed":     return `Removed ${user ?? "a member"} from President`;
    case "presidency.transferred":return `Transferred Presidency to ${user ?? "a member"}`;
    default:                      return entry.action;
  }
}

function formatRelativeTime(iso: string): string {
  const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (diff < 60)           return "just now";
  if (diff < 3_600)        return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86_400)       return `${Math.floor(diff / 3_600)}h ago`;
  if (diff < 7 * 86_400)   return `${Math.floor(diff / 86_400)}d ago`;
  return new Date(iso).toLocaleDateString();
}

function AuditDot({ action }: { action: string }) {
  const meta = AUDIT_ACTION_ICONS[action];
  const color = meta?.color ?? "slate";

  const colorMap: Record<string, string> = {
    emerald: "bg-emerald-100 text-emerald-600 ring-emerald-200",
    blue:    "bg-blue-100    text-blue-600    ring-blue-200",
    red:     "bg-red-100     text-red-600     ring-red-200",
    amber:   "bg-amber-100   text-amber-600   ring-amber-200",
    violet:  "bg-violet-100  text-violet-600  ring-violet-200",
    slate:   "bg-slate-100   text-slate-500   ring-slate-200",
  };

  const isPersidency = action.startsWith("president") || action === "presidency.transferred";
  const isDelete = action === "role.deleted" || action === "president.removed";

  return (
    <span
      className={`flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full ring-2 ${colorMap[color] ?? colorMap.slate}`}
      aria-hidden
    >
      {isPersidency ? (
        <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
            d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
          />
        </svg>
      ) : isDelete ? (
        <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
            d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
          />
        </svg>
      ) : (
        <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
            d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"
          />
        </svg>
      )}
    </span>
  );
}

export function GovernanceSection({
  clubId,
  clubName,
  currentUserId,
  isPresident,
  presidentRoleId,
  presidents,
  nonPresidents,
  query,
  auditLogs,
  canViewAudit,
}: GovernanceSectionProps) {
  const [confirm, setConfirm] = useState<ConfirmState>(null);
  const [selectedAddUserId, setSelectedAddUserId] = useState<string>("");
  const [selectedTransferUserId, setSelectedTransferUserId] = useState<string>("");
  const [isPending, startTransition] = useTransition();

  const isMigrationMissing = !presidentRoleId;
  const successMessage = query.success ? decodeURIComponent(query.success.replace(/\+/g, " ")) : null;
  const errorMessage = query.error ? decodeURIComponent(query.error.replace(/\+/g, " ")) : null;

  function handleRemoveClick(member: GovernanceMember) {
    setConfirm({ kind: "remove", targetUserId: member.userId, targetLabel: getMemberLabel(member) });
  }

  function handleTransferClick() {
    if (!selectedTransferUserId) return;
    const target = nonPresidents.find((m) => m.userId === selectedTransferUserId);
    if (!target) return;
    setConfirm({ kind: "transfer", targetUserId: selectedTransferUserId, targetLabel: getMemberLabel(target) });
  }

  function handleCancel() {
    setConfirm(null);
  }

  function submitAction(action: (fd: FormData) => Promise<void>, fields: Record<string, string>) {
    startTransition(async () => {
      const fd = new FormData();
      for (const [key, value] of Object.entries(fields)) {
        fd.set(key, value);
      }
      await action(fd);
    });
  }

  return (
    <section className="space-y-4 lg:space-y-6">

      <header className="card-surface border border-slate-200/90 bg-gradient-to-br from-slate-50 to-violet-50/80 p-4 shadow-sm sm:p-6 lg:border-2 lg:p-8">
        <div className="max-w-4xl">
          <p className="section-kicker text-slate-600">Settings</p>
          <h1 className="section-title mt-1 text-xl sm:mt-2 sm:text-3xl md:text-4xl">Governance</h1>
          <p className="section-subtitle mt-2 max-w-2xl text-sm sm:mt-3 sm:text-base sm:text-lg text-slate-700">
            The President holds full authority over <strong>{clubName}</strong>. This page manages who holds that authority and how it can be transferred.
          </p>

          <div className="mt-4 flex flex-wrap items-center gap-4 sm:mt-5 sm:gap-6 lg:mt-6">
            <div>
              <p className="text-2xl font-bold text-slate-900">{presidents.length}</p>
              <p className="mt-1 text-xs font-semibold uppercase tracking-[0.1em] text-slate-500">
                {presidents.length === 1 ? "President" : "Presidents"}
              </p>
            </div>
            <div className="hidden h-8 w-px bg-slate-200 sm:block" aria-hidden />
            <div>
              <p className="text-2xl font-bold text-slate-900">{nonPresidents.length}</p>
              <p className="mt-1 text-xs font-semibold uppercase tracking-[0.1em] text-slate-500">Other Members</p>
            </div>
          </div>

          {!isPresident && (
            <div className="mt-5 flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800 sm:mt-6 sm:items-center sm:py-2.5">
              <svg className="h-4 w-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M12 3a9 9 0 100 18A9 9 0 0012 3z" />
              </svg>
              You have read-only access. Only Presidents can manage Presidency.
            </div>
          )}
        </div>
      </header>

      {/* Status banners */}
      {successMessage && (
        <div className="flex items-center gap-3 rounded-lg border border-emerald-200 bg-emerald-50 px-5 py-3.5 text-sm font-medium text-emerald-800">
          <svg className="h-5 w-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          {successMessage}
        </div>
      )}
      {errorMessage && (
        <div className="flex items-center gap-3 rounded-lg border border-red-200 bg-red-50 px-5 py-3.5 text-sm font-medium text-red-800">
          <svg className="h-5 w-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M12 3a9 9 0 100 18A9 9 0 0012 3z" />
          </svg>
          {errorMessage}
        </div>
      )}

      {/* RBAC migration warning */}
      {isMigrationMissing && (
        <div className="rounded-xl border border-orange-200 bg-orange-50 p-5">
          <div className="flex items-start gap-3">
            <svg className="mt-0.5 h-5 w-5 flex-shrink-0 text-orange-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M12 3a9 9 0 100 18A9 9 0 0012 3z" />
            </svg>
            <div>
              <p className="text-sm font-semibold text-orange-800">RBAC migrations not applied</p>
              <p className="mt-1 text-sm text-orange-700">
                The President role was not found for this club. Apply the RBAC database migrations (013–016) in the Supabase SQL Editor, then reload this page.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* ── Protection model explanation ──────────────────────────────────────── */}
      <div className="card-surface p-4 sm:p-6">
        <div className="section-card-header">
          <div>
            <p className="section-kicker">How It Works</p>
            <h2 className="mt-1 text-base font-semibold tracking-tight text-slate-900">Presidency Guardrails</h2>
          </div>
          <span className="inline-flex items-center gap-1.5 rounded-full border border-violet-200 bg-violet-50 px-3 py-1 text-xs font-semibold text-violet-700">
            <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            Protected
          </span>
        </div>
        <ul className="mt-4 space-y-3">
          {[
            { icon: "shield", text: "A club must always have at least one President. The last President cannot be removed." },
            { icon: "lock", text: "Only Presidents can grant or remove Presidency. Non-Presidents cannot escalate their own authority." },
            { icon: "alert", text: "The President system role cannot be deleted or renamed." },
            { icon: "switch", text: "Transferring Presidency adds the successor first, then removes the current President — ensuring continuity." },
          ].map(({ text }, i) => (
            <li key={i} className="flex items-start gap-3 text-sm text-slate-600">
              <span className="mt-0.5 flex h-5 w-5 flex-shrink-0 items-center justify-center rounded-full bg-violet-100">
                <svg className="h-3 w-3 text-violet-600" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                </svg>
              </span>
              {text}
            </li>
          ))}
        </ul>
      </div>

      {/* ── Current Presidents ────────────────────────────────────────────────── */}
      <div className="card-surface p-4 sm:p-6">
        <div className="section-card-header">
          <div>
            <p className="section-kicker">Authority</p>
            <h2 className="mt-1 text-base font-semibold tracking-tight text-slate-900">Current Presidents</h2>
            <p className="mt-1 text-sm text-slate-600">
              {presidents.length === 0
                ? "No Presidents assigned. Apply RBAC migrations to set this up."
                : `${presidents.length} ${presidents.length === 1 ? "person holds" : "people hold"} full club authority.`}
            </p>
          </div>
          <span className="badge-soft">{presidents.length} total</span>
        </div>

        {presidents.length === 0 ? (
          <div className="mt-4 rounded-xl border border-dashed border-slate-200 bg-slate-50/60 p-6 text-center">
            <p className="text-sm text-slate-500">No Presidents found. Run the RBAC backfill migration.</p>
          </div>
        ) : (
          <ul className="mt-4 space-y-2">
            {presidents.map((president) => {
              const isCurrentUser = president.userId === currentUserId;
              const isLastOne = presidents.length <= 1;
              const isConfirmingRemove =
                confirm?.kind === "remove" && confirm.targetUserId === president.userId;

              return (
                <li key={president.userId} className="surface-subcard p-3 sm:p-4">
                  <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center sm:justify-between">
                    {/* Identity */}
                    <div className="flex items-center gap-3">
                      <div className="flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-full bg-violet-100 text-sm font-bold text-violet-700">
                        {getMemberLabel(president).slice(0, 1).toUpperCase()}
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <p className="text-sm font-semibold text-slate-900">{getMemberLabel(president)}</p>
                          {isCurrentUser && (
                            <span className="rounded-full bg-blue-100 px-2 py-0.5 text-[11px] font-semibold text-blue-700">You</span>
                          )}
                          <span className="rounded-full border border-violet-200 bg-violet-50 px-2 py-0.5 text-[11px] font-semibold text-violet-700">
                            President
                          </span>
                          {isLastOne && (
                            <span className="rounded-full border border-amber-200 bg-amber-50 px-2 py-0.5 text-[11px] font-semibold text-amber-700">
                              Last
                            </span>
                          )}
                        </div>
                        {getMemberSubtext(president) && (
                          <p className="mt-0.5 text-xs text-slate-500">{getMemberSubtext(president)}</p>
                        )}
                      </div>
                    </div>

                    {/* Remove button — Presidents only, disabled for last */}
                    {isPresident && !isMigrationMissing && (
                      <div className="flex w-full items-stretch gap-2 sm:w-auto sm:items-center">
                        {isLastOne ? (
                          <span className="text-xs leading-snug text-slate-400 sm:py-2" title="Cannot remove the last President">
                            Protected — last President
                          </span>
                        ) : (
                          <button
                            type="button"
                            onClick={() => isConfirmingRemove ? handleCancel() : handleRemoveClick(president)}
                            className={`btn-secondary min-h-11 w-full text-xs sm:min-h-0 sm:w-auto ${isConfirmingRemove ? "ring-2 ring-red-400" : ""}`}
                          >
                            {isConfirmingRemove ? "Cancel" : "Remove"}
                          </button>
                        )}
                      </div>
                    )}
                  </div>

                  {/* Inline remove confirmation */}
                  {isConfirmingRemove && (
                    <div className="mt-4 rounded-xl border border-red-200 bg-red-50 p-4">
                      <p className="text-sm font-semibold text-red-900">
                        Remove President: {confirm.targetLabel}?
                      </p>
                      <p className="mt-1 text-sm text-red-700">
                        This will revoke all President-level authority from{" "}
                        {isCurrentUser ? "you" : confirm.targetLabel}. They will keep any other roles they hold.
                      </p>
                      <div className="mt-4 flex flex-col-reverse gap-2 sm:flex-row sm:flex-wrap sm:gap-3">
                        <button
                          type="button"
                          onClick={handleCancel}
                          className="btn-secondary min-h-11 w-full text-sm sm:min-h-0 sm:w-auto"
                        >
                          Cancel
                        </button>
                        <button
                          type="button"
                          disabled={isPending}
                          onClick={() =>
                            submitAction(removePresidentAction, {
                              club_id: clubId,
                              target_user_id: confirm.targetUserId,
                            })
                          }
                          className="btn-danger min-h-11 w-full text-sm sm:min-h-0 sm:w-auto"
                        >
                          {isPending ? "Removing…" : "Yes, remove President"}
                        </button>
                      </div>
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </div>

      {/* ── Add Co-President ─────────────────────────────────────────────────── */}
      {isPresident && !isMigrationMissing && (
        <div className="card-surface p-4 sm:p-6">
          <div className="section-card-header">
            <div>
              <p className="section-kicker">Expand Authority</p>
              <h2 className="mt-1 text-base font-semibold tracking-tight text-slate-900">Add Co-President</h2>
              <p className="mt-1 text-sm text-slate-600">
                Grant another member full President authority alongside your own. You will remain a President.
              </p>
            </div>
          </div>

          {nonPresidents.length === 0 ? (
            <div className="mt-4 rounded-xl border border-dashed border-slate-200 bg-slate-50/60 p-5 text-center">
              <p className="text-sm text-slate-500">All club members are already Presidents.</p>
            </div>
          ) : (
            <div className="mt-5 space-y-4">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
                <div className="flex-1 space-y-1.5">
                  <label htmlFor="add-president-select" className="block text-sm font-medium text-slate-700">
                    Select member
                  </label>
                  <select
                    id="add-president-select"
                    value={selectedAddUserId}
                    onChange={(e) => setSelectedAddUserId(e.target.value)}
                    className="input-control min-h-11 sm:min-h-0"
                  >
                    <option value="">— choose a member —</option>
                    {nonPresidents.map((m) => (
                      <option key={m.userId} value={m.userId}>
                        {getMemberLabel(m)}{getMemberSubtext(m) ? ` (${getMemberSubtext(m)})` : ""}
                      </option>
                    ))}
                  </select>
                </div>
                <button
                  type="button"
                  disabled={!selectedAddUserId || isPending}
                  onClick={() =>
                    submitAction(addPresidentAction, {
                      club_id: clubId,
                      target_user_id: selectedAddUserId,
                    })
                  }
                  className="btn-primary min-h-11 w-full whitespace-nowrap disabled:opacity-50 sm:min-h-0 sm:w-auto"
                >
                  {isPending ? "Adding…" : "Add as Co-President"}
                </button>
              </div>
              <div className="rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 text-xs text-slate-500">
                The selected member will immediately gain full President authority, including the ability to manage roles, transfer Presidency, and access all club settings.
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── Transfer Presidency ───────────────────────────────────────────────── */}
      {isPresident && !isMigrationMissing && (
        <div className="card-surface p-4 sm:p-6">
          <div className="section-card-header">
            <div>
              <p className="section-kicker">Step Down</p>
              <h2 className="mt-1 text-base font-semibold tracking-tight text-slate-900">Transfer Presidency</h2>
              <p className="mt-1 text-sm text-slate-600">
                Pass full authority to another member and remove yourself from the President role.
              </p>
            </div>
            <span className="inline-flex items-center gap-1 rounded-full border border-red-200 bg-red-50 px-2.5 py-1 text-xs font-semibold text-red-700">
              <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              Irreversible
            </span>
          </div>

          {nonPresidents.length === 0 ? (
            <div className="mt-4 rounded-xl border border-dashed border-slate-200 bg-slate-50/60 p-5 text-center">
              <p className="text-sm text-slate-500">
                There are no other members to transfer Presidency to. Invite members first.
              </p>
            </div>
          ) : confirm?.kind === "transfer" ? (
            /* ── Transfer confirmation panel ── */
            <div className="mt-5 rounded-xl border border-red-200 bg-red-50 p-5">
              <div className="flex items-start gap-3">
                <svg className="mt-0.5 h-5 w-5 flex-shrink-0 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
                <div>
                  <p className="text-sm font-bold text-red-900">
                    Transfer Presidency to {confirm.targetLabel}?
                  </p>
                  <p className="mt-1 text-sm text-red-700">
                    <strong>{confirm.targetLabel}</strong> will become President and you will lose all President-level authority immediately. This action cannot be undone without their cooperation.
                  </p>
                </div>
              </div>
              <div className="mt-4 flex flex-col-reverse gap-2 sm:flex-row sm:flex-wrap sm:gap-3">
                <button
                  type="button"
                  onClick={handleCancel}
                  className="btn-secondary min-h-11 w-full text-sm sm:min-h-0 sm:w-auto"
                >
                  Cancel — keep Presidency
                </button>
                <button
                  type="button"
                  disabled={isPending}
                  onClick={() =>
                    submitAction(transferPresidencyAction, {
                      club_id: clubId,
                      target_user_id: confirm.targetUserId,
                    })
                  }
                  className="btn-danger min-h-11 w-full text-sm sm:min-h-0 sm:w-auto"
                >
                  {isPending ? "Transferring…" : `Yes, transfer to ${confirm.targetLabel}`}
                </button>
              </div>
            </div>
          ) : (
            <div className="mt-5 space-y-4">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
                <div className="flex-1 space-y-1.5">
                  <label htmlFor="transfer-select" className="block text-sm font-medium text-slate-700">
                    Transfer to
                  </label>
                  <select
                    id="transfer-select"
                    value={selectedTransferUserId}
                    onChange={(e) => setSelectedTransferUserId(e.target.value)}
                    className="input-control min-h-11 sm:min-h-0"
                  >
                    <option value="">— choose your successor —</option>
                    {nonPresidents.map((m) => (
                      <option key={m.userId} value={m.userId}>
                        {getMemberLabel(m)}{getMemberSubtext(m) ? ` (${getMemberSubtext(m)})` : ""}
                      </option>
                    ))}
                  </select>
                </div>
                <button
                  type="button"
                  disabled={!selectedTransferUserId}
                  onClick={handleTransferClick}
                  className="btn-danger min-h-11 w-full whitespace-nowrap disabled:opacity-50 sm:min-h-0 sm:w-auto"
                >
                  Review Transfer…
                </button>
              </div>
              <div className="rounded-lg border border-red-100 bg-red-50/60 px-4 py-3 text-xs text-red-600">
                Transferring Presidency removes you from the President role. Make sure you have chosen the right successor — they will immediately gain full control of this club.
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── Audit Timeline ────────────────────────────────────────────────────── */}
      {canViewAudit && (
        <div className="card-surface p-4 sm:p-6">
          <div className="section-card-header">
            <div>
              <p className="section-kicker">Transparency</p>
              <h2 className="mt-1 text-base font-semibold tracking-tight text-slate-900">
                Governance &amp; role audit
              </h2>
              <p className="mt-1 text-sm text-slate-600">
                High-impact authority changes for this club. Expand the timeline when you need the full history.
              </p>
            </div>
            <span className="badge-soft">{auditLogs.length} entries</span>
          </div>

          {auditLogs.length === 0 ? (
            <div className="mt-4 rounded-xl border border-dashed border-slate-200 bg-slate-50/60 p-8 text-center">
              <div className="mx-auto mb-3 flex h-10 w-10 items-center justify-center rounded-full bg-slate-100">
                <svg className="h-5 w-5 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                    d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"
                  />
                </svg>
              </div>
              <p className="text-sm font-medium text-slate-600">No changes recorded yet</p>
              <p className="mt-1 text-xs text-slate-400">
                Role and governance changes will appear here as they happen.
              </p>
            </div>
          ) : (
            <DisclosurePanel
              className="mt-4"
              title="Full audit timeline"
              subtitle="Newest entries appear first in the list below."
              defaultOpen={auditLogs.length <= 6}
              badge={<span className="badge-soft text-[10px]">{auditLogs.length} events</span>}
            >
              <ol className="space-y-0" aria-label="Governance change history">
                {auditLogs.map((entry, idx) => {
                  const isLast = idx === auditLogs.length - 1;
                  return (
                    <li key={entry.id} className="relative flex gap-4">
                      {!isLast && (
                        <div
                          className="absolute left-4 top-8 h-full w-px -translate-x-1/2 bg-slate-200"
                          aria-hidden
                        />
                      )}

                      <div className="relative z-10 mt-1 flex-shrink-0">
                        <AuditDot action={entry.action} />
                      </div>

                      <div className={`min-w-0 flex-1 ${isLast ? "pb-0" : "pb-5"}`}>
                        <div className="flex flex-col gap-1 sm:flex-row sm:flex-wrap sm:items-baseline sm:justify-between sm:gap-x-4 sm:gap-y-0.5">
                          <p className="break-words text-sm font-medium text-slate-900">
                            {formatAuditAction(entry)}
                          </p>
                          <time
                            dateTime={entry.createdAt}
                            className="flex-shrink-0 text-xs text-slate-400"
                            title={new Date(entry.createdAt).toLocaleString()}
                          >
                            {formatRelativeTime(entry.createdAt)}
                          </time>
                        </div>
                        <p className="mt-0.5 text-xs text-slate-500">
                          by <span className="font-medium text-slate-600">{entry.actorName}</span>
                        </p>
                      </div>
                    </li>
                  );
                })}
              </ol>
            </DisclosurePanel>
          )}
        </div>
      )}

    </section>
  );
}
