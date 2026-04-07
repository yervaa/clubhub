"use client";

import { useRouter } from "next/navigation";
import { useCallback, useState, useTransition } from "react";
import {
  bulkAssignCommitteeMembersAction,
  bulkAssignMemberTagAction,
  bulkAssignTeamMembersAction,
  bulkMarkMembersAlumniAction,
  bulkRemoveCommitteeMembersAction,
  bulkRemoveMemberTagAction,
  bulkRemoveMembersAction,
  bulkRemoveTeamMembersAction,
  type BulkMutationResult,
} from "@/app/(app)/clubs/bulk-member-actions";

type IdName = { id: string; name: string };

type MemberBulkActionsToolbarProps = {
  clubId: string;
  clubName: string;
  currentUserId: string;
  selectedUserIds: string[];
  onClearSelection: () => void;
  canManageMemberTags: boolean;
  canManageCommittees: boolean;
  canManageTeams: boolean;
  canRemoveMembers: boolean;
  memberTagDefinitions: IdName[];
  clubCommittees: IdName[];
  clubTeams: IdName[];
};

function summarizeResult(r: Extract<BulkMutationResult, { ok: true }>): string {
  const parts = [`${r.applied} updated`];
  if (r.skipped > 0) parts.push(`${r.skipped} skipped`);
  return parts.join(" · ");
}

export function MemberBulkActionsToolbar({
  clubId,
  clubName,
  currentUserId,
  selectedUserIds,
  onClearSelection,
  canManageMemberTags,
  canManageCommittees,
  canManageTeams,
  canRemoveMembers,
  memberTagDefinitions,
  clubCommittees,
  clubTeams,
}: MemberBulkActionsToolbarProps) {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();
  const [message, setMessage] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [destructiveModalError, setDestructiveModalError] = useState<string | null>(null);

  const [tagAddId, setTagAddId] = useState("");
  const [tagRemoveId, setTagRemoveId] = useState("");
  const [committeeAddId, setCommitteeAddId] = useState("");
  const [committeeRemoveId, setCommitteeRemoveId] = useState("");
  const [teamAddId, setTeamAddId] = useState("");
  const [teamRemoveId, setTeamRemoveId] = useState("");

  const [alumniOpen, setAlumniOpen] = useState(false);
  const [alumniConfirm, setAlumniConfirm] = useState("");

  const [removeOpen, setRemoveOpen] = useState(false);
  const [removeConfirmName, setRemoveConfirmName] = useState("");

  const n = selectedUserIds.length;
  const effectiveIds = selectedUserIds.filter((id) => id !== currentUserId);

  const run = useCallback(
    (label: string, fn: () => Promise<BulkMutationResult>) => {
      setMessage(null);
      startTransition(async () => {
        const result = await fn();
        if (!result.ok) {
          setMessage({ kind: "err", text: result.error });
          return;
        }
        const base = summarizeResult(result);
        const extra = result.notes.length > 0 ? ` ${result.notes.join(" ")}` : "";
        setMessage({ kind: "ok", text: `${label}: ${base}.${extra}`.trim() });
        onClearSelection();
        router.refresh();
      });
    },
    [onClearSelection, router],
  );

  const runDestructive = useCallback(
    (label: string, fn: () => Promise<BulkMutationResult>, onSuccessClose: () => void) => {
      setDestructiveModalError(null);
      setMessage(null);
      startTransition(async () => {
        const result = await fn();
        if (!result.ok) {
          setDestructiveModalError(result.error);
          return;
        }
        onSuccessClose();
        const base = summarizeResult(result);
        const extra = result.notes.length > 0 ? ` ${result.notes.join(" ")}` : "";
        setMessage({ kind: "ok", text: `${label}: ${base}.${extra}`.trim() });
        onClearSelection();
        router.refresh();
      });
    },
    [onClearSelection, router],
  );

  if (n === 0) return null;

  return (
    <div className="mt-5 space-y-3 rounded-xl border border-indigo-200/70 bg-indigo-50/40 px-4 py-3.5 shadow-sm sm:px-5 sm:py-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <p className="text-sm font-semibold text-slate-900">
            {n} member{n === 1 ? "" : "s"} selected
            {effectiveIds.length < n ? (
              <span className="ml-2 font-normal text-slate-600">(your account cannot be bulk-changed)</span>
            ) : null}
          </p>
          <p className="mt-0.5 text-xs text-slate-600">
            Bulk actions run on the server. Ineligible rows are skipped; results may be partial.
          </p>
        </div>
        <button
          type="button"
          className="btn-secondary shrink-0 px-4 py-2 text-sm font-semibold"
          disabled={isPending}
          onClick={onClearSelection}
        >
          Clear selection
        </button>
      </div>

      {message ? (
        <p
          className={
            message.kind === "ok"
              ? "rounded-lg border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-950"
              : "rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-900"
          }
          role="status"
        >
          {message.text}
        </p>
      ) : null}

      <div className="flex flex-col gap-3 border-t border-indigo-100/80 pt-3">
        {canManageMemberTags && memberTagDefinitions.length > 0 ? (
          <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap sm:items-end sm:gap-3">
            <div className="min-w-0 flex-1 sm:max-w-xs">
              <label className="mb-1 block text-xs font-semibold text-slate-700">Add tag</label>
              <select
                className="input-control w-full text-sm"
                value={tagAddId}
                onChange={(e) => setTagAddId(e.target.value)}
                disabled={isPending}
              >
                <option value="">Choose tag…</option>
                {memberTagDefinitions.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name}
                  </option>
                ))}
              </select>
            </div>
            <button
              type="button"
              className="btn-primary px-4 py-2 text-sm font-semibold"
              disabled={isPending || !tagAddId || effectiveIds.length === 0}
              onClick={() =>
                run("Tag added", () =>
                  bulkAssignMemberTagAction({ clubId, tagId: tagAddId, userIds: selectedUserIds }),
                )
              }
            >
              Apply
            </button>
            <div className="min-w-0 flex-1 sm:max-w-xs">
              <label className="mb-1 block text-xs font-semibold text-slate-700">Remove tag</label>
              <select
                className="input-control w-full text-sm"
                value={tagRemoveId}
                onChange={(e) => setTagRemoveId(e.target.value)}
                disabled={isPending}
              >
                <option value="">Choose tag…</option>
                {memberTagDefinitions.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name}
                  </option>
                ))}
              </select>
            </div>
            <button
              type="button"
              className="btn-secondary px-4 py-2 text-sm font-semibold"
              disabled={isPending || !tagRemoveId || effectiveIds.length === 0}
              onClick={() =>
                run("Tag removed", () =>
                  bulkRemoveMemberTagAction({ clubId, tagId: tagRemoveId, userIds: selectedUserIds }),
                )
              }
            >
              Apply
            </button>
          </div>
        ) : null}

        {canManageCommittees && clubCommittees.length > 0 ? (
          <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap sm:items-end sm:gap-3">
            <div className="min-w-0 flex-1 sm:max-w-xs">
              <label className="mb-1 block text-xs font-semibold text-slate-700">Add to committee</label>
              <select
                className="input-control w-full text-sm"
                value={committeeAddId}
                onChange={(e) => setCommitteeAddId(e.target.value)}
                disabled={isPending}
              >
                <option value="">Choose committee…</option>
                {clubCommittees.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name}
                  </option>
                ))}
              </select>
            </div>
            <button
              type="button"
              className="btn-primary px-4 py-2 text-sm font-semibold"
              disabled={isPending || !committeeAddId || effectiveIds.length === 0}
              onClick={() =>
                run("Committee assigned", () =>
                  bulkAssignCommitteeMembersAction({
                    clubId,
                    committeeId: committeeAddId,
                    userIds: selectedUserIds,
                  }),
                )
              }
            >
              Apply
            </button>
            <div className="min-w-0 flex-1 sm:max-w-xs">
              <label className="mb-1 block text-xs font-semibold text-slate-700">Remove from committee</label>
              <select
                className="input-control w-full text-sm"
                value={committeeRemoveId}
                onChange={(e) => setCommitteeRemoveId(e.target.value)}
                disabled={isPending}
              >
                <option value="">Choose committee…</option>
                {clubCommittees.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name}
                  </option>
                ))}
              </select>
            </div>
            <button
              type="button"
              className="btn-secondary px-4 py-2 text-sm font-semibold"
              disabled={isPending || !committeeRemoveId || effectiveIds.length === 0}
              onClick={() =>
                run("Committee removed", () =>
                  bulkRemoveCommitteeMembersAction({
                    clubId,
                    committeeId: committeeRemoveId,
                    userIds: selectedUserIds,
                  }),
                )
              }
            >
              Apply
            </button>
          </div>
        ) : null}

        {canManageTeams && clubTeams.length > 0 ? (
          <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap sm:items-end sm:gap-3">
            <div className="min-w-0 flex-1 sm:max-w-xs">
              <label className="mb-1 block text-xs font-semibold text-slate-700">Add to team</label>
              <select
                className="input-control w-full text-sm"
                value={teamAddId}
                onChange={(e) => setTeamAddId(e.target.value)}
                disabled={isPending}
              >
                <option value="">Choose team…</option>
                {clubTeams.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name}
                  </option>
                ))}
              </select>
            </div>
            <button
              type="button"
              className="btn-primary px-4 py-2 text-sm font-semibold"
              disabled={isPending || !teamAddId || effectiveIds.length === 0}
              onClick={() =>
                run("Team assigned", () =>
                  bulkAssignTeamMembersAction({ clubId, teamId: teamAddId, userIds: selectedUserIds }),
                )
              }
            >
              Apply
            </button>
            <div className="min-w-0 flex-1 sm:max-w-xs">
              <label className="mb-1 block text-xs font-semibold text-slate-700">Remove from team</label>
              <select
                className="input-control w-full text-sm"
                value={teamRemoveId}
                onChange={(e) => setTeamRemoveId(e.target.value)}
                disabled={isPending}
              >
                <option value="">Choose team…</option>
                {clubTeams.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name}
                  </option>
                ))}
              </select>
            </div>
            <button
              type="button"
              className="btn-secondary px-4 py-2 text-sm font-semibold"
              disabled={isPending || !teamRemoveId || effectiveIds.length === 0}
              onClick={() =>
                run("Team removed", () =>
                  bulkRemoveTeamMembersAction({ clubId, teamId: teamRemoveId, userIds: selectedUserIds }),
                )
              }
            >
              Apply
            </button>
          </div>
        ) : null}

        {canRemoveMembers && effectiveIds.length > 0 ? (
          <div className="flex flex-wrap gap-2 border-t border-amber-200/60 pt-3">
            <button
              type="button"
              className="btn-secondary border-amber-300 bg-amber-50 px-4 py-2 text-sm font-semibold text-amber-950 hover:bg-amber-100"
              disabled={isPending}
              onClick={() => {
                setAlumniConfirm("");
                setDestructiveModalError(null);
                setAlumniOpen(true);
              }}
            >
              Mark as alumni…
            </button>
            <button
              type="button"
              className="btn-danger px-4 py-2 text-sm font-semibold"
              disabled={isPending}
              onClick={() => {
                setRemoveConfirmName("");
                setDestructiveModalError(null);
                setRemoveOpen(true);
              }}
            >
              Remove from club…
            </button>
          </div>
        ) : null}
      </div>

      {alumniOpen ? (
        <div
          className="fixed inset-0 z-50 flex items-end justify-center bg-black/40 p-4 sm:items-center"
          role="dialog"
          aria-modal="true"
          aria-labelledby="bulk-alumni-title"
        >
          <div className="max-h-[90vh] w-full max-w-md overflow-auto rounded-2xl border border-slate-200 bg-white p-5 shadow-xl">
            <h3 id="bulk-alumni-title" className="text-lg font-semibold text-slate-900">
              Mark {effectiveIds.length} as alumni?
            </h3>
            <p className="mt-2 text-sm text-slate-600">
              Active members only are updated. Presidents cannot be marked alumni if they are the only President.
              Type <span className="font-mono font-semibold">MARK ALUMNI</span> to confirm.
            </p>
            {destructiveModalError && alumniOpen ? (
              <p className="mt-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-900" role="alert">
                {destructiveModalError}
              </p>
            ) : null}
            <input
              className="input-control mt-4 w-full text-sm"
              value={alumniConfirm}
              onChange={(e) => setAlumniConfirm(e.target.value)}
              placeholder="MARK ALUMNI"
              autoComplete="off"
            />
            <div className="mt-4 flex flex-wrap justify-end gap-2">
              <button
                type="button"
                className="btn-secondary px-4 py-2 text-sm font-semibold"
                onClick={() => {
                  setAlumniOpen(false);
                  setDestructiveModalError(null);
                }}
              >
                Cancel
              </button>
              <button
                type="button"
                className="btn-primary px-4 py-2 text-sm font-semibold"
                disabled={isPending}
                onClick={() =>
                  runDestructive(
                    "Alumni status",
                    () =>
                      bulkMarkMembersAlumniAction({
                        clubId,
                        userIds: selectedUserIds,
                        confirmation: alumniConfirm,
                      }),
                    () => setAlumniOpen(false),
                  )
                }
              >
                Confirm
              </button>
            </div>
          </div>
        </div>
      ) : null}

      {removeOpen ? (
        <div
          className="fixed inset-0 z-50 flex items-end justify-center bg-black/40 p-4 sm:items-center"
          role="dialog"
          aria-modal="true"
          aria-labelledby="bulk-remove-title"
        >
          <div className="max-h-[90vh] w-full max-w-md overflow-auto rounded-2xl border border-red-200 bg-white p-5 shadow-xl">
            <h3 id="bulk-remove-title" className="text-lg font-semibold text-red-950">
              Remove {effectiveIds.length} from the club?
            </h3>
            <p className="mt-2 text-sm text-slate-700">
              This cannot be undone from this screen. Officers cannot be removed if they are the last officer. To confirm,
              type the club name exactly: <span className="font-semibold text-slate-900">{clubName}</span>
            </p>
            {destructiveModalError && removeOpen ? (
              <p className="mt-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-900" role="alert">
                {destructiveModalError}
              </p>
            ) : null}
            <input
              className="input-control mt-4 w-full text-sm"
              value={removeConfirmName}
              onChange={(e) => setRemoveConfirmName(e.target.value)}
              placeholder="Club name"
              autoComplete="off"
            />
            <div className="mt-4 flex flex-wrap justify-end gap-2">
              <button
                type="button"
                className="btn-secondary px-4 py-2 text-sm font-semibold"
                onClick={() => {
                  setRemoveOpen(false);
                  setDestructiveModalError(null);
                }}
              >
                Cancel
              </button>
              <button
                type="button"
                className="btn-danger px-4 py-2 text-sm font-semibold"
                disabled={isPending}
                onClick={() =>
                  runDestructive(
                    "Members removed",
                    () =>
                      bulkRemoveMembersAction({
                        clubId,
                        userIds: selectedUserIds,
                        confirmationClubName: removeConfirmName,
                      }),
                    () => setRemoveOpen(false),
                  )
                }
              >
                Remove members
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
