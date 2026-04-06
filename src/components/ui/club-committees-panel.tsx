"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import {
  createClubCommitteeAction,
  deleteClubCommitteeAction,
  renameClubCommitteeAction,
} from "@/app/(app)/clubs/club-committee-actions";
import type { ClubCommitteeSummary } from "@/lib/clubs/queries";

type ClubCommitteesPanelProps = {
  clubId: string;
  committees: ClubCommitteeSummary[];
  canManage: boolean;
  isArchived: boolean;
};

export function ClubCommitteesPanel({ clubId, committees, canManage, isArchived }: ClubCommitteesPanelProps) {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);

  if (!canManage && committees.length === 0) {
    return null;
  }

  return (
    <section className="card-surface border border-slate-200 p-5">
      <div className="section-card-header">
        <div>
          <p className="section-kicker">Organization</p>
          <h2 className="mt-1 text-base font-semibold tracking-tight text-slate-900">Committees</h2>
          <p className="mt-1 text-sm text-slate-600">
            Standing groups within this club. Members can belong to multiple committees.
          </p>
        </div>
      </div>

      {committees.length > 0 ? (
        <ul className="mt-4 flex flex-wrap gap-2">
          {committees.map((c) => (
            <li
              key={c.id}
              className="inline-flex items-center rounded-full border border-teal-200 bg-teal-50 px-3 py-1 text-xs font-semibold text-teal-900"
            >
              {c.name}
            </li>
          ))}
        </ul>
      ) : (
        <p className="mt-4 text-sm text-slate-500">No committees yet.</p>
      )}

      {error ? <p className="mt-3 text-xs text-red-600">{error}</p> : null}

      {canManage && !isArchived ? (
        <div className="mt-5 space-y-4 border-t border-slate-100 pt-5">
          <form
            className="flex flex-wrap items-end gap-2"
            action={async (fd) => {
              setError(null);
              const r = await createClubCommitteeAction(fd);
              if (r.ok) router.refresh();
              else setError(r.error);
            }}
          >
            <input type="hidden" name="club_id" value={clubId} />
            <label htmlFor="new-committee-name" className="sr-only">
              New committee name
            </label>
            <input
              id="new-committee-name"
              name="name"
              placeholder="New committee name"
              className="min-w-[200px] flex-1 rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-900"
              maxLength={80}
              autoComplete="off"
            />
            <button type="submit" className="btn-secondary text-sm font-semibold">
              Create committee
            </button>
          </form>

          {committees.length > 0 ? (
            <ul className="space-y-3">
              {committees.map((c) => (
                <li
                  key={c.id}
                  className="flex flex-col gap-2 rounded-xl border border-slate-100 bg-slate-50/80 p-3 sm:flex-row sm:items-end sm:justify-between"
                >
                  <form
                    className="flex min-w-0 flex-1 flex-wrap items-end gap-2"
                    action={async (fd) => {
                      setError(null);
                      const r = await renameClubCommitteeAction(fd);
                      if (r.ok) router.refresh();
                      else setError(r.error);
                    }}
                  >
                    <input type="hidden" name="club_id" value={clubId} />
                    <input type="hidden" name="committee_id" value={c.id} />
                    <label className="sr-only" htmlFor={`rename-${c.id}`}>
                      Rename {c.name}
                    </label>
                    <input
                      id={`rename-${c.id}`}
                      name="name"
                      defaultValue={c.name}
                      className="min-w-0 flex-1 rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-sm text-slate-900"
                      maxLength={80}
                    />
                    <button type="submit" className="btn-secondary text-xs">
                      Save name
                    </button>
                  </form>
                  <button
                    type="button"
                    className="shrink-0 text-xs font-semibold text-red-700 hover:underline sm:ml-2"
                    onClick={async () => {
                      if (!confirm(`Delete “${c.name}” and remove all member assignments?`)) return;
                      setError(null);
                      const fd = new FormData();
                      fd.set("club_id", clubId);
                      fd.set("committee_id", c.id);
                      const r = await deleteClubCommitteeAction(fd);
                      if (r.ok) router.refresh();
                      else setError(r.error);
                    }}
                  >
                    Delete
                  </button>
                </li>
              ))}
            </ul>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}
