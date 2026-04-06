"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import {
  createClubTeamAction,
  deleteClubTeamAction,
  renameClubTeamAction,
} from "@/app/(app)/clubs/club-team-actions";
import type { ClubTeamSummary } from "@/lib/clubs/queries";

type ClubTeamsPanelProps = {
  clubId: string;
  teams: ClubTeamSummary[];
  canManage: boolean;
  isArchived: boolean;
};

export function ClubTeamsPanel({ clubId, teams, canManage, isArchived }: ClubTeamsPanelProps) {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);

  if (!canManage && teams.length === 0) {
    return null;
  }

  return (
    <section className="card-surface border border-slate-200 p-5">
      <div className="section-card-header">
        <div>
          <p className="section-kicker">Organization</p>
          <h2 className="mt-1 text-base font-semibold tracking-tight text-slate-900">Teams</h2>
          <p className="mt-1 text-sm text-slate-600">
            Working groups or squads. Separate from committees and informal tags. Members can be on multiple teams.
          </p>
        </div>
      </div>

      {teams.length > 0 ? (
        <ul className="mt-4 flex flex-wrap gap-2">
          {teams.map((t) => (
            <li
              key={t.id}
              className="inline-flex items-center rounded-full border border-rose-200 bg-rose-50 px-3 py-1 text-xs font-semibold text-rose-900"
            >
              {t.name}
            </li>
          ))}
        </ul>
      ) : (
        <p className="mt-4 text-sm text-slate-500">No teams yet.</p>
      )}

      {error ? <p className="mt-3 text-xs text-red-600">{error}</p> : null}

      {canManage && !isArchived ? (
        <div className="mt-5 space-y-4 border-t border-slate-100 pt-5">
          <form
            className="flex flex-wrap items-end gap-2"
            action={async (fd) => {
              setError(null);
              const r = await createClubTeamAction(fd);
              if (r.ok) router.refresh();
              else setError(r.error);
            }}
          >
            <input type="hidden" name="club_id" value={clubId} />
            <label htmlFor="new-team-name" className="sr-only">
              New team name
            </label>
            <input
              id="new-team-name"
              name="name"
              placeholder="New team name"
              className="min-w-[200px] flex-1 rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-900"
              maxLength={80}
              autoComplete="off"
            />
            <button type="submit" className="btn-secondary text-sm font-semibold">
              Create team
            </button>
          </form>

          {teams.length > 0 ? (
            <ul className="space-y-3">
              {teams.map((t) => (
                <li
                  key={t.id}
                  className="flex flex-col gap-2 rounded-xl border border-slate-100 bg-slate-50/80 p-3 sm:flex-row sm:items-end sm:justify-between"
                >
                  <form
                    className="flex min-w-0 flex-1 flex-wrap items-end gap-2"
                    action={async (fd) => {
                      setError(null);
                      const r = await renameClubTeamAction(fd);
                      if (r.ok) router.refresh();
                      else setError(r.error);
                    }}
                  >
                    <input type="hidden" name="club_id" value={clubId} />
                    <input type="hidden" name="team_id" value={t.id} />
                    <label className="sr-only" htmlFor={`rename-team-${t.id}`}>
                      Rename {t.name}
                    </label>
                    <input
                      id={`rename-team-${t.id}`}
                      name="name"
                      defaultValue={t.name}
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
                      if (!confirm(`Delete “${t.name}” and remove all member assignments?`)) return;
                      setError(null);
                      const fd = new FormData();
                      fd.set("club_id", clubId);
                      fd.set("team_id", t.id);
                      const r = await deleteClubTeamAction(fd);
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
