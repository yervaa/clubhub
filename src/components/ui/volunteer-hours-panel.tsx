"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import {
  addVolunteerHoursEntryAction,
  deleteVolunteerHoursEntryAction,
  updateVolunteerHoursEntryAction,
} from "@/app/(app)/clubs/volunteer-hours-actions";
import { VOLUNTEER_HOURS_PARTICIPATION_NOTE } from "@/lib/clubs/member-engagement-copy";
import type { ClubMember } from "@/lib/clubs/queries";

export function volunteerHoursLocalYmd(): string {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

export function formatVolunteerHoursAmount(n: number): string {
  const r = Math.round(n * 100) / 100;
  if (Number.isInteger(r)) return String(r);
  return r.toFixed(2).replace(/\.?0+$/, "") || "0";
}

function formatVolunteerServiceDate(iso: string): string {
  try {
    return new Date(`${iso}T12:00:00`).toLocaleDateString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  } catch {
    return iso;
  }
}

type VolunteerHoursPanelProps = {
  clubId: string;
  member: ClubMember;
  canManage: boolean;
  /** `default`: section heading + intro (member profile). `embedded`: panel body only (overview rows). */
  variant?: "default" | "embedded";
};

export function VolunteerHoursPanel({ clubId, member, canManage, variant = "default" }: VolunteerHoursPanelProps) {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const entries = member.volunteerHourEntries ?? [];
  const total = member.volunteerHoursTotal ?? 0;

  const body = (
    <>
      {variant === "default" ? (
        <>
          <p className="mt-1 text-xs text-slate-500">
            Service hours for this club only — not shared across other clubs or your global profile.
          </p>
          <p className="mt-1 text-xs text-slate-500">{VOLUNTEER_HOURS_PARTICIPATION_NOTE}</p>
          <p className="mt-2 text-sm font-semibold text-slate-900">
            Total: {formatVolunteerHoursAmount(total)} h
          </p>
        </>
      ) : (
        <p className="text-sm font-semibold text-slate-900">
          Total: {formatVolunteerHoursAmount(total)} h
          {entries.length > 0 ? (
            <span className="ml-2 font-normal text-slate-500">
              · {entries.length} {entries.length === 1 ? "entry" : "entries"}
            </span>
          ) : null}
        </p>
      )}

      {entries.length > 0 ? (
        <ul className={`space-y-3 ${variant === "default" ? "mt-3 border-t border-slate-100 pt-3" : "mt-3"}`}>
          {entries.map((e) => (
            <li key={e.id} className="rounded-lg border border-slate-200 bg-slate-50/80 px-3 py-2.5 text-sm">
              {editingId === e.id ? (
                <form
                  className="space-y-2"
                  action={async (fd) => {
                    setError(null);
                    const r = await updateVolunteerHoursEntryAction(fd);
                    if (r.ok) {
                      setEditingId(null);
                      router.refresh();
                    } else setError(r.error);
                  }}
                >
                  <input type="hidden" name="club_id" value={clubId} />
                  <input type="hidden" name="entry_id" value={e.id} />
                  <div className="grid gap-2 sm:grid-cols-2">
                    <label className="block text-xs font-semibold text-slate-600">
                      Hours
                      <input
                        name="hours"
                        type="text"
                        inputMode="decimal"
                        required
                        defaultValue={formatVolunteerHoursAmount(e.hours)}
                        className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-sm"
                      />
                    </label>
                    <label className="block text-xs font-semibold text-slate-600">
                      Service date
                      <input
                        name="service_date"
                        type="date"
                        required
                        defaultValue={e.serviceDate}
                        className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-sm"
                      />
                    </label>
                  </div>
                  <label className="block text-xs font-semibold text-slate-600">
                    Note (optional)
                    <textarea
                      name="note"
                      rows={2}
                      defaultValue={e.note ?? ""}
                      className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-sm"
                    />
                  </label>
                  <div className="flex flex-wrap gap-2">
                    <button type="submit" className="btn-secondary text-xs">
                      Save
                    </button>
                    <button type="button" className="btn-secondary text-xs" onClick={() => setEditingId(null)}>
                      Cancel
                    </button>
                  </div>
                </form>
              ) : (
                <div className="flex flex-col gap-1 sm:flex-row sm:items-start sm:justify-between">
                  <div>
                    <p className="font-semibold text-slate-900">
                      {formatVolunteerHoursAmount(e.hours)} h · {formatVolunteerServiceDate(e.serviceDate)}
                    </p>
                    {e.note ? <p className="mt-1 text-xs text-slate-600">{e.note}</p> : null}
                  </div>
                  {canManage ? (
                    <div className="flex shrink-0 gap-2">
                      <button
                        type="button"
                        className="text-xs font-semibold text-indigo-600 underline-offset-2 hover:underline"
                        onClick={() => setEditingId(e.id)}
                      >
                        Edit
                      </button>
                      <form
                        action={async (fd) => {
                          setError(null);
                          const r = await deleteVolunteerHoursEntryAction(fd);
                          if (r.ok) router.refresh();
                          else setError(r.error);
                        }}
                      >
                        <input type="hidden" name="club_id" value={clubId} />
                        <input type="hidden" name="entry_id" value={e.id} />
                        <button
                          type="submit"
                          className="text-xs font-semibold text-red-600 underline-offset-2 hover:underline"
                        >
                          Remove
                        </button>
                      </form>
                    </div>
                  ) : null}
                </div>
              )}
            </li>
          ))}
        </ul>
      ) : variant === "embedded" ? (
        <p className="mt-2 text-sm text-slate-500">No entries yet for this member.</p>
      ) : (
        <p className="mt-2 text-sm text-slate-500">No entries yet.</p>
      )}

      {error ? <p className="mt-2 text-xs text-red-600">{error}</p> : null}

      {canManage ? (
        <form
          className={`space-y-3 border-t border-slate-100 pt-4 ${variant === "default" ? "mt-4" : "mt-4"}`}
          action={async (fd) => {
            setError(null);
            const r = await addVolunteerHoursEntryAction(fd);
            if (r.ok) router.refresh();
            else setError(r.error);
          }}
        >
          <input type="hidden" name="club_id" value={clubId} />
          <input type="hidden" name="user_id" value={member.userId} />
          <p className="text-xs font-semibold text-slate-600">Add entry</p>
          <div className="grid gap-2 sm:grid-cols-2">
            <label className="block text-xs font-semibold text-slate-600">
              Hours
              <input
                name="hours"
                type="text"
                inputMode="decimal"
                required
                placeholder="e.g. 2.5"
                className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-sm"
              />
            </label>
            <label className="block text-xs font-semibold text-slate-600">
              Service date
              <input
                name="service_date"
                type="date"
                required
                defaultValue={volunteerHoursLocalYmd()}
                className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-sm"
              />
            </label>
          </div>
          <label className="block text-xs font-semibold text-slate-600">
            Note (optional)
            <textarea name="note" rows={2} className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-sm" />
          </label>
          <button type="submit" className="btn-secondary text-xs">
            Log hours
          </button>
        </form>
      ) : null}
    </>
  );

  if (variant === "embedded") {
    return <div className="space-y-1">{body}</div>;
  }

  return (
    <section>
      <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Volunteer hours</h3>
      {body}
    </section>
  );
}
