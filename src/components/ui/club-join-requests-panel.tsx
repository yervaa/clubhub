"use client";

import { useActionState } from "react";
import {
  reviewJoinRequestAction,
  type JoinRequestReviewState,
} from "@/app/(app)/clubs/join-request-actions";
import type { PendingJoinRequest } from "@/lib/clubs/queries";

type ClubJoinRequestsPanelProps = {
  clubId: string;
  requests: PendingJoinRequest[];
};

function formatRequestedAt(iso: string): string {
  try {
    return new Date(iso).toLocaleString(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    });
  } catch {
    return iso;
  }
}

export function ClubJoinRequestsPanel({ clubId, requests }: ClubJoinRequestsPanelProps) {
  const [state, formAction, isPending] = useActionState<JoinRequestReviewState, FormData>(
    reviewJoinRequestAction,
    { ok: true },
  );

  if (requests.length === 0) {
    return null;
  }

  return (
    <section className="card-surface border border-amber-200/80 bg-gradient-to-br from-amber-50/50 to-white p-5 sm:p-6">
      <div className="section-card-header">
        <div>
          <p className="section-kicker text-amber-900/80">Membership</p>
          <h2 className="mt-1 text-lg font-semibold text-slate-900">Pending join requests</h2>
          <p className="mt-1 text-sm text-slate-600">
            These people submitted a join request (your club requires approval). Approve to add them as members, or deny
            if the request should not go through. They are not on the roster until you approve.
          </p>
        </div>
        <span className="feedback-pill bg-amber-100 text-amber-950">{requests.length} pending</span>
      </div>

      {!state.ok ? (
        <div className="mt-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm font-medium text-red-900">
          {state.error}
        </div>
      ) : null}

      <ul className="mt-5 divide-y divide-slate-200/90 rounded-xl border border-slate-200 bg-white">
        {requests.map((req) => (
          <li key={req.id} className="flex flex-col gap-3 p-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="font-semibold text-slate-900">{req.fullName ?? "Member"}</p>
              <p className="mt-0.5 text-xs text-slate-500">Requested {formatRequestedAt(req.requestedAt)}</p>
            </div>
            <form action={formAction} className="flex flex-wrap gap-2">
              <input type="hidden" name="club_id" value={clubId} />
              <input type="hidden" name="request_id" value={req.id} />
              <button
                type="submit"
                name="intent"
                value="approve"
                disabled={isPending}
                className="inline-flex items-center justify-center rounded-lg bg-emerald-700 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-emerald-800 disabled:cursor-not-allowed disabled:opacity-60"
              >
                Approve
              </button>
              <button
                type="submit"
                name="intent"
                value="deny"
                disabled={isPending}
                className="inline-flex items-center justify-center rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-semibold text-slate-800 shadow-sm hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
              >
                Deny
              </button>
            </form>
          </li>
        ))}
      </ul>
    </section>
  );
}
