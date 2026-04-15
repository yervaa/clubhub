"use client";

import { useState } from "react";
import type { ClubMember } from "@/lib/clubs/queries";
import { getMemberRosterDisplayName, getMemberRosterInitials } from "@/lib/member-display";
import { CardSection, PageEmptyState, SectionHeader } from "@/components/ui/page-patterns";
import { formatVolunteerHoursAmount, VolunteerHoursPanel } from "@/components/ui/volunteer-hours-panel";

type ClubVolunteerHoursOverviewProps = {
  clubId: string;
  members: ClubMember[];
  canManage: boolean;
};

export function ClubVolunteerHoursOverview({ clubId, members, canManage }: ClubVolunteerHoursOverviewProps) {
  const [openId, setOpenId] = useState<string | null>(null);

  const sorted = [...members].sort((a, b) =>
    getMemberRosterDisplayName(a).localeCompare(getMemberRosterDisplayName(b), undefined, {
      sensitivity: "base",
    }),
  );

  const clubTotal = members.reduce((sum, m) => sum + (m.volunteerHoursTotal ?? 0), 0);

  return (
    <div className="space-y-4 lg:space-y-5">
      <CardSection className="border border-slate-200/90">
        <SectionHeader
          kicker="Club total"
          title={`${formatVolunteerHoursAmount(clubTotal)} h`}
          description="Sum of all logged entries. Open a member to add, edit, or remove lines."
        />
      </CardSection>

      <CardSection className="overflow-hidden border border-slate-200/90 p-0">
        {sorted.length === 0 ? (
          <PageEmptyState title="No members yet" copy="Member rows will appear here when the roster has members." />
        ) : (
          <ul className="divide-y divide-slate-200">
          {sorted.map((m) => {
            const expanded = openId === m.userId;
            return (
              <li key={m.userId} className="bg-white">
                <div className="flex flex-wrap items-center gap-3 px-4 py-3 sm:px-6">
                  <div className="flex min-w-0 flex-1 items-center gap-3">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-slate-700 text-sm font-bold text-white">
                      {getMemberRosterInitials(m)}
                    </div>
                    <div className="min-w-0">
                      <p className="truncate font-semibold text-slate-900">{getMemberRosterDisplayName(m)}</p>
                      <p className="text-xs text-slate-500">
                        {m.membershipStatus === "alumni" ? "Alumni" : "Active"} ·{" "}
                        {formatVolunteerHoursAmount(m.volunteerHoursTotal ?? 0)} h
                      </p>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => setOpenId(expanded ? null : m.userId)}
                    className="btn-secondary shrink-0 px-3 py-2 text-xs font-semibold"
                    aria-expanded={expanded}
                  >
                    {expanded ? "Hide details" : canManage ? "View & edit" : "View details"}
                  </button>
                </div>
                {expanded ? (
                  <div className="border-t border-slate-100 bg-slate-50/90 px-4 py-4 sm:px-6">
                    <VolunteerHoursPanel clubId={clubId} member={m} canManage={canManage} variant="embedded" />
                  </div>
                ) : null}
              </li>
            );
          })}
          </ul>
        )}
      </CardSection>
    </div>
  );
}
